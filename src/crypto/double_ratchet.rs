use crate::crypto::{KeyPair, PublicKey};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::{Aead, NewAead, Payload};
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;
use rand::Rng;
use ring::hmac;
use hex;

#[derive(Error, Debug)]
pub enum RatchetError {
    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),
    
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    
    #[error("Key exchange failed: {0}")]
    KeyExchangeFailed(String),
    
    #[error("Invalid state: {0}")]
    InvalidState(String),
}

/// 密钥导出函数KDF
fn kdf(input: &[u8], salt: &[u8], info: &[u8], output_len: usize) -> Result<Vec<u8>, RatchetError> {
    // 使用HKDF
    let prk = hmac::Key::new(hmac::HMAC_SHA256, salt);
    let mut ctx = hmac::Context::with_key(&prk);
    ctx.update(input);
    let prk = ctx.sign();
    
    let mut output = Vec::with_capacity(output_len);
    let mut t = Vec::new();
    let mut counter = 1u8;
    
    while output.len() < output_len {
        let mut ctx = hmac::Context::with_key(&hmac::Key::new(hmac::HMAC_SHA256, prk.as_ref()));
        ctx.update(&t);
        ctx.update(info);
        ctx.update(&[counter]);
        t = ctx.sign().as_ref().to_vec();
        
        output.extend_from_slice(&t);
        counter += 1;
    }
    
    output.truncate(output_len);
    Ok(output)
}

/// 双棘轮状态
#[derive(Clone, Serialize, Deserialize)]
pub struct DoubleRatchet {
    /// 根密钥
    root_key: Vec<u8>,
    
    /// 发送链密钥
    send_chain_key: Vec<u8>,
    
    /// 接收链密钥
    recv_chain_key: Vec<u8>,
    
    /// 下一个发送消息密钥的索引
    send_message_key_counter: u32,
    
    /// 接收消息密钥的最大索引
    recv_message_key_counter: u32,
    
    /// DHe自己的密钥对
    #[serde(skip)]
    dh_key_pair: Option<KeyPair>,
    
    /// DHr对方的公钥
    dh_remote_key: Option<PublicKey>,
    
    /// 跳过的消息密钥
    skipped_message_keys: Vec<(u32, Vec<u8>)>,
}

impl fmt::Debug for DoubleRatchet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DoubleRatchet")
            .field("send_message_key_counter", &self.send_message_key_counter)
            .field("recv_message_key_counter", &self.recv_message_key_counter)
            .field("skipped_message_keys.len", &self.skipped_message_keys.len())
            .field("has_dh_key_pair", &self.dh_key_pair.is_some())
            .field("has_dh_remote_key", &self.dh_remote_key.is_some())
            .finish()
    }
}

impl DoubleRatchet {
    /// 创建新的双棘轮，初始化发送方 (Alice)
    pub fn new_initiator(
        shared_secret: &[u8],
        remote_public_key: &PublicKey,
    ) -> Result<Self, RatchetError> {
        // 生成DH密钥对
        let dh_key_pair = KeyPair::generate()
            .map_err(|e| RatchetError::KeyExchangeFailed(e.to_string()))?;
        

        
        // 直接使用共享秘密派生发送链密钥
        // 注意：使用相同的密钥导出参数
        // Alice的发送链密钥 = Bob的接收链密钥
        let send_chain_key = kdf(
            shared_secret,
            b"AliceSendChainKey",  // 固定的salt
            b"DoubleRatchet",     // 固定的info
            32,
        )?;
        

        
        // 初始化双棘轮结构
        Ok(Self {
            dh_key_pair: Some(dh_key_pair),
            dh_remote_key: Some(remote_public_key.clone()),
            root_key: shared_secret.to_vec(),  // 使用共享秘密作为根密钥
            send_chain_key,
            recv_chain_key: Vec::new(), // 接收链密钥需要等待对方发送第一条消息
            send_message_key_counter: 0,
            recv_message_key_counter: 0,
            skipped_message_keys: Vec::new(),
        })
    }
    
    /// 创建新的双棘轮，初始化接收方
    pub fn new_responder(
        shared_secret: &[u8],
        dh_key_pair: KeyPair,
    ) -> Result<Self, RatchetError> {

        
        // 直接从共享秘密派生接收链密钥
        // 注意：使用相同的密钥导出参数
        // 与Alice的发送链密钥对应
        let recv_chain_key = kdf(
            shared_secret,
            b"AliceSendChainKey",  // 与Alice发送一致的salt
            b"DoubleRatchet",     // 固定的info
            32,
        )?;
        

        
        // 初始化双棘轮结构
        Ok(Self {
            dh_key_pair: Some(dh_key_pair),
            dh_remote_key: None, // 等待收到第一条消息后设置
            root_key: shared_secret.to_vec(), // 初始化为共享秘密
            send_chain_key: Vec::new(), // 等待发送第一条消息时再生成
            recv_chain_key,
            send_message_key_counter: 0,
            recv_message_key_counter: 0,
            skipped_message_keys: Vec::new(),
        })
    }
    
    /// 执行DH棘轮步进 - 导出新的根密钥和链密钥
    fn dh_ratchet(&mut self) -> Result<(), RatchetError> {
        // 确保有必要的密钥
        let dh_pair = self.dh_key_pair.as_ref()
            .ok_or_else(|| RatchetError::InvalidState("Missing DH key pair".to_string()))?;
        
        let remote_key = self.dh_remote_key.as_ref()
            .ok_or_else(|| RatchetError::InvalidState("Missing remote public key".to_string()))?;
        
        // 计算DH共享秘密
        // 注意：在真实实现中，这需要使用X25519密钥协商
        // 这里简化为将公钥组合并哈希
        let mut dh_output = Vec::new();
        dh_output.extend_from_slice(&dh_pair.public.to_bytes().unwrap());
        dh_output.extend_from_slice(&remote_key.to_bytes().unwrap());
        
        let mut hasher = ring::digest::Context::new(&ring::digest::SHA256);
        hasher.update(&dh_output);
        let dh_output = hasher.finish();
        
        // KDF链式导出新的根密钥和链密钥
        let derived = kdf(
            &self.root_key,                // 使用当前根密钥
            dh_output.as_ref(),           // 添加DH输出
            b"DoubleRatchetInit",         // 输入信息 - 与初始化中使用的相同
            64,                           // 输出64字节：32字节根密钥 + 32字节链密钥
        )?;
        
        // 更新密钥
        self.root_key = derived[0..32].to_vec();          // 新的根密钥
        self.send_chain_key = derived[32..64].to_vec();   // 新的链密钥
        
        // 重置发送消息计数器
        self.send_message_key_counter = 0;
        
        Ok(())
    }
    
    /// 接收方处理新的DH棘轮 - 执行棘轮状态切换
    fn dh_ratchet_response(&mut self, remote_public_key: &PublicKey) -> Result<(), RatchetError> {

        
        // 1. 保存跳过的消息密钥（确保不会丢失旧消息）
        self.save_skipped_message_keys()?;
        
        // 2. 更新远程公钥
        self.dh_remote_key = Some(remote_public_key.clone());
        
        // 始终确保接收链密钥已初始化
        if self.recv_chain_key.is_empty() {
            // 使用固定方法生成接收链密钥
            // 与Alice的发送链密钥对应
            let recv_chain_key = kdf(
                &self.root_key,
                b"AliceSendChainKey",  // 与Alice发送一致的salt
                b"DoubleRatchet",     // 固定的info
                32,
            )?;
            
            self.recv_chain_key = recv_chain_key;
            self.recv_message_key_counter = 0;
            

        }
        
        // 检查发送链密钥是否初始化
        if self.send_chain_key.is_empty() {

            
            // 生成发送链密钥 - 使用固定方式
            // Bob的发送链密钥 = Alice的接收链密钥
            let send_chain_key = kdf(
                &self.root_key,
                b"BobSendChainKey",  // 固定的salt
                b"DoubleRatchet",     // 固定的info
                32,
            )?;
            
            // 更新发送链密钥
            self.send_chain_key = send_chain_key;
            self.send_message_key_counter = 0;
            

        } else {
            // 有新的远程公钥，更新接收链密钥
            let recv_chain_key = kdf(
                &self.root_key,
                b"NewRecvChainKey",  // 固定的salt
                b"DoubleRatchet",     // 固定的info
                32,
            )?;
            
            // 更新接收链密钥
            self.recv_chain_key = recv_chain_key;
            self.recv_message_key_counter = 0;  // 重置接收消息计数器
            

        }
        
        Ok(())
    }
    
    /// 保存跳过的消息密钥
    fn save_skipped_message_keys(&mut self) -> Result<(), RatchetError> {
        // 创建接收链的消息密钥，直到最新的接收计数器
        if self.recv_chain_key.is_empty() {
            return Ok(()); // 接收链为空，无需保存
        }
        
        let mut chain_key = self.recv_chain_key.clone();
        let max_skipped = 30; // 限制最多保存30个跳过的密钥
        
        // 为每个潜在的跳过消息索引保存密钥
        for i in self.recv_message_key_counter..(self.recv_message_key_counter + max_skipped) {
            // 导出消息密钥和链密钥
            let (message_key, next_chain_key) = self.chain_key_step(&chain_key)?;
            
            // 保存该消息密钥
            self.skipped_message_keys.push((i, message_key));
            
            // 更新链密钥
            chain_key = next_chain_key;
        }
        
        Ok(())
    }
    
    /// 链密钥步进，返回当前链密钥的消息密钥和下一个链密钥
    fn chain_key_step(&self, chain_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), RatchetError> {

        
        // 创建消息密钥 - 确保算法严格按照Signal协议规范
        let mut hmac_ctx = hmac::Context::with_key(&hmac::Key::new(hmac::HMAC_SHA256, chain_key));
        hmac_ctx.update(&[0x01]); // 标准Signal协议的消息密钥常量
        let message_key = hmac_ctx.sign();
        
        // 创建链密钥
        let mut hmac_ctx = hmac::Context::with_key(&hmac::Key::new(hmac::HMAC_SHA256, chain_key));
        hmac_ctx.update(&[0x02]); // 标准Signal协议的链密钥常量
        let next_chain_key = hmac_ctx.sign();
        

        
        // 返回32字节的密钥
        Ok((message_key.as_ref().to_vec(), next_chain_key.as_ref().to_vec()))
    }
    
    /// 发送链步进
    fn send_chain_step(&mut self) -> Result<Vec<u8>, RatchetError> {
        if self.send_chain_key.is_empty() {
            return Err(RatchetError::InvalidState("Send chain key not initialized".to_string()));
        }
        
        // 导出消息密钥和下一个链密钥
        let (message_key, next_chain_key) = self.chain_key_step(&self.send_chain_key)?;
        
        // 更新链密钥
        self.send_chain_key = next_chain_key;
        
        // 增加消息计数器
        self.send_message_key_counter += 1;
        
        Ok(message_key)
    }
    
    /// 接收链步进
    fn recv_chain_step(&mut self) -> Result<Vec<u8>, RatchetError> {
        if self.recv_chain_key.is_empty() {
            return Err(RatchetError::InvalidState("Receive chain key not initialized".to_string()));
        }
        
        // 导出消息密钥和下一个链密钥
        let (message_key, next_chain_key) = self.chain_key_step(&self.recv_chain_key)?;
        
        // 更新链密钥
        self.recv_chain_key = next_chain_key;
        
        // 增加消息计数器
        self.recv_message_key_counter += 1;
        
        Ok(message_key)
    }
    
    /// 尝试获取跳过的消息密钥
    fn try_skipped_message_keys(&mut self, counter: u32) -> Option<Vec<u8>> {
        let pos = self.skipped_message_keys.iter().position(|(c, _)| *c == counter);
        
        if let Some(index) = pos {
            let (_, key) = self.skipped_message_keys.remove(index);
            Some(key)
        } else {
            None
        }
    }
    
    /// 清理旧的跳过消息密钥
    fn clean_old_skipped_message_keys(&mut self, max_age: usize) {
        // 限制跳过消息密钥的数量
        if self.skipped_message_keys.len() > max_age {
            self.skipped_message_keys.drain(0..(self.skipped_message_keys.len() - max_age));
        }
    }
    
    /// 加密消息
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<(Vec<u8>, PublicKey, u32), RatchetError> {
        // 获取当前DH密钥对的公钥
        let dh_public = self.dh_key_pair.as_ref()
            .ok_or_else(|| RatchetError::InvalidState("Missing DH key pair".to_string()))?
            .public.clone();
        
        // 检查发送链是否初始化
        if self.send_chain_key.is_empty() {
            return Err(RatchetError::InvalidState("Send chain key not initialized".to_string()));
        }
        
        // 发送链步进，获取消息密钥

        let (message_key, next_chain_key) = self.chain_key_step(&self.send_chain_key)?;

        
        // 更新链密钥
        self.send_chain_key = next_chain_key;

        
        // 增加消息计数器
        self.send_message_key_counter += 1;
        
        // 当前消息计数器
        let counter = self.send_message_key_counter - 1;
        
        // 生成确定的IV，使用计数器作为前4个字节
        let mut iv = [0u8; 12];
        let counter_bytes = counter.to_le_bytes();
        iv[0..4].copy_from_slice(&counter_bytes);

        
        // 使用ChaCha20-Poly1305加密
        let key = Key::from_slice(&message_key);
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = Nonce::from_slice(&iv);
        
        // 关联数据 - 使用小端序以确保跨平台一致性
        let associated_data = counter.to_le_bytes();

        
        // 创建Payload类型的有效负载
        let payload = Payload {
            msg: plaintext,
            aad: &associated_data,  // 使用计数器作为关联数据
        };

        
        // 加密消息，使用关联数据
        let ciphertext = cipher.encrypt(nonce, payload)
            .map_err(|e| {

                RatchetError::EncryptionFailed(e.to_string())
            })?;

        
        // 组合IV和密文
        let mut result = Vec::with_capacity(iv.len() + ciphertext.len());
        result.extend_from_slice(&iv);
        result.extend_from_slice(&ciphertext);
        
        Ok((result, dh_public, self.send_message_key_counter - 1))
    }
    
    /// 解密消息
    pub fn decrypt(
        &mut self,
        ciphertext: &[u8],
        remote_public_key: &PublicKey,
        counter: u32,
    ) -> Result<Vec<u8>, RatchetError> {
        // 检查是否需要执行DH棘轮 - 远程公钥是否发生变化
        let dh_changed = match &self.dh_remote_key {
            Some(key) => {
                // 安全处理可能出现的错误情况
                let key_bytes = key.to_bytes().unwrap_or_default();
                let remote_bytes = remote_public_key.to_bytes().unwrap_or_default();
                key_bytes != remote_bytes
            },
            None => true,
        };
        
        if dh_changed {
            // 执行DH棘轮 - 这个方法会更新接收链
            self.dh_ratchet_response(remote_public_key)?;
        }
        
        // 如果接收链未初始化，使用固定方式初始化
        if self.recv_chain_key.is_empty() {

            // 使用与发送者对称的方式生成接收链密钥
            // 重要：这里使用的salt必须与Bob发送时使用的一致
            let recv_chain_key = kdf(
                &self.root_key,
                b"BobSendChainKey",  // 与Bob发送一致的salt
                b"DoubleRatchet",    // 固定的info
                32,
            )?;
            self.recv_chain_key = recv_chain_key;

        }
        
        // 获取消息密钥 - 基于计数器处理消息顺序
        let message_key = if counter < self.recv_message_key_counter {

            let key = self.try_skipped_message_keys(counter)
                .ok_or_else(|| RatchetError::DecryptionFailed("找不到消息密钥".to_string()))?;

            key
        } else if counter > self.recv_message_key_counter {
            // 生成并保存中间消息密钥（处理消息跳跃）
            let mut chain_key = self.recv_chain_key.clone();
            let mut keys = Vec::new();
            
            // 为中间的所有消息生成密钥
            for i in self.recv_message_key_counter..counter {
                // 导出消息密钥和下一个链密钥
                let (message_key, next_chain_key) = self.chain_key_step(&chain_key)?;
                
                // 打印日志前复制消息密钥以避免所有权问题

                
                // 更新链密钥
                chain_key = next_chain_key;
                
                // 保存跳过的消息密钥
                keys.push((i, message_key));
            }
            
            // 添加所有跳过的消息密钥到缓存
            self.skipped_message_keys.extend(keys);

            
            // 更新链密钥和计数器
            self.recv_chain_key = chain_key;
            self.recv_message_key_counter = counter;
            
            // 接收链步进，获取当前消息密钥
            let (message_key, next_chain_key) = self.chain_key_step(&self.recv_chain_key)?;
            self.recv_chain_key = next_chain_key;
            self.recv_message_key_counter += 1;

            message_key
        } else {
            // 顺序接收 - 接收链步进，获取当前消息密钥
            let (message_key, next_chain_key) = self.chain_key_step(&self.recv_chain_key)?;
            self.recv_chain_key = next_chain_key;
            self.recv_message_key_counter += 1;

            message_key
        };
        
        // 清理旧的跳过消息密钥 - 安全考虑限制缓存大小
        self.clean_old_skipped_message_keys(100);
        
        // 检查密文长度
        if ciphertext.len() < 12 {
            return Err(RatchetError::DecryptionFailed("Ciphertext too short".to_string()));
        }
        
        // 解析IV和密文
        let iv = &ciphertext[0..12];
        let encrypted = &ciphertext[12..];

        
        // 使用ChaCha20-Poly1305解密
        let key = Key::from_slice(&message_key);
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = Nonce::from_slice(iv);
        
        // 关联数据 - 使用小端序以确保跨平台一致性
        let associated_data = counter.to_le_bytes();

        
        // 创建Payload类型的有效负载
        let payload = Payload {
            msg: encrypted,
            aad: &associated_data,  // 使用计数器作为关联数据，确保与加密一致
        };

        
        // 解密消息 - 复制消息密钥信息以在错误中使用
        let message_key_hex = hex::encode(&message_key);
        let key_len = message_key.len();

        
        let plaintext = cipher.decrypt(nonce, payload)
            .map_err(|e| {
                // 提供更详细的错误信息以便调试

                RatchetError::DecryptionFailed(format!(
                    "AEAD error: {}. Counter: {}, Key length: {}", 
                    e.to_string(), counter, key_len
                ))
            })?;

        
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 创建固定的测试共享秘密，确保测试的可重现性
    fn create_test_shared_secret() -> Vec<u8> {
        // 使用固定值代替随机值，确保测试可重现
        let secret = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32].to_vec();

        secret
    }

    #[test]
    fn test_double_ratchet_basic() -> Result<(), RatchetError> {

        // 使用带有明显模式的固定共享秘密
        let shared_secret = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
                               0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00];

        // 创建固定的Bob密钥对来确保测试的可重现性
        // 使用generate方法创建密钥对
        let bob_key_pair = KeyPair::generate().unwrap();
        let _alice_key_pair = KeyPair::generate().unwrap(); // 保留变量以便理解测试

        // 初始化Alice的双棘轮
        let mut alice_ratchet = DoubleRatchet::new_initiator(
            &shared_secret,
            &bob_key_pair.public,
        ).unwrap();

        // 初始化Bob的双棘轮
        let mut bob_ratchet = DoubleRatchet::new_responder(
            &shared_secret,
            bob_key_pair,
        ).unwrap();

        // Alice发送消息给Bob
        let plaintext = b"Hello, Bob!";
        let (ciphertext, alice_public, counter) = alice_ratchet.encrypt(plaintext).unwrap();

        // Bob接收并解密消息
        let decrypted = bob_ratchet.decrypt(&ciphertext, &alice_public, counter).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());

        // Bob回复Alice
        let reply = b"Hello, Alice!";
        let (ciphertext, bob_public, counter) = bob_ratchet.encrypt(reply).unwrap();

        // Alice接收并解密回复
        let decrypted = alice_ratchet.decrypt(&ciphertext, &bob_public, counter).unwrap();

        assert_eq!(reply, decrypted.as_slice());

        Ok(())
    }

    #[test]
    fn test_double_ratchet_out_of_order() -> Result<(), RatchetError> {

        // 使用固定共享秘密
        let shared_secret = [1u8; 32].to_vec();

        // 创建固定的Bob密钥对来确保测试的可重现性
        // 使用generate方法创建密钥对
        let bob_key_pair = KeyPair::generate().unwrap();
        let _alice_key_pair = KeyPair::generate().unwrap(); // 保留变量以便理解测试
        
        // 初始化Alice的双棘轮
        let mut alice_ratchet = DoubleRatchet::new_initiator(
            &shared_secret,
            &bob_key_pair.public,
        )?;
        
        // 初始化Bob的双棘轮
        let mut bob_ratchet = DoubleRatchet::new_responder(
            &shared_secret,
            bob_key_pair,
        )?;
        
        // Alice发送3条消息
        let message1 = b"Message 1";
        let (ciphertext1, alice_public, counter1) = alice_ratchet.encrypt(message1)?;
        
        let message2 = b"Message 2";
        let (ciphertext2, _, counter2) = alice_ratchet.encrypt(message2)?;
        
        let message3 = b"Message 3";
        let (ciphertext3, _, counter3) = alice_ratchet.encrypt(message3)?;
        
        // Bob先接收消息3，然后是消息1，最后是消息2
        let decrypted3 = bob_ratchet.decrypt(&ciphertext3, &alice_public, counter3)?;
        assert_eq!(message3, decrypted3.as_slice());
        
        let decrypted1 = bob_ratchet.decrypt(&ciphertext1, &alice_public, counter1)?;
        assert_eq!(message1, decrypted1.as_slice());
        
        let decrypted2 = bob_ratchet.decrypt(&ciphertext2, &alice_public, counter2)?;
        assert_eq!(message2, decrypted2.as_slice());
        
        Ok(())
    }
}
