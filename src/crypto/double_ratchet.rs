use crate::crypto::{KeyPair, PublicKey};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::{Aead, NewAead};
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;
use rand::Rng;
use ring::hmac;

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
    /// 创建新的双棘轮，初始化发送方
    pub fn new_initiator(
        shared_secret: &[u8],
        remote_public_key: &PublicKey,
    ) -> Result<Self, RatchetError> {
        // 生成DH密钥对
        let dh_key_pair = KeyPair::generate()
            .map_err(|e| RatchetError::KeyExchangeFailed(e.to_string()))?;
        
        // 使用共享秘密和DH输出初始化根密钥
        let mut ratchet = Self {
            root_key: shared_secret.to_vec(),
            send_chain_key: Vec::new(),
            recv_chain_key: Vec::new(),
            send_message_key_counter: 0,
            recv_message_key_counter: 0,
            dh_key_pair: Some(dh_key_pair),
            dh_remote_key: Some(remote_public_key.clone()),
            skipped_message_keys: Vec::new(),
        };
        
        // 执行初始密钥导出
        ratchet.dh_ratchet()?;
        
        Ok(ratchet)
    }
    
    /// 创建新的双棘轮，初始化接收方
    pub fn new_responder(
        shared_secret: &[u8],
        local_key_pair: KeyPair,
    ) -> Result<Self, RatchetError> {
        // 初始化双棘轮
        let ratchet = Self {
            root_key: shared_secret.to_vec(),
            send_chain_key: Vec::new(),
            recv_chain_key: Vec::new(),
            send_message_key_counter: 0,
            recv_message_key_counter: 0,
            dh_key_pair: Some(local_key_pair),
            dh_remote_key: None, // 尚未收到发送方的公钥
            skipped_message_keys: Vec::new(),
        };
        
        Ok(ratchet)
    }
    
    /// 执行DH棘轮步进
    fn dh_ratchet(&mut self) -> Result<(), RatchetError> {
        // 确保有必要的密钥
        let dh_pair = self.dh_key_pair.as_ref()
            .ok_or_else(|| RatchetError::InvalidState("Missing DH key pair".to_string()))?;
        
        let remote_key = self.dh_remote_key.as_ref()
            .ok_or_else(|| RatchetError::InvalidState("Missing remote public key".to_string()))?;
        
        // 计算DH共享秘密
        // 注意：在真实实现中，这需要使用合适的DH函数，例如X25519
        // 这里简化为将公钥和私钥拼接后哈希
        let mut dh_output = Vec::new();
        dh_output.extend_from_slice(&dh_pair.public.to_bytes().unwrap());
        dh_output.extend_from_slice(&remote_key.to_bytes().unwrap());
        
        let mut hasher = ring::digest::Context::new(&ring::digest::SHA256);
        hasher.update(&dh_output);
        let dh_output = hasher.finish();
        
        // 导出新的根密钥和链密钥
        let derived = kdf(
            &self.root_key,
            dh_output.as_ref(),
            b"DoubleRatchetUpdate",
            64,
        )?;
        
        // 更新密钥
        self.root_key = derived[0..32].to_vec();
        self.send_chain_key = derived[32..64].to_vec();
        
        // 重置消息计数器
        self.send_message_key_counter = 0;
        
        Ok(())
    }
    
    /// 接收方处理新的DH棘轮
    fn dh_ratchet_response(&mut self, remote_public_key: &PublicKey) -> Result<(), RatchetError> {
        // 保存跳过的消息密钥
        self.save_skipped_message_keys()?;
        
        // 交换发送链和接收链
        std::mem::swap(&mut self.send_chain_key, &mut self.recv_chain_key);
        
        // 更新远程公钥
        self.dh_remote_key = Some(remote_public_key.clone());
        
        // 生成新的密钥对
        self.dh_key_pair = Some(KeyPair::generate()
            .map_err(|e| RatchetError::KeyExchangeFailed(e.to_string()))?);
        
        // 执行DH棘轮步进
        self.dh_ratchet()?;
        
        Ok(())
    }
    
    /// 保存跳过的消息密钥
    fn save_skipped_message_keys(&mut self) -> Result<(), RatchetError> {
        // 创建接收链的消息密钥，直到最新的接收计数器
        if !self.recv_chain_key.is_empty() {
            let chain_key = self.recv_chain_key.clone();
            
            for i in (self.recv_message_key_counter + 1)..30 { // 限制最多保存30个跳过的密钥
                // 导出消息密钥
                let message_key = self.chain_key_step(&chain_key)?;
                
                // 保存跳过的消息密钥
                self.skipped_message_keys.push((i, message_key));
            }
        }
        
        Ok(())
    }
    
    /// 链密钥步进
    fn chain_key_step(&self, chain_key: &[u8]) -> Result<Vec<u8>, RatchetError> {
        // 使用HMAC-SHA256导出新的链密钥和消息密钥
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, b"DoubleRatchetChain");
        let mut ctx = hmac::Context::with_key(&hmac_key);
        ctx.update(chain_key);
        let result = ctx.sign();
        
        // 前32字节作为消息密钥
        Ok(result.as_ref().to_vec())
    }
    
    /// 发送链步进
    fn send_chain_step(&mut self) -> Result<Vec<u8>, RatchetError> {
        if self.send_chain_key.is_empty() {
            return Err(RatchetError::InvalidState("Send chain key not initialized".to_string()));
        }
        
        // 导出消息密钥
        let message_key = self.chain_key_step(&self.send_chain_key)?;
        
        // 更新链密钥
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, b"DoubleRatchetNext");
        let mut ctx = hmac::Context::with_key(&hmac_key);
        ctx.update(&self.send_chain_key);
        let result = ctx.sign();
        self.send_chain_key = result.as_ref().to_vec();
        
        // 增加消息计数器
        self.send_message_key_counter += 1;
        
        Ok(message_key)
    }
    
    /// 接收链步进
    fn recv_chain_step(&mut self) -> Result<Vec<u8>, RatchetError> {
        if self.recv_chain_key.is_empty() {
            return Err(RatchetError::InvalidState("Receive chain key not initialized".to_string()));
        }
        
        // 导出消息密钥
        let message_key = self.chain_key_step(&self.recv_chain_key)?;
        
        // 更新链密钥
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, b"DoubleRatchetNext");
        let mut ctx = hmac::Context::with_key(&hmac_key);
        ctx.update(&self.recv_chain_key);
        let result = ctx.sign();
        self.recv_chain_key = result.as_ref().to_vec();
        
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
        
        // 发送链步进，获取消息密钥
        let message_key = self.send_chain_step()?;
        
        // 生成随机IV
        let mut iv = [0u8; 12];
        rand::thread_rng().fill(&mut iv);
        
        // 使用ChaCha20-Poly1305加密
        let key = Key::from_slice(&message_key);
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = Nonce::from_slice(&iv);
        
        // 加密消息
        let ciphertext = cipher.encrypt(nonce, plaintext)
            .map_err(|e| RatchetError::EncryptionFailed(e.to_string()))?;
        
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
        // 检查是否需要执行DH棘轮
        let dh_changed = match &self.dh_remote_key {
            Some(key) => key.to_bytes().unwrap() != remote_public_key.to_bytes().unwrap(),
            None => true,
        };
        
        if dh_changed {
            // 执行DH棘轮
            self.dh_ratchet_response(remote_public_key)?;
        }
        
        // 获取消息密钥
        let message_key = if counter < self.recv_message_key_counter {
            // 尝试使用跳过的消息密钥
            self.try_skipped_message_keys(counter)
                .ok_or_else(|| RatchetError::DecryptionFailed("Message key not found".to_string()))?
        } else if counter > self.recv_message_key_counter {
            // 生成并保存中间消息密钥
            let mut chain_key = self.recv_chain_key.clone();
            let mut keys = Vec::new();
            
            for i in self.recv_message_key_counter..counter {
                // 导出消息密钥
                let key = self.chain_key_step(&chain_key)?;
                
                // 更新链密钥
                let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, b"DoubleRatchetNext");
                let mut ctx = hmac::Context::with_key(&hmac_key);
                ctx.update(&chain_key);
                let result = ctx.sign();
                chain_key = result.as_ref().to_vec();
                
                // 保存跳过的消息密钥
                keys.push((i, key));
            }
            
            // 添加所有跳过的消息密钥
            self.skipped_message_keys.extend(keys);
            
            // 更新链密钥和计数器
            self.recv_chain_key = chain_key;
            self.recv_message_key_counter = counter;
            
            // 接收链步进，获取当前消息密钥
            self.recv_chain_step()?
        } else {
            // 接收链步进，获取当前消息密钥
            self.recv_chain_step()?
        };
        
        // 清理旧的跳过消息密钥
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
        
        // 解密消息
        let plaintext = cipher.decrypt(nonce, encrypted)
            .map_err(|e| RatchetError::DecryptionFailed(e.to_string()))?;
        
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    // 创建测试共享秘密
    fn create_test_shared_secret() -> Vec<u8> {
        let mut secret = [0u8; 32];
        rand::thread_rng().fill(&mut secret);
        secret.to_vec()
    }
    
    #[test]
    fn test_double_ratchet_basic() -> Result<(), RatchetError> {
        // 创建共享秘密
        let shared_secret = create_test_shared_secret();
        
        // 创建Alice和Bob的密钥对
        let alice_key_pair = KeyPair::generate().unwrap();
        let bob_key_pair = KeyPair::generate().unwrap();
        
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
        
        // Alice发送消息给Bob
        let plaintext = b"Hello, Bob!";
        let (ciphertext, alice_public, counter) = alice_ratchet.encrypt(plaintext)?;
        
        // Bob接收并解密消息
        let decrypted = bob_ratchet.decrypt(&ciphertext, &alice_public, counter)?;
        
        assert_eq!(plaintext, decrypted.as_slice());
        
        // Bob回复Alice
        let reply = b"Hello, Alice!";
        let (ciphertext, bob_public, counter) = bob_ratchet.encrypt(reply)?;
        
        // Alice接收并解密回复
        let decrypted = alice_ratchet.decrypt(&ciphertext, &bob_public, counter)?;
        
        assert_eq!(reply, decrypted.as_slice());
        
        Ok(())
    }
    
    #[test]
    fn test_double_ratchet_out_of_order() -> Result<(), RatchetError> {
        // 创建共享秘密
        let shared_secret = create_test_shared_secret();
        
        // 创建Alice和Bob的密钥对
        let alice_key_pair = KeyPair::generate().unwrap();
        let bob_key_pair = KeyPair::generate().unwrap();
        
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
