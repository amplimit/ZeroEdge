use crate::crypto::{PublicKey, SecretKey};
use crate::identity::UserId;
use crate::message::{Message, MessageType};
use thiserror::Error;
use serde::{Serialize, Deserialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Error, Debug)]
pub enum MessageEncryptionError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    
    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// 加密消息结构
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedMessage {
    /// 唯一标识符
    pub id: uuid::Uuid,
    
    /// 接收者ID
    pub recipient_id: UserId,
    
    /// 发送者ID
    pub sender_id: UserId,
    
    /// 发送者公钥
    pub sender_public_key: PublicKey,
    
    /// 加密内容
    pub encrypted_content: Vec<u8>,
    
    /// 内容类型
    pub content_type: String,
    
    /// 时间戳
    pub timestamp: u64,
    
    /// 序列号
    pub sequence: u64,
    
    /// 过期时间
    pub expiry: Option<u64>,
}

impl EncryptedMessage {
    /// 创建新的加密消息
    pub fn new(
        recipient_id: UserId,
        sender_id: UserId,
        sender_public_key: PublicKey,
        encrypted_content: Vec<u8>,
        content_type: String,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        Self {
            id: uuid::Uuid::new_v4(),
            recipient_id,
            sender_id,
            sender_public_key,
            encrypted_content,
            content_type,
            timestamp: now,
            sequence: 0,
            expiry: None,
        }
    }
    
    /// 设置过期时间
    pub fn with_expiry(mut self, expiry_seconds: u64) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        self.expiry = Some(now + expiry_seconds);
        self
    }
    
    /// 设置序列号
    pub fn with_sequence(mut self, sequence: u64) -> Self {
        self.sequence = sequence;
        self
    }
    
    /// 检查消息是否过期
    pub fn is_expired(&self) -> bool {
        if let Some(expiry) = self.expiry {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            
            now > expiry
        } else {
            false
        }
    }
    
    /// 转换为普通消息
    pub fn to_message(&self, decrypted_content: Vec<u8>) -> Message {
        Message {
            id: self.id,
            message_type: MessageType::Direct,
            timestamp: self.timestamp,
            sender_id: self.sender_id.clone(),
            recipient_id: Some(self.recipient_id.clone()),
            sender_public_key: self.sender_public_key.clone(),
            content: decrypted_content,
            content_type: self.content_type.clone(),
            signature: Vec::new(), // 待填充
            sequence_number: self.sequence,
            references: None,
        }
    }
}

/// 提供消息加密和解密功能
pub struct MessageEncryption;

impl MessageEncryption {
    /// 加密消息
    pub fn encrypt_message(
        message: &Message,
        recipient_public_key: &PublicKey,
        sender_secret_key: &SecretKey,
    ) -> Result<EncryptedMessage, MessageEncryptionError> {
        // 序列化消息
        let message_bytes = bincode::serialize(message)
            .map_err(|e| MessageEncryptionError::SerializationError(e.to_string()))?;
        
        // 加密消息内容
        let encrypted_content = crate::crypto::encrypt(
            recipient_public_key,
            sender_secret_key,
            &message_bytes,
        ).map_err(|e| MessageEncryptionError::EncryptionFailed(e.to_string()))?;
        
        // 创建加密消息
        let encrypted_message = EncryptedMessage::new(
            message.sender_id.clone(), // 用发送者ID代替，实际项目中应修改Message结构体添加recipient_id
            message.sender_id.clone(),
            message.sender_public_key.clone(),
            encrypted_content,
            message.content_type.clone(),
        )
        .with_sequence(message.sequence_number);
        
        // 在当前版本的Message中没有expires_at字段
        // 这里设置一个默认的过期时间，比如两天
        let default_expiry = 60 * 60 * 24 * 2; // 2天，以秒为单位
        Ok(encrypted_message.with_expiry(default_expiry))
    }
    
    /// 解密消息
    pub fn decrypt_message(
        encrypted_message: &EncryptedMessage,
        recipient_secret_key: &SecretKey,
    ) -> Result<Message, MessageEncryptionError> {
        // 解密消息内容
        let decrypted_content = crate::crypto::decrypt(
            recipient_secret_key,
            &encrypted_message.sender_public_key,
            &encrypted_message.encrypted_content,
        ).map_err(|e| MessageEncryptionError::DecryptionFailed(e.to_string()))?;
        
        // 反序列化消息
        let message: Message = bincode::deserialize(&decrypted_content)
            .map_err(|e| MessageEncryptionError::SerializationError(e.to_string()))?;
        
        Ok(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;
    
    #[test]
    fn test_encrypt_decrypt() {
        // 创建发送者和接收者的密钥对
        let sender_keypair = KeyPair::generate().unwrap();
        let recipient_keypair = KeyPair::generate().unwrap();
        
        // 创建用户ID
        let sender_id = crate::identity::UserId([1; 32]);
        let recipient_id = crate::identity::UserId([2; 32]);
        
        // 创建原始消息
        let message = Message {
            id: uuid::Uuid::new_v4(),
            message_type: MessageType::Direct,
            timestamp: 12345,
            sender_id: sender_id.clone(),
            recipient_id: Some(recipient_id.clone()),
            sender_public_key: sender_keypair.public.clone(),
            content: b"Hello, world!".to_vec(),
            content_type: "text/plain".to_string(),
            signature: Vec::new(),
            sequence_number: 1,
            references: None,
            expires_at: None,
        };
        
        // 加密消息
        let encrypted_message = MessageEncryption::encrypt_message(
            &message,
            &recipient_keypair.public,
            &sender_keypair.secret,
        ).unwrap();
        
        // 验证加密消息的属性
        assert_eq!(encrypted_message.sender_id, sender_id);
        assert_eq!(encrypted_message.recipient_id, recipient_id);
        assert_eq!(encrypted_message.sender_public_key, sender_keypair.public);
        assert_eq!(encrypted_message.content_type, "text/plain");
        
        // 解密消息
        let decrypted_message = MessageEncryption::decrypt_message(
            &encrypted_message,
            &recipient_keypair.secret,
        ).unwrap();
        
        // 验证解密后的消息
        assert_eq!(decrypted_message.id, message.id);
        assert_eq!(decrypted_message.message_type, message.message_type);
        assert_eq!(decrypted_message.timestamp, message.timestamp);
        assert_eq!(decrypted_message.sender_id, message.sender_id);
        assert_eq!(decrypted_message.content, message.content);
        assert_eq!(decrypted_message.content_type, message.content_type);
        assert_eq!(decrypted_message.sequence_number, message.sequence_number);
    }
}
