use crate::identity::UserId;
use crate::crypto::{PublicKey, KeyPair};
use serde::{Deserialize, Serialize};
// 移除未使用的导入
// use ed25519_dalek::Signer;
use std::fmt;
use std::time::SystemTime;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DeviceError {
    #[error("Device creation failed: {0}")]
    CreationFailed(String),
    
    #[error("Device verification failed: {0}")]
    VerificationFailed(String),
    
    #[error("Device operation failed: {0}")]
    OperationFailed(String),
}

/// 设备ID，唯一标识一个设备
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceId(pub [u8; 32]);

impl DeviceId {
    /// 从设备公钥派生设备ID
    pub fn from_public_key(public_key: &PublicKey) -> Result<Self, DeviceError> {
        let key_bytes = public_key.to_bytes()
            .map_err(|e| DeviceError::CreationFailed(e.to_string()))?;
        
        let mut hasher = ring::digest::Context::new(&ring::digest::SHA256);
        hasher.update(&key_bytes);
        let digest = hasher.finish();
        
        let mut id = [0u8; 32];
        id.copy_from_slice(digest.as_ref());
        
        Ok(Self(id))
    }
}

impl fmt::Debug for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceId({})", hex::encode(&self.0[..6]))
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

/// 设备能力
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCapabilities {
    /// 设备可以作为中继
    pub can_relay: bool,
    
    /// 设备可以存储离线消息
    pub can_store_offline: bool,
    
    /// 设备是否通常在线
    pub is_always_online: bool,
    
    /// 设备的带宽能力（0-100）
    pub bandwidth_score: u8,
    
    /// 设备的存储能力（MB）
    pub storage_capacity: u64,
}

impl Default for DeviceCapabilities {
    fn default() -> Self {
        Self {
            can_relay: false,
            can_store_offline: true,
            is_always_online: false,
            bandwidth_score: 50,
            storage_capacity: 100,
        }
    }
}

/// 设备信息
#[derive(Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// 设备ID
    pub device_id: DeviceId,
    
    /// 所有者ID（可选，用于多用户设备）
    pub owner_id: Option<UserId>,
    
    /// 设备名称
    pub name: String,
    
    /// 设备公钥
    pub public_key: PublicKey,
    
    /// 设备类型
    pub device_type: DeviceType,
    
    /// 设备能力
    pub capabilities: DeviceCapabilities,
    
    /// 最后活跃时间
    pub last_active: SystemTime,
    
    /// 最后已知地址（可选）
    pub last_known_address: Option<String>,
    
    /// 创建时间
    pub created_at: SystemTime,
    
    /// 签名
    pub signature: Vec<u8>,
}

/// 设备类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceType {
    /// 移动设备
    Mobile,
    
    /// 桌面设备
    Desktop,
    
    /// 服务器
    Server,
    
    /// 嵌入式设备
    Embedded,
    
    /// 其他设备
    Other,
}

impl DeviceInfo {
    /// 创建新的设备信息
    pub fn new(
        name: String,
        keypair: &KeyPair,
        device_type: DeviceType,
        owner_id: Option<UserId>,
    ) -> Result<Self, DeviceError> {
        // 从公钥派生设备ID
        let device_id = DeviceId::from_public_key(&keypair.public)?;
        
        // 创建默认设备能力
        let capabilities = DeviceCapabilities::default();
        
        let now = SystemTime::now();
        
        // 创建设备信息
        let mut device = Self {
            device_id,
            owner_id,
            name,
            public_key: keypair.public.clone(),
            device_type,
            capabilities,
            last_active: now,
            last_known_address: None,
            created_at: now,
            signature: Vec::new(),
        };
        
        // 签名设备信息
        device.sign(keypair)?;
        
        Ok(device)
    }
    
    /// 签名设备信息
    pub fn sign(&mut self, keypair: &KeyPair) -> Result<(), DeviceError> {
        // 创建一个副本，但没有签名
        let mut device_copy = self.clone();
        device_copy.signature = Vec::new();
        
        // 序列化设备信息
        let device_bytes = bincode::serialize(&device_copy)
            .map_err(|e| DeviceError::OperationFailed(e.to_string()))?;
        
        // 签名设备信息
        self.signature = crate::crypto::sign(&keypair.secret, &device_bytes)
            .map_err(|e| DeviceError::OperationFailed(e.to_string()))?;
        
        Ok(())
    }
    
    /// 验证设备信息签名
    pub fn verify(&self) -> Result<(), DeviceError> {
        // 创建一个副本，但没有签名
        let mut device_copy = self.clone();
        device_copy.signature = Vec::new();
        
        // 序列化设备信息
        let device_bytes = bincode::serialize(&device_copy)
            .map_err(|e| DeviceError::VerificationFailed(e.to_string()))?;
        
        // 验证签名
        crate::crypto::verify(&self.public_key, &device_bytes, &self.signature)
            .map_err(|e| DeviceError::VerificationFailed(e.to_string()))?;
        
        Ok(())
    }
    
    /// 更新设备信息
    pub fn update(
        &mut self,
        name: Option<String>,
        capabilities: Option<DeviceCapabilities>,
        last_known_address: Option<String>,
        keypair: &KeyPair,
    ) -> Result<(), DeviceError> {
        // 更新信息
        if let Some(name) = name {
            self.name = name;
        }
        
        if let Some(capabilities) = capabilities {
            self.capabilities = capabilities;
        }
        
        self.last_known_address = last_known_address;
        self.last_active = SystemTime::now();
        
        // 重新签名
        self.sign(keypair)?;
        
        Ok(())
    }
    
    /// 检查设备信息是否过期
    pub fn is_expired(&self, ttl: std::time::Duration) -> bool {
        match SystemTime::now().duration_since(self.last_active) {
            Ok(age) => age > ttl,
            Err(_) => false, // 时钟回调，视为未过期
        }
    }
}

impl fmt::Debug for DeviceInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceInfo")
            .field("device_id", &self.device_id)
            .field("owner_id", &self.owner_id)
            .field("name", &self.name)
            .field("device_type", &self.device_type)
            .field("capabilities", &self.capabilities)
            .field("last_active", &self.last_active)
            .field("last_known_address", &self.last_known_address)
            .field("created_at", &self.created_at)
            .field("signature", &format!("[{} bytes]", self.signature.len()))
            .finish()
    }
}

/// 设备授权令牌
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceAuthToken {
    /// 发布者设备ID
    pub issuer_device_id: DeviceId,
    
    /// 所有者用户ID
    pub owner_id: UserId,
    
    /// 令牌唯一ID
    pub token_id: [u8; 16],
    
    /// 发布时间
    pub issued_at: SystemTime,
    
    /// 过期时间
    pub expires_at: SystemTime,
    
    /// 授权的设备类型
    pub authorized_device_type: DeviceType,
    
    /// 授权的设备能力
    pub authorized_capabilities: DeviceCapabilities,
    
    /// 一次性预共享密钥（用于安全通信）
    pub one_time_key: Vec<u8>,
    
    /// 发布者签名
    pub signature: Vec<u8>,
}

impl DeviceAuthToken {
    /// 创建新的设备授权令牌
    pub fn new(
        issuer_device: &DeviceInfo,
        owner_id: &UserId,
        device_type: DeviceType,
        capabilities: DeviceCapabilities,
        validity_period: std::time::Duration,
        keypair: &KeyPair,
    ) -> Result<Self, DeviceError> {
        // 生成令牌ID
        let mut token_id = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut token_id);
        
        // 生成一次性密钥
        let mut one_time_key = vec![0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut one_time_key);
        
        let now = SystemTime::now();
        
        // 创建令牌
        let mut token = Self {
            issuer_device_id: issuer_device.device_id.clone(),
            owner_id: owner_id.clone(),
            token_id,
            issued_at: now,
            expires_at: now + validity_period,
            authorized_device_type: device_type,
            authorized_capabilities: capabilities,
            one_time_key,
            signature: Vec::new(),
        };
        
        // 签名令牌
        token.sign(keypair)?;
        
        Ok(token)
    }
    
    /// 签名令牌
    pub fn sign(&mut self, keypair: &KeyPair) -> Result<(), DeviceError> {
        // 创建一个副本，但没有签名
        let mut token_copy = self.clone();
        token_copy.signature = Vec::new();
        
        // 序列化令牌
        let token_bytes = bincode::serialize(&token_copy)
            .map_err(|e| DeviceError::OperationFailed(e.to_string()))?;
        
        // 签名令牌
        self.signature = crate::crypto::sign(&keypair.secret, &token_bytes)
            .map_err(|e| DeviceError::OperationFailed(e.to_string()))?;
        
        Ok(())
    }
    
    /// 验证令牌签名
    pub fn verify(&self, issuer_public_key: &PublicKey) -> Result<(), DeviceError> {
        // 创建一个副本，但没有签名
        let mut token_copy = self.clone();
        token_copy.signature = Vec::new();
        
        // 序列化令牌
        let token_bytes = bincode::serialize(&token_copy)
            .map_err(|e| DeviceError::VerificationFailed(e.to_string()))?;
        
        // 验证签名
        crate::crypto::verify(issuer_public_key, &token_bytes, &self.signature)
            .map_err(|e| DeviceError::VerificationFailed(e.to_string()))?;
        
        Ok(())
    }
    
    /// 检查令牌是否过期
    pub fn is_expired(&self) -> bool {
        match SystemTime::now().duration_since(self.expires_at) {
            Ok(_) => true, // 当前时间超过过期时间
            Err(_) => false, // 当前时间尚未到达过期时间
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_device_info() {
        // 生成密钥对
        let keypair = KeyPair::generate().unwrap();
        
        // 创建设备信息
        let device = DeviceInfo::new(
            "Test Device".to_string(),
            &keypair,
            DeviceType::Desktop,
            None,
        ).unwrap();
        
        // 验证设备信息
        assert!(device.verify().is_ok());
        
        // 验证设备ID派生
        let derived_id = DeviceId::from_public_key(&keypair.public).unwrap();
        assert_eq!(device.device_id, derived_id);
    }
    
    #[test]
    fn test_device_auth_token() {
        // 生成密钥对
        let keypair = KeyPair::generate().unwrap();
        
        // 创建设备信息
        let device = DeviceInfo::new(
            "Test Device".to_string(),
            &keypair,
            DeviceType::Desktop,
            None,
        ).unwrap();
        
        // 创建用户ID
        let user_id = UserId([1u8; 32]);
        
        // 创建设备授权令牌
        let token = DeviceAuthToken::new(
            &device,
            &user_id,
            DeviceType::Mobile,
            DeviceCapabilities::default(),
            std::time::Duration::from_secs(3600), // 1小时有效期
            &keypair,
        ).unwrap();
        
        // 验证令牌
        assert!(token.verify(&keypair.public).is_ok());
        
        // 验证令牌未过期
        assert!(!token.is_expired());
    }
}
