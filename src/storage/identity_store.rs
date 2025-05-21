use crate::storage::Database;
use crate::identity::{UserIdentity, DeviceInfo, TrustStore};
use crate::identity::user::UserIdentityError;
use crate::identity::device::DeviceType;
// 移除未使用的导入
// use crate::crypto::{KeyPair, PublicKey};
// use serde::{Serialize, Deserialize};
use thiserror::Error;
use log::error;
// 移除未使用的导入
// use log::{debug, info, warn};
use hex;
// 移除未使用的导入
// use std::collections::HashMap;

#[derive(Error, Debug)]
pub enum IdentityStoreError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] crate::storage::DatabaseError),
    
    #[error("Identity not found: {0}")]
    IdentityNotFound(String),
    
    #[error("Device not found: {0}")]
    DeviceNotFound(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("Identity error: {0}")]
    IdentityError(#[from] UserIdentityError),
    
    #[error("Key error: {0}")]
    KeyError(String),
}

/// 身份存储
pub struct IdentityStore {
    /// 数据库实例
    db: Database,
}

impl IdentityStore {
    /// 创建新的身份存储
    pub fn new(db: &Database) -> Result<Self, IdentityStoreError> {
        // 初始化身份表
        let _ = db.get_tree("identities")?;
        let _ = db.get_tree("devices")?;
        let _ = db.get_tree("trusts")?;
        
        Ok(Self {
            db: db.clone(),
        })
    }
    
    /// 保存身份
    pub fn save_identity(&self, identity: &UserIdentity) -> Result<(), IdentityStoreError> {
        // 序列化身份
        let identity_data = bincode::serialize(identity)
            .map_err(|e| IdentityStoreError::SerializationError(e.to_string()))?;
        
        // 保存身份
        self.db.put("identities", identity.id.0.as_ref(), &identity_data)?;
        
        // 保存信任存储
        let trust_data = bincode::serialize(&identity.trust_store)
            .map_err(|e| IdentityStoreError::SerializationError(e.to_string()))?;
        
        self.db.put("trusts", identity.id.0.as_ref(), &trust_data)?;
        
        // 保存所有设备
        for device in &identity.devices {
            self.save_device(device)?;
        }
        
        Ok(())
    }
    
    /// 加载身份
    pub fn load_identity(&self, user_id: &crate::identity::UserId) -> Result<UserIdentity, IdentityStoreError> {
        // 获取身份数据
        let identity_data = self.db.get("identities", user_id.0.as_ref())?
            .ok_or_else(|| IdentityStoreError::IdentityNotFound(hex::encode(&user_id.0)))?;
        
        // 反序列化身份
        let identity: UserIdentity = bincode::deserialize(&identity_data)
            .map_err(|e| IdentityStoreError::SerializationError(e.to_string()))?;
        
        Ok(identity)
    }
    
    /// 保存设备
    pub fn save_device(&self, device: &DeviceInfo) -> Result<(), IdentityStoreError> {
        // 序列化设备
        let device_data = bincode::serialize(device)
            .map_err(|e| IdentityStoreError::SerializationError(e.to_string()))?;
        
        // 保存设备
        self.db.put("devices", device.device_id.0.as_ref(), &device_data)?;
        
        Ok(())
    }
    
    /// 加载设备
    pub fn load_device(&self, device_id: &crate::identity::DeviceId) -> Result<DeviceInfo, IdentityStoreError> {
        // 获取设备数据
        let device_data = self.db.get("devices", device_id.0.as_ref())?
            .ok_or_else(|| IdentityStoreError::DeviceNotFound(hex::encode(&device_id.0)))?;
        
        // 反序列化设备
        let device: DeviceInfo = bincode::deserialize(&device_data)
            .map_err(|e| IdentityStoreError::SerializationError(e.to_string()))?;
        
        Ok(device)
    }
    
    /// 加载信任存储
    pub fn load_trust_store(&self, user_id: &crate::identity::UserId) -> Result<TrustStore, IdentityStoreError> {
        // 获取信任存储数据
        let trust_data = self.db.get("trusts", user_id.0.as_ref())?
            .ok_or_else(|| IdentityStoreError::IdentityNotFound(hex::encode(&user_id.0)))?;
        
        // 反序列化信任存储
        let trust_store: TrustStore = bincode::deserialize(&trust_data)
            .map_err(|e| IdentityStoreError::SerializationError(e.to_string()))?;
        
        Ok(trust_store)
    }
    
    /// 更新信任存储
    pub fn update_trust_store(&self, user_id: &crate::identity::UserId, trust_store: &TrustStore) -> Result<(), IdentityStoreError> {
        // 序列化信任存储
        let trust_data = bincode::serialize(trust_store)
            .map_err(|e| IdentityStoreError::SerializationError(e.to_string()))?;
        
        // 保存信任存储
        self.db.put("trusts", user_id.0.as_ref(), &trust_data)?;
        
        Ok(())
    }
    
    /// 列出所有身份
    pub fn list_identities(&self) -> Result<Vec<UserIdentity>, IdentityStoreError> {
        let mut identities = Vec::new();
        
        // 扫描所有身份
        for (_, identity_data) in self.db.scan_prefix("identities", &[])? {
            // 反序列化身份
            match bincode::deserialize::<UserIdentity>(&identity_data) {
                Ok(identity) => identities.push(identity),
                Err(e) => error!("Failed to deserialize identity: {}", e),
            }
        }
        
        Ok(identities)
    }
    
    /// 列出所有设备
    pub fn list_devices(&self) -> Result<Vec<DeviceInfo>, IdentityStoreError> {
        let mut devices = Vec::new();
        
        // 扫描所有设备
        for (_, device_data) in self.db.scan_prefix("devices", &[])? {
            // 反序列化设备
            match bincode::deserialize::<DeviceInfo>(&device_data) {
                Ok(device) => devices.push(device),
                Err(e) => error!("Failed to deserialize device: {}", e),
            }
        }
        
        Ok(devices)
    }
    
    /// 删除身份
    pub fn delete_identity(&self, user_id: &crate::identity::UserId) -> Result<(), IdentityStoreError> {
        // 加载身份以获取所有设备
        if let Ok(identity) = self.load_identity(user_id) {
            // 删除所有设备
            for device in &identity.devices {
                self.db.delete("devices", device.device_id.0.as_ref())?;
            }
        }
        
        // 删除信任存储
        self.db.delete("trusts", user_id.0.as_ref())?;
        
        // 删除身份
        self.db.delete("identities", user_id.0.as_ref())?;
        
        Ok(())
    }
    
    /// 删除设备
    pub fn delete_device(&self, device_id: &crate::identity::DeviceId) -> Result<(), IdentityStoreError> {
        // 删除设备
        self.db.delete("devices", device_id.0.as_ref())?;
        
        Ok(())
    }
    
    /// 创建并保存新身份
    pub fn create_identity(&self, display_name: &str) -> Result<UserIdentity, IdentityStoreError> {
        // 创建新身份
        let identity = UserIdentity::new(display_name.to_string())?;
        
        // 保存身份
        self.save_identity(&identity)?;
        
        Ok(identity)
    }
    
    /// 添加设备到身份
    pub fn add_device_to_identity(
        &self,
        user_id: &crate::identity::UserId,
        device_name: &str,
        device_type: DeviceType,
    ) -> Result<DeviceInfo, IdentityStoreError> {
        // 加载身份
        let mut identity = self.load_identity(user_id)?;
        
        // 创建设备
        let device = DeviceInfo::new(
            device_name.to_string(),
            &identity.keypair,
            device_type,
            Some(user_id.clone()),
        ).map_err(|e| IdentityStoreError::IdentityError(UserIdentityError::CreationFailed(e.to_string())))?;
        
        // 添加设备到身份
        identity.add_device(device.clone())?;
        
        // 保存身份
        self.save_identity(&identity)?;
        
        Ok(device)
    }
}
