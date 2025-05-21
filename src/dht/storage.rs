use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Error, Debug)]
pub enum DhtStorageError {
    #[error("Storage error: {0}")]
    StorageError(String),
    
    #[error("Value not found")]
    ValueNotFound,
    
    #[error("Value expired")]
    ValueExpired,
}

/// DHT存储的值
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DhtValue {
    /// 存储的数据
    pub data: Vec<u8>,
    
    /// 发布者ID
    pub publisher: Option<Vec<u8>>,
    
    /// 存储时间
    pub timestamp: SystemTime,
    
    /// 过期时间
    pub expiry: Option<SystemTime>,
    
    /// 版本号
    pub version: u64,
}

impl DhtValue {
    /// 创建新的DHT值
    pub fn new(data: Vec<u8>, ttl: Option<Duration>) -> Self {
        let now = SystemTime::now();
        let expiry = ttl.map(|ttl| now + ttl);
        
        Self {
            data,
            publisher: None,
            timestamp: now,
            expiry,
            version: 1,
        }
    }
    
    /// 检查值是否已过期
    pub fn is_expired(&self) -> bool {
        if let Some(expiry) = self.expiry {
            match SystemTime::now().duration_since(expiry) {
                Ok(_) => true, // 当前时间超过过期时间
                Err(_) => false, // 当前时间未超过过期时间
            }
        } else {
            false // 没有过期时间
        }
    }
    
    /// 更新值
    pub fn update(&mut self, new_data: Vec<u8>, ttl: Option<Duration>) {
        let now = SystemTime::now();
        self.data = new_data;
        self.timestamp = now;
        self.expiry = ttl.map(|ttl| now + ttl);
        self.version += 1;
    }
}

/// DHT存储接口
pub trait DhtStorage: Send + Sync {
    /// 存储键值对
    async fn store(&self, key: Vec<u8>, value: DhtValue) -> Result<(), DhtStorageError>;
    
    /// 获取键对应的值
    async fn get(&self, key: &[u8]) -> Result<DhtValue, DhtStorageError>;
    
    /// 检查键是否存在
    async fn contains(&self, key: &[u8]) -> bool;
    
    /// 移除键值对
    async fn remove(&self, key: &[u8]) -> Result<(), DhtStorageError>;
    
    /// 获取所有键
    async fn keys(&self) -> Vec<Vec<u8>>;
    
    /// 清理过期数据
    async fn cleanup_expired(&self) -> usize;
}

/// 内存DHT存储实现
pub struct MemoryDhtStorage {
    /// 存储数据
    data: Arc<RwLock<HashMap<Vec<u8>, DhtValue>>>,
}

impl MemoryDhtStorage {
    /// 创建新的内存DHT存储
    pub fn new() -> Self {
        Self {
            data: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl DhtStorage for MemoryDhtStorage {
    /// 存储键值对
    async fn store(&self, key: Vec<u8>, value: DhtValue) -> Result<(), DhtStorageError> {
        let mut data = self.data.write().await;
        data.insert(key, value);
        Ok(())
    }
    
    /// 获取键对应的值
    async fn get(&self, key: &[u8]) -> Result<DhtValue, DhtStorageError> {
        let data = self.data.read().await;
        
        // 查找键
        match data.get(key) {
            Some(value) => {
                // 检查是否过期
                if value.is_expired() {
                    return Err(DhtStorageError::ValueExpired);
                }
                
                Ok(value.clone())
            },
            None => Err(DhtStorageError::ValueNotFound),
        }
    }
    
    /// 检查键是否存在
    async fn contains(&self, key: &[u8]) -> bool {
        let data = self.data.read().await;
        data.contains_key(key)
    }
    
    /// 移除键值对
    async fn remove(&self, key: &[u8]) -> Result<(), DhtStorageError> {
        let mut data = self.data.write().await;
        data.remove(key);
        Ok(())
    }
    
    /// 获取所有键
    async fn keys(&self) -> Vec<Vec<u8>> {
        let data = self.data.read().await;
        data.keys().cloned().collect()
    }
    
    /// 清理过期数据
    async fn cleanup_expired(&self) -> usize {
        let mut data = self.data.write().await;
        
        // 找出所有过期的键
        let expired_keys: Vec<Vec<u8>> = data.iter()
            .filter(|(_, value)| value.is_expired())
            .map(|(key, _)| key.clone())
            .collect();
        
        // 移除过期的键
        for key in &expired_keys {
            data.remove(key);
        }
        
        expired_keys.len()
    }
}

/// 持久化DHT存储实现（使用sled数据库）
pub struct PersistentDhtStorage {
    /// 数据库
    db: sled::Db,
}

impl PersistentDhtStorage {
    /// 创建新的持久化DHT存储
    pub fn new(path: &str) -> Result<Self, DhtStorageError> {
        // 打开数据库
        let db = sled::open(path)
            .map_err(|e| DhtStorageError::StorageError(e.to_string()))?;
        
        Ok(Self { db })
    }
}

impl DhtStorage for PersistentDhtStorage {
    /// 存储键值对
    async fn store(&self, key: Vec<u8>, value: DhtValue) -> Result<(), DhtStorageError> {
        // 序列化值
        let encoded = bincode::serialize(&value)
            .map_err(|e| DhtStorageError::StorageError(e.to_string()))?;
        
        // 存储到数据库
        self.db.insert(key, encoded)
            .map_err(|e| DhtStorageError::StorageError(e.to_string()))?;
        
        Ok(())
    }
    
    /// 获取键对应的值
    async fn get(&self, key: &[u8]) -> Result<DhtValue, DhtStorageError> {
        // 从数据库获取
        let encoded = self.db.get(key)
            .map_err(|e| DhtStorageError::StorageError(e.to_string()))?
            .ok_or(DhtStorageError::ValueNotFound)?;
        
        // 反序列化值
        let value: DhtValue = bincode::deserialize(&encoded)
            .map_err(|e| DhtStorageError::StorageError(e.to_string()))?;
        
        // 检查是否过期
        if value.is_expired() {
            return Err(DhtStorageError::ValueExpired);
        }
        
        Ok(value)
    }
    
    /// 检查键是否存在
    async fn contains(&self, key: &[u8]) -> bool {
        match self.db.contains_key(key) {
            Ok(exists) => exists,
            Err(_) => false,
        }
    }
    
    /// 移除键值对
    async fn remove(&self, key: &[u8]) -> Result<(), DhtStorageError> {
        self.db.remove(key)
            .map_err(|e| DhtStorageError::StorageError(e.to_string()))?;
        
        Ok(())
    }
    
    /// 获取所有键
    async fn keys(&self) -> Vec<Vec<u8>> {
        self.db.iter()
            .filter_map(|res| res.ok())
            .map(|(key, _)| key.to_vec())
            .collect()
    }
    
    /// 清理过期数据
    async fn cleanup_expired(&self) -> usize {
        let mut expired_count = 0;
        
        // 遍历所有键值对
        for res in self.db.iter() {
            // 跳过错误
            let (key, encoded) = match res {
                Ok(pair) => pair,
                Err(_) => continue,
            };
            
            // 尝试反序列化
            let value: DhtValue = match bincode::deserialize(&encoded) {
                Ok(value) => value,
                Err(_) => continue,
            };
            
            // 检查是否过期
            if value.is_expired() {
                // 移除过期数据
                if let Ok(_) = self.db.remove(key) {
                    expired_count += 1;
                }
            }
        }
        
        expired_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    
    #[tokio::test]
    async fn test_memory_storage() {
        let storage = MemoryDhtStorage::new();
        
        // 创建测试数据
        let key = b"test_key".to_vec();
        let value = DhtValue::new(b"test_value".to_vec(), Some(Duration::from_secs(300)));
        
        // 存储数据
        storage.store(key.clone(), value.clone()).await.unwrap();
        
        // 获取数据
        let retrieved = storage.get(&key).await.unwrap();
        assert_eq!(retrieved.data, b"test_value".to_vec());
        
        // 检查是否存在
        assert!(storage.contains(&key).await);
        
        // 移除数据
        storage.remove(&key).await.unwrap();
        
        // 检查是否已移除
        assert!(!storage.contains(&key).await);
    }
}
