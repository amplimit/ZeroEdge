use std::path::Path;
use std::sync::{Arc, Mutex};
use sled::{Db, Tree};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DatabaseError {
    #[error("Database error: {0}")]
    DbError(#[from] sled::Error),
    
    #[error("Tree not found: {0}")]
    TreeNotFound(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("Deserialization error: {0}")]
    DeserializationError(String),
}

/// 简单的键值数据库
pub struct Database {
    /// sled数据库实例
    db: Arc<Db>,
    
    /// 打开的树
    trees: Arc<Mutex<std::collections::HashMap<String, Tree>>>,
}

impl Database {
    /// 创建新的数据库实例
    pub fn new(path: impl AsRef<Path>) -> Result<Self, DatabaseError> {
        // 打开数据库
        let db = sled::open(path)?;
        
        Ok(Self {
            db: Arc::new(db),
            trees: Arc::new(Mutex::new(std::collections::HashMap::new())),
        })
    }
    
    /// 获取树
    pub fn get_tree(&self, name: &str) -> Result<Tree, DatabaseError> {
        // 检查已打开的树
        {
            let trees = self.trees.lock().unwrap();
            if let Some(tree) = trees.get(name) {
                return Ok(tree.clone());
            }
        }
        
        // 打开树
        let tree = self.db.open_tree(name)?;
        
        // 缓存树
        {
            let mut trees = self.trees.lock().unwrap();
            trees.insert(name.to_string(), tree.clone());
        }
        
        Ok(tree)
    }
    
    /// 获取值
    pub fn get(&self, tree: &str, key: &[u8]) -> Result<Option<Vec<u8>>, DatabaseError> {
        let tree = self.get_tree(tree)?;
        
        match tree.get(key)? {
            Some(value) => Ok(Some(value.to_vec())),
            None => Ok(None),
        }
    }
    
    /// 设置值
    pub fn put(&self, tree: &str, key: &[u8], value: &[u8]) -> Result<(), DatabaseError> {
        let tree = self.get_tree(tree)?;
        tree.insert(key, value)?;
        Ok(())
    }
    
    /// 删除值
    pub fn delete(&self, tree: &str, key: &[u8]) -> Result<(), DatabaseError> {
        let tree = self.get_tree(tree)?;
        tree.remove(key)?;
        Ok(())
    }
    
    /// 获取前缀迭代器
    pub fn scan_prefix(&self, tree: &str, prefix: &[u8]) -> Result<impl Iterator<Item = (Vec<u8>, Vec<u8>)>, DatabaseError> {
        let tree = self.get_tree(tree)?;
        
        let iter = tree.scan_prefix(prefix)
            .map(|res| {
                match res {
                    Ok((key, value)) => (key.to_vec(), value.to_vec()),
                    Err(_) => (Vec::new(), Vec::new()), // 忽略错误
                }
            })
            .filter(|(key, _)| !key.is_empty()); // 过滤掉错误结果
        
        Ok(iter)
    }
    
    /// 关闭数据库
    pub fn close(&self) -> Result<(), DatabaseError> {
        // 清空树缓存
        {
            let mut trees = self.trees.lock().unwrap();
            trees.clear();
        }
        
        // 刷新数据库
        self.db.flush()?;
        
        Ok(())
    }
    
    /// 获取序列化的值
    pub fn get_serialized<T: serde::de::DeserializeOwned>(&self, tree: &str, key: &[u8]) -> Result<Option<T>, DatabaseError> {
        match self.get(tree, key)? {
            Some(value) => {
                // 反序列化
                bincode::deserialize(&value)
                    .map_err(|e| DatabaseError::DeserializationError(e.to_string()))
                    .map(Some)
            },
            None => Ok(None),
        }
    }
    
    /// 设置序列化的值
    pub fn put_serialized<T: serde::Serialize>(&self, tree: &str, key: &[u8], value: &T) -> Result<(), DatabaseError> {
        // 序列化
        let data = bincode::serialize(value)
            .map_err(|e| DatabaseError::SerializationError(e.to_string()))?;
        
        // 存储
        self.put(tree, key, &data)
    }
}

impl Clone for Database {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
            trees: self.trees.clone(),
        }
    }
}
