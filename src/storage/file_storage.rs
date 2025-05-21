use std::path::{Path, PathBuf};
use std::fs::{self, File, create_dir_all};
use std::io::{Read, Write};
use thiserror::Error;
use log::error;
// 移除未使用的导入
// use log::{debug, info, warn};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use serde::{Serialize, Deserialize};

#[derive(Error, Debug)]
pub enum FileStorageError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("File not found: {0}")]
    FileNotFound(String),
    
    #[error("Invalid file path: {0}")]
    InvalidPath(String),
    
    #[error("File too large: {0}")]
    FileTooLarge(usize),
    
    #[error("Storage full")]
    StorageFull,
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("Meta storage error: {0}")]
    MetaStorageError(String),
}

/// 文件元数据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    /// 文件ID
    pub id: String,
    
    /// 文件名
    pub name: String,
    
    /// 文件类型
    pub content_type: String,
    
    /// 文件大小
    pub size: usize,
    
    /// 文件哈希
    pub hash: String,
    
    /// 创建时间
    pub created_at: u64,
    
    /// 所有者ID
    pub owner_id: Option<String>,
    
    /// 标签
    pub tags: Vec<String>,
    
    /// 是否是临时文件
    pub is_temporary: bool,
    
    /// 过期时间（如果是临时文件）
    pub expires_at: Option<u64>,
}

/// 文件存储
pub struct FileStorage {
    /// 存储根路径
    root_path: PathBuf,
    
    /// 当前存储使用量
    used_space: Arc<Mutex<u64>>,
    
    /// 最大存储空间
    max_space: u64,
    
    /// 文件元数据缓存
    metadata_cache: Arc<Mutex<HashMap<String, FileMetadata>>>,
}

impl FileStorage {
    /// 创建新的文件存储
    pub fn new(path: impl AsRef<Path>) -> Result<Self, FileStorageError> {
        let root_path = path.as_ref().to_path_buf();
        
        // 确保目录存在
        create_dir_all(&root_path)?;
        
        // 创建子目录
        create_dir_all(root_path.join("files"))?;
        create_dir_all(root_path.join("temp"))?;
        create_dir_all(root_path.join("meta"))?;
        
        // 加载元数据
        let metadata_path = root_path.join("meta").join("files.json");
        let metadata_cache = if metadata_path.exists() {
            let mut file = File::open(&metadata_path)?;
            let mut content = String::new();
            file.read_to_string(&mut content)?;
            
            match serde_json::from_str::<HashMap<String, FileMetadata>>(&content) {
                Ok(metadata) => metadata,
                Err(e) => {
                    error!("Failed to load file metadata: {}", e);
                    HashMap::new()
                }
            }
        } else {
            HashMap::new()
        };
        
        // 计算当前存储使用量
        let mut used_space = 0;
        for metadata in metadata_cache.values() {
            used_space += metadata.size as u64;
        }
        
        let storage = Self {
            root_path,
            used_space: Arc::new(Mutex::new(used_space)),
            max_space: u64::MAX, // 默认无限制
            metadata_cache: Arc::new(Mutex::new(metadata_cache)),
        };
        
        Ok(storage)
    }
    
    /// 设置最大存储空间
    pub fn set_max_space(&mut self, max_space: u64) {
        self.max_space = max_space;
    }
    
    /// 获取已使用的存储空间
    pub fn used_space(&self) -> u64 {
        *self.used_space.lock().unwrap()
    }
    
    /// 获取可用的存储空间
    pub fn available_space(&self) -> u64 {
        self.max_space.saturating_sub(self.used_space())
    }
    
    /// 检查是否有足够的空间
    pub fn has_enough_space(&self, size: usize) -> bool {
        let available = self.available_space();
        size as u64 <= available
    }
    
    /// 保存文件
    pub fn save_file(
        &self,
        data: &[u8],
        name: &str,
        content_type: &str,
        owner_id: Option<&str>,
        tags: Vec<String>,
    ) -> Result<String, FileStorageError> {
        // 检查存储空间
        if !self.has_enough_space(data.len()) {
            return Err(FileStorageError::StorageFull);
        }
        
        // 生成文件ID
        let file_id = crate::utils::random_id();
        
        // 计算文件哈希
        let mut hasher = ring::digest::Context::new(&ring::digest::SHA256);
        hasher.update(data);
        let digest = hasher.finish();
        let hash = hex::encode(digest.as_ref());
        
        // 获取当前时间戳
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        // 创建文件元数据
        let metadata = FileMetadata {
            id: file_id.clone(),
            name: name.to_string(),
            content_type: content_type.to_string(),
            size: data.len(),
            hash,
            created_at: now,
            owner_id: owner_id.map(|s| s.to_string()),
            tags,
            is_temporary: false,
            expires_at: None,
        };
        
        // 确定文件路径
        let file_path = self.get_file_path(&file_id);
        
        // 创建目录
        if let Some(parent) = file_path.parent() {
            create_dir_all(parent)?;
        }
        
        // 写入文件
        let mut file = File::create(&file_path)?;
        file.write_all(data)?;
        
        // 更新元数据缓存
        {
            let mut cache = self.metadata_cache.lock().unwrap();
            cache.insert(file_id.clone(), metadata);
        }
        
        // 更新存储使用量
        {
            let mut used_space = self.used_space.lock().unwrap();
            *used_space += data.len() as u64;
        }
        
        // 保存元数据
        self.save_metadata()?;
        
        Ok(file_id)
    }
    
    /// 保存临时文件
    pub fn save_temp_file(
        &self,
        data: &[u8],
        name: &str,
        content_type: &str,
        ttl: std::time::Duration,
    ) -> Result<String, FileStorageError> {
        // 检查存储空间
        if !self.has_enough_space(data.len()) {
            return Err(FileStorageError::StorageFull);
        }
        
        // 生成文件ID
        let file_id = crate::utils::random_id();
        
        // 计算文件哈希
        let mut hasher = ring::digest::Context::new(&ring::digest::SHA256);
        hasher.update(data);
        let digest = hasher.finish();
        let hash = hex::encode(digest.as_ref());
        
        // 获取当前时间戳
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        // 计算过期时间
        let expires_at = now + ttl.as_secs();
        
        // 创建文件元数据
        let metadata = FileMetadata {
            id: file_id.clone(),
            name: name.to_string(),
            content_type: content_type.to_string(),
            size: data.len(),
            hash,
            created_at: now,
            owner_id: None,
            tags: Vec::new(),
            is_temporary: true,
            expires_at: Some(expires_at),
        };
        
        // 确定文件路径（临时文件存储在temp目录下）
        let file_path = self.get_temp_path(&file_id);
        
        // 创建目录
        if let Some(parent) = file_path.parent() {
            create_dir_all(parent)?;
        }
        
        // 写入文件
        let mut file = File::create(&file_path)?;
        file.write_all(data)?;
        
        // 更新元数据缓存
        {
            let mut cache = self.metadata_cache.lock().unwrap();
            cache.insert(file_id.clone(), metadata);
        }
        
        // 更新存储使用量
        {
            let mut used_space = self.used_space.lock().unwrap();
            *used_space += data.len() as u64;
        }
        
        // 保存元数据
        self.save_metadata()?;
        
        Ok(file_id)
    }
    
    /// 读取文件
    pub fn read_file(&self, file_id: &str) -> Result<Vec<u8>, FileStorageError> {
        // 获取文件元数据
        let metadata = self.get_metadata(file_id)?;
        
        // 确定文件路径
        let file_path = if metadata.is_temporary {
            self.get_temp_path(file_id)
        } else {
            self.get_file_path(file_id)
        };
        
        // 检查文件是否存在
        if !file_path.exists() {
            return Err(FileStorageError::FileNotFound(file_id.to_string()));
        }
        
        // 读取文件
        let mut file = File::open(&file_path)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        
        Ok(data)
    }
    
    /// 删除文件
    pub fn delete_file(&self, file_id: &str) -> Result<(), FileStorageError> {
        // 获取文件元数据
        let metadata = self.get_metadata(file_id)?;
        
        // 确定文件路径
        let file_path = if metadata.is_temporary {
            self.get_temp_path(file_id)
        } else {
            self.get_file_path(file_id)
        };
        
        // 检查文件是否存在
        if !file_path.exists() {
            return Err(FileStorageError::FileNotFound(file_id.to_string()));
        }
        
        // 删除文件
        fs::remove_file(&file_path)?;
        
        // 更新元数据缓存
        {
            let mut cache = self.metadata_cache.lock().unwrap();
            cache.remove(file_id);
        }
        
        // 更新存储使用量
        {
            let mut used_space = self.used_space.lock().unwrap();
            *used_space = used_space.saturating_sub(metadata.size as u64);
        }
        
        // 保存元数据
        self.save_metadata()?;
        
        Ok(())
    }
    
    /// 获取文件元数据
    pub fn get_metadata(&self, file_id: &str) -> Result<FileMetadata, FileStorageError> {
        let cache = self.metadata_cache.lock().unwrap();
        
        match cache.get(file_id) {
            Some(metadata) => Ok(metadata.clone()),
            None => Err(FileStorageError::FileNotFound(file_id.to_string())),
        }
    }
    
    /// 更新文件元数据
    pub fn update_metadata(
        &self,
        file_id: &str,
        name: Option<String>,
        content_type: Option<String>,
        owner_id: Option<String>,
        tags: Option<Vec<String>>,
    ) -> Result<(), FileStorageError> {
        // 更新元数据缓存
        {
            let mut cache = self.metadata_cache.lock().unwrap();
            
            if let Some(metadata) = cache.get_mut(file_id) {
                if let Some(name) = name {
                    metadata.name = name;
                }
                
                if let Some(content_type) = content_type {
                    metadata.content_type = content_type;
                }
                
                if let Some(owner_id) = owner_id {
                    metadata.owner_id = Some(owner_id);
                }
                
                if let Some(tags) = tags {
                    metadata.tags = tags;
                }
            } else {
                return Err(FileStorageError::FileNotFound(file_id.to_string()));
            }
        }
        
        // 保存元数据
        self.save_metadata()?;
        
        Ok(())
    }
    
    /// 列出所有文件
    pub fn list_files(&self) -> Vec<FileMetadata> {
        let cache = self.metadata_cache.lock().unwrap();
        cache.values().cloned().collect()
    }
    
    /// 通过标签查找文件
    pub fn find_by_tag(&self, tag: &str) -> Vec<FileMetadata> {
        let cache = self.metadata_cache.lock().unwrap();
        
        cache.values()
            .filter(|metadata| metadata.tags.contains(&tag.to_string()))
            .cloned()
            .collect()
    }
    
    /// 通过所有者ID查找文件
    pub fn find_by_owner(&self, owner_id: &str) -> Vec<FileMetadata> {
        let cache = self.metadata_cache.lock().unwrap();
        
        cache.values()
            .filter(|metadata| metadata.owner_id.as_ref().map_or(false, |id| id == owner_id))
            .cloned()
            .collect()
    }
    
    /// 清理过期的临时文件
    pub fn cleanup_expired_files(&self) -> Result<usize, FileStorageError> {
        // 获取当前时间戳
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        // 找出过期的文件
        let expired_files = {
            let cache = self.metadata_cache.lock().unwrap();
            
            cache.values()
                .filter(|metadata| {
                    metadata.is_temporary && 
                    metadata.expires_at.map_or(false, |expires| expires < now)
                })
                .map(|metadata| metadata.id.clone())
                .collect::<Vec<_>>()
        };
        
        // 删除过期文件
        for file_id in &expired_files {
            if let Err(e) = self.delete_file(file_id) {
                error!("Failed to delete expired file {}: {}", file_id, e);
            }
        }
        
        Ok(expired_files.len())
    }
    
    /// 保存元数据到文件
    fn save_metadata(&self) -> Result<(), FileStorageError> {
        let metadata_path = self.root_path.join("meta").join("files.json");
        
        // 确保目录存在
        if let Some(parent) = metadata_path.parent() {
            create_dir_all(parent)?;
        }
        
        // 序列化元数据
        let cache = self.metadata_cache.lock().unwrap();
        let metadata_json = serde_json::to_string_pretty(&*cache)
            .map_err(|e| FileStorageError::SerializationError(e.to_string()))?;
        
        // 写入文件
        let mut file = File::create(&metadata_path)?;
        file.write_all(metadata_json.as_bytes())?;
        
        Ok(())
    }
    
    /// 获取文件路径
    fn get_file_path(&self, file_id: &str) -> PathBuf {
        // 使用文件ID的前两个字符作为子目录，以分散文件
        let prefix = &file_id[0..2];
        self.root_path.join("files").join(prefix).join(file_id)
    }
    
    /// 获取临时文件路径
    fn get_temp_path(&self, file_id: &str) -> PathBuf {
        self.root_path.join("temp").join(file_id)
    }
}
