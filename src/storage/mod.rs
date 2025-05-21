mod database;
mod file_storage;
mod message_store;
mod identity_store;

pub use database::{Database, DatabaseError};
pub use file_storage::{FileStorage, FileStorageError};
pub use message_store::{MessageStore, MessageStoreError};
pub use identity_store::{IdentityStore, IdentityStoreError};

/// 存储管理器
pub struct StorageManager {
    /// 数据库
    database: Database,
    
    /// 文件存储
    file_storage: FileStorage,
    
    /// 消息存储
    message_store: MessageStore,
    
    /// 身份存储
    identity_store: IdentityStore,
}

impl StorageManager {
    /// 创建新的存储管理器
    pub fn new(data_dir: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        // 确保目录存在
        std::fs::create_dir_all(data_dir)?;
        
        // 创建数据库
        let database = Database::new(data_dir.join("database"))?;
        
        // 创建文件存储
        let file_storage = FileStorage::new(data_dir.join("files"))?;
        
        // 创建消息存储
        let message_store = MessageStore::new(&database)?;
        
        // 创建身份存储
        let identity_store = IdentityStore::new(&database)?;
        
        Ok(Self {
            database,
            file_storage,
            message_store,
            identity_store,
        })
    }
    
    /// 获取数据库
    pub fn database(&self) -> &Database {
        &self.database
    }
    
    /// 获取文件存储
    pub fn file_storage(&self) -> &FileStorage {
        &self.file_storage
    }
    
    /// 获取消息存储
    pub fn message_store(&self) -> &MessageStore {
        &self.message_store
    }
    
    /// 获取身份存储
    pub fn identity_store(&self) -> &IdentityStore {
        &self.identity_store
    }
    
    /// 关闭存储
    pub fn close(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.database.close()?;
        Ok(())
    }
}
