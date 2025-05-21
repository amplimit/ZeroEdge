use serde::{Deserialize, Serialize};
use std::fs::{File, create_dir_all};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Parse error: {0}")]
    ParseError(#[from] serde_json::Error),
    
    #[error("Path error: {0}")]
    PathError(String),
}

/// 应用程序配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// 节点ID
    pub node_id: Option<String>,
    
    /// 节点名称
    pub node_name: String,
    
    /// 身份密钥路径
    pub identity_path: PathBuf,
    
    /// 监听地址
    pub listen_addr: String,
    
    /// DHT引导节点
    pub bootstrap_nodes: Vec<String>,
    
    /// STUN服务器
    pub stun_servers: Vec<String>,
    
    /// 日志级别
    pub log_level: String,
    
    /// 数据目录
    pub data_dir: PathBuf,
    
    /// 最大存储空间（MB）
    pub max_storage_mb: u64,
    
    /// 是否允许中继
    pub allow_relay: bool,
    
    /// 是否自动接受连接
    pub auto_accept_connections: bool,
    
    /// 是否加入DHT
    pub join_dht: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            node_id: None,
            node_name: "ZeroEdge Node".to_string(),
            identity_path: PathBuf::from("identity.json"),
            listen_addr: "0.0.0.0:0".to_string(),
            bootstrap_nodes: vec![],
            stun_servers: vec![
                "stun.l.google.com:19302".to_string(),
                "stun1.l.google.com:19302".to_string(),
                "stun2.l.google.com:19302".to_string(),
            ],
            log_level: "info".to_string(),
            data_dir: PathBuf::from("data"),
            max_storage_mb: 1024, // 1 GB
            allow_relay: true,
            auto_accept_connections: false,
            join_dht: true,
        }
    }
}

impl Config {
    /// 从文件加载配置
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        // 检查文件是否存在
        if !path.exists() {
            return Ok(Self::default());
        }
        
        // 打开文件
        let mut file = File::open(path)?;
        
        // 读取文件内容
        let mut content = String::new();
        file.read_to_string(&mut content)?;
        
        // 解析JSON
        let config = serde_json::from_str(&content)?;
        
        Ok(config)
    }
    
    /// 保存配置到文件
    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        // 确保目录存在
        if let Some(parent) = path.parent() {
            create_dir_all(parent)?;
        }
        
        // 序列化为JSON
        let content = serde_json::to_string_pretty(self)?;
        
        // 创建文件
        let mut file = File::create(path)?;
        
        // 写入内容
        file.write_all(content.as_bytes())?;
        
        Ok(())
    }
    
    /// 确保数据目录存在
    pub fn ensure_data_dir(&self) -> Result<(), ConfigError> {
        create_dir_all(&self.data_dir)?;
        Ok(())
    }
    
    /// 获取身份文件路径
    pub fn identity_file_path(&self) -> Result<PathBuf, ConfigError> {
        if self.identity_path.is_absolute() {
            Ok(self.identity_path.clone())
        } else {
            Ok(self.data_dir.join(&self.identity_path))
        }
    }
}
