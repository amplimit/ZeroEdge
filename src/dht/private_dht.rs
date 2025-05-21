use crate::crypto::{KeyPair, PublicKey};
use crate::dht::{KademliaConfig, KademliaNode, NodeId};
// 移除未使用的导入
// use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Error, Debug)]
pub enum PrivateDhtError {
    #[error("DHT operation failed: {0}")]
    OperationFailed(String),
    
    #[error("Node not found")]
    NodeNotFound,
    
    #[error("Value not found")]
    ValueNotFound,
    
    #[error("Invalid parameters: {0}")]
    InvalidParameters(String),
    
    #[error("Unauthorized access")]
    Unauthorized,
}

/// 私有DHT配置
#[derive(Clone, Debug)]
pub struct PrivateDhtConfig {
    /// 本地节点ID
    pub local_id: NodeId,
    
    /// 本地公钥
    pub local_public_key: PublicKey,
    
    /// 引导节点
    pub bootstrap_nodes: Vec<(NodeId, SocketAddr)>,
    
    /// 访问控制列表
    pub access_list: Vec<NodeId>,
    
    /// 存储路径
    pub storage_path: Option<String>,
    
    /// 哈希表大小
    pub table_size: usize,
    
    /// 副本数
    pub replication_factor: usize,
}

impl Default for PrivateDhtConfig {
    fn default() -> Self {
        Self {
            local_id: NodeId([0; 32]),
            local_public_key: KeyPair::generate().unwrap().public,
            bootstrap_nodes: Vec::new(),
            access_list: Vec::new(),
            storage_path: None,
            table_size: 20,
            replication_factor: 3,
        }
    }
}

/// 私有DHT实现，用于好友间的加密数据交换
pub struct PrivateDht {
    /// 内部Kademlia节点
    node: Arc<KademliaNode>,
    
    /// 配置
    config: PrivateDhtConfig,
    
    /// 访问控制列表
    access_list: Arc<RwLock<Vec<NodeId>>>,
    
    /// 共享密钥缓存
    shared_keys: Arc<RwLock<HashMap<NodeId, Vec<u8>>>>,
    
    /// 是否运行中
    running: Arc<RwLock<bool>>,
}

impl PrivateDht {
    /// 创建新的私有DHT
    pub fn new(config: PrivateDhtConfig) -> Self {
        // 创建Kademlia配置
        let kademlia_config = KademliaConfig {
            k_value: config.table_size,
            alpha_value: 3, // 默认并行查询节点数
            refresh_interval: Duration::from_secs(3600), // 1小时
            republish_interval: Duration::from_secs(24 * 3600), // 24小时
            record_ttl: Duration::from_secs(48 * 3600), // 48小时
            replication_factor: config.replication_factor,
        };
        
        // 创建Kademlia节点
        let node = Arc::new(KademliaNode::new(kademlia_config));
        
        // 在赋值前先获取需要的值
        let access_list = config.access_list.clone();
        
        // 创建私有DHT
        Self {
            node,
            config,
            access_list: Arc::new(RwLock::new(access_list)),
            shared_keys: Arc::new(RwLock::new(HashMap::new())),
            running: Arc::new(RwLock::new(false)),
        }
    }
    
    /// 启动DHT
    pub async fn start(&self) -> Result<(), PrivateDhtError> {
        // 启动Kademlia节点
        // 此处省略具体实现，因为KademliaNode已经处理了底层网络逻辑
        
        // 标记为运行中
        let mut running = self.running.write().await;
        *running = true;
        
        Ok(())
    }
    
    /// 停止DHT
    pub async fn stop(&self) -> Result<(), PrivateDhtError> {
        // 标记为停止
        let mut running = self.running.write().await;
        *running = false;
        
        Ok(())
    }
    
    /// 添加节点到访问控制列表
    pub async fn add_to_acl(&self, node_id: NodeId) -> Result<(), PrivateDhtError> {
        let mut acl = self.access_list.write().await;
        
        // 检查是否已存在
        if !acl.contains(&node_id) {
            acl.push(node_id);
        }
        
        Ok(())
    }
    
    /// 从访问控制列表移除节点
    pub async fn remove_from_acl(&self, node_id: &NodeId) -> Result<(), PrivateDhtError> {
        let mut acl = self.access_list.write().await;
        
        // 查找并移除
        acl.retain(|id| id != node_id);
        
        Ok(())
    }
    
    /// 检查节点是否在访问控制列表中
    async fn is_authorized(&self, node_id: &NodeId) -> bool {
        let acl = self.access_list.read().await;
        acl.contains(node_id)
    }
    
    /// 存储键值对
    pub async fn store(&self, _key: &[u8], _value: &[u8]) -> Result<(), PrivateDhtError> {
        // 在实际实现中，此处应该加密数据，并且只允许授权节点访问
        // 此处简化为直接调用底层Kademlia存储

        // TODO: 当KademliaNode实现完成后，取消下面的注释
        // self.node.store(key.to_vec(), value.to_vec())
        //     .await
        //     .map_err(|e| PrivateDhtError::OperationFailed(e.to_string()))?;
        
        // 暂时返回成功，待实现完成
        Ok(())
    }
    
    /// 获取键对应的值
    pub async fn get(&self, _key: &[u8]) -> Result<Vec<u8>, PrivateDhtError> {
        // TODO: 当KademliaNode实现完成后，取消下面的注释
        // // 使用底层Kademlia获取数据
        // let value = self.node.get(key.to_vec())
        //     .await
        //     .map_err(|e| PrivateDhtError::OperationFailed(e.to_string()))?
        //     .ok_or(PrivateDhtError::ValueNotFound)?;

        // 在实际实现中，此处应该解密数据
        // 此处简化直接返回
        
        // 暂时返回空数据，待实现完成
        Ok(Vec::new())
    }
    
    /// 查找节点
    pub async fn find_node(&self, node_id: &NodeId) -> Result<SocketAddr, PrivateDhtError> {
        // 检查是否为授权节点
        if !self.is_authorized(node_id).await {
            return Err(PrivateDhtError::Unauthorized);
        }
        
        // TODO: 当KademliaNode实现完成后，取消下面的注释
        // // 使用底层Kademlia查找节点
        // let node_info = self.node.find_node(node_id.clone())
        //     .await
        //     .map_err(|e| PrivateDhtError::OperationFailed(e.to_string()))?
        //     .ok_or(PrivateDhtError::NodeNotFound)?;

        // 暂时返回一个虚拟地址，待实现完成
        Ok("127.0.0.1:8000".parse().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;
    
    #[tokio::test]
    async fn test_acl() {
        // 创建配置
        let keypair = KeyPair::generate().unwrap();
        let node_id = NodeId::from_public_key(&keypair.public).unwrap();
        
        let mut config = PrivateDhtConfig::default();
        config.local_id = node_id;
        config.local_public_key = keypair.public;
        
        // 创建私有DHT
        let dht = PrivateDht::new(config);
        
        // 创建测试节点ID
        let test_id = NodeId([1; 32]);
        
        // 添加到ACL
        dht.add_to_acl(test_id.clone()).await.unwrap();
        
        // 验证是否已授权
        assert!(dht.is_authorized(&test_id).await);
        
        // 从ACL移除
        dht.remove_from_acl(&test_id).await.unwrap();
        
        // 验证是否已被移除
        assert!(!dht.is_authorized(&test_id).await);
    }
}
