use crate::crypto::PublicKey;
use libp2p::kad::record::Key;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::fmt;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum KademliaError {
    #[error("Node ID derivation failed: {0}")]
    NodeIdDerivationFailed(String),
    
    #[error("Invalid node info: {0}")]
    InvalidNodeInfo(String),
    
    #[error("DHT operation failed: {0}")]
    OperationFailed(String),
}

/// Configuration for the Kademlia DHT
#[derive(Debug, Clone)]
pub struct KademliaConfig {
    /// The number of nodes to keep in each k-bucket
    pub k_value: usize,
    /// The number of nodes to query in parallel during lookups
    pub alpha_value: usize,
    /// The interval for refreshing buckets
    pub refresh_interval: Duration,
    /// The interval for republishing keys
    pub republish_interval: Duration,
    /// The time after which a key should be republished
    pub record_ttl: Duration,
    /// The number of nodes to replicate a record to
    pub replication_factor: usize,
}

impl Default for KademliaConfig {
    fn default() -> Self {
        Self {
            k_value: 20,
            alpha_value: 3,
            refresh_interval: Duration::from_secs(3600), // 1 hour
            republish_interval: Duration::from_secs(21600), // 6 hours
            record_ttl: Duration::from_secs(86400), // 24 hours
            replication_factor: 5,
        }
    }
}

/// Represents a node's identifier in the DHT
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct NodeId(pub [u8; 32]);

impl NodeId {
    /// Generates a NodeId from a public key
    pub fn from_public_key(key: &PublicKey) -> Result<Self, KademliaError> {
        // Use the SHA-256 hash of the public key as the node ID
        let key_bytes = key.to_bytes()
            .map_err(|e| KademliaError::NodeIdDerivationFailed(e.to_string()))?;
        
        let mut hasher = ring::digest::Context::new(&ring::digest::SHA256);
        hasher.update(&key_bytes);
        let digest = hasher.finish();
        
        let mut id = [0u8; 32];
        id.copy_from_slice(digest.as_ref());
        
        Ok(Self(id))
    }
    
    /// Generates a random NodeId
    pub fn random() -> Self {
        let mut id = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut id);
        Self(id)
    }
    
    /// Calculates the XOR distance between two NodeIds
    pub fn distance(&self, other: &Self) -> [u8; 32] {
        let mut result = [0u8; 32];
        
        for i in 0..32 {
            result[i] = self.0[i] ^ other.0[i];
        }
        
        result
    }
    
    /// Converts the NodeId to a Kademlia Key
    pub fn to_kademlia_key(&self) -> Key {
        Key::from(self.0.to_vec())
    }
}

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeId({})", hex::encode(&self.0[..6]))
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

impl TryFrom<&[u8]> for NodeId {
    type Error = KademliaError;
    
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != 32 {
            return Err(KademliaError::NodeIdDerivationFailed(
                format!("Invalid length: expected 32, got {}", bytes.len())
            ));
        }
        
        let mut id = [0u8; 32];
        id.copy_from_slice(bytes);
        
        Ok(Self(id))
    }
}

/// Represents information about a node in the network
#[derive(Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    /// The node's ID
    pub id: NodeId,
    /// The node's public key
    pub public_key: PublicKey,
    /// The node's network addresses
    pub addresses: Vec<SocketAddr>,
    /// The time when this information was last updated
    pub last_updated: SystemTime,
    /// The node's protocol version
    pub protocol_version: u16,
    /// Whether the node is a relay
    pub is_relay: bool,
    /// The signature of this node info, signed by the node
    pub signature: Vec<u8>,
}

impl NodeInfo {
    /// Creates a new NodeInfo
    pub fn new(
        id: NodeId, 
        public_key: PublicKey, 
        addresses: Vec<SocketAddr>, 
        protocol_version: u16,
        is_relay: bool
    ) -> Self {
        Self {
            id,
            public_key,
            addresses,
            last_updated: SystemTime::now(),
            protocol_version,
            is_relay,
            signature: Vec::new(), // Will be set by sign method
        }
    }
    
    /// Creates a new NodeInfo and signs it
    pub fn new_signed(
        id: NodeId, 
        public_key: PublicKey, 
        addresses: Vec<SocketAddr>, 
        protocol_version: u16,
        is_relay: bool,
        secret_key: &crate::crypto::SecretKey,
    ) -> Result<Self, KademliaError> {
        let mut node_info = Self::new(id, public_key, addresses, protocol_version, is_relay);
        
        // 使用提供的密钥签名
        node_info.sign(secret_key)?;
        
        Ok(node_info)
    }
    
    /// Signs the node info with the given secret key
    pub fn sign(&mut self, secret_key: &crate::crypto::SecretKey) -> Result<(), KademliaError> {
        // Create a copy without the signature field
        let mut info_copy = self.clone();
        info_copy.signature = Vec::new();
        
        // Serialize the info
        let info_bytes = bincode::serialize(&info_copy)
            .map_err(|e| KademliaError::InvalidNodeInfo(e.to_string()))?;
        
        // Sign the info
        let signature = crate::crypto::sign(secret_key, &info_bytes)
            .map_err(|e| KademliaError::InvalidNodeInfo(e.to_string()))?;
        
        // Set the signature
        self.signature = signature;
        
        Ok(())
    }
    
    /// Verifies the signature on the node info
    pub fn verify(&self) -> Result<(), KademliaError> {
        // Create a copy without the signature field
        let mut info_copy = self.clone();
        info_copy.signature = Vec::new();
        
        // Serialize the info
        let info_bytes = bincode::serialize(&info_copy)
            .map_err(|e| KademliaError::InvalidNodeInfo(e.to_string()))?;
        
        // Verify the signature
        crate::crypto::verify(&self.public_key, &info_bytes, &self.signature)
            .map_err(|e| KademliaError::InvalidNodeInfo(e.to_string()))?;
        
        Ok(())
    }
    
    /// Checks if the node info is expired
    pub fn is_expired(&self, ttl: Duration) -> bool {
        match SystemTime::now().duration_since(self.last_updated) {
            Ok(age) => age > ttl,
            Err(_) => false, // Clock went backwards, consider not expired
        }
    }
}

impl fmt::Debug for NodeInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeInfo")
            .field("id", &self.id)
            .field("public_key", &self.public_key)
            .field("addresses", &self.addresses)
            .field("last_updated", &self.last_updated)
            .field("protocol_version", &self.protocol_version)
            .field("is_relay", &self.is_relay)
            .field("signature", &format!("[{} bytes]", self.signature.len()))
            .finish()
    }
}

/// Implementation of the Kademlia DHT node
pub struct KademliaNode {
    /// 节点配置
    config: KademliaConfig,
    
    /// 本地节点信息
    local_node: NodeInfo,
    
    /// 路由表
    routing_table: crate::dht::RoutingTable,
    
    /// 网络传输层
    network: Option<crate::dht::DhtNetwork>,
    
    /// 消息处理器
    message_rx: Option<tokio::sync::mpsc::Receiver<crate::dht::MessageRoute>>,
    
    /// 运行状态
    running: std::sync::Arc<std::sync::RwLock<bool>>,
    
    /// 引导节点列表
    bootstrap_nodes: Vec<NodeInfo>,
}

impl KademliaNode {
    /// Creates a new KademliaNode with the given configuration
    pub fn new(config: KademliaConfig, local_node: NodeInfo) -> Self {
        let routing_table = crate::dht::RoutingTable::new(
            local_node.id.clone(),
            config.record_ttl,
        );
        
        Self {
            config,
            local_node,
            routing_table,
            network: None,
            message_rx: None,
            running: std::sync::Arc::new(std::sync::RwLock::new(false)),
            bootstrap_nodes: Vec::new(),
        }
    }
    
    /// 设置引导节点
    pub fn set_bootstrap_nodes(&mut self, bootstrap_nodes: Vec<NodeInfo>) {
        self.bootstrap_nodes = bootstrap_nodes;
    }
    
    /// Starts the Kademlia node
    pub async fn start(&mut self) -> Result<(), KademliaError> {
        use log::info;
        
        // 创建网络层
        let bind_addr = self.local_node.addresses.first()
            .ok_or_else(|| KademliaError::OperationFailed("No local address configured".to_string()))?
            .clone();
        
        let (network, message_rx) = crate::dht::DhtNetwork::new(bind_addr).await?;
        
        // 启动网络
        network.start().await?;
        
        // 更新本地节点地址为实际绑定的地址
        self.local_node.addresses = vec![network.local_addr()];
        
        self.network = Some(network);
        self.message_rx = Some(message_rx);
        
        // 设置运行状态
        {
            let mut running = self.running.write().unwrap();
            *running = true;
        }
        
        // 启动消息处理任务
        self.spawn_message_handler();
        
        info!("Kademlia node started on {}", self.local_node.addresses[0]);
        
        Ok(())
    }
    
    /// Stops the Kademlia node
    pub async fn stop(&mut self) -> Result<(), KademliaError> {
        use log::info;
        
        // 设置停止状态
        {
            let mut running = self.running.write().unwrap();
            *running = false;
        }
        
        // 停止网络
        if let Some(network) = &self.network {
            network.stop().await?;
        }
        
        self.network = None;
        self.message_rx = None;
        
        info!("Kademlia node stopped");
        
        Ok(())
    }
    
    /// Bootstraps the node by connecting to the given bootstrap nodes
    pub async fn bootstrap(&mut self, bootstrap_nodes: Vec<NodeInfo>) -> Result<(), KademliaError> {
        use log::{info, warn, debug};
        
        if bootstrap_nodes.is_empty() && self.bootstrap_nodes.is_empty() {
            info!("No bootstrap nodes provided, node will wait for incoming connections");
            return Ok(());
        }
        
        let nodes_to_bootstrap = if bootstrap_nodes.is_empty() {
            &self.bootstrap_nodes
        } else {
            &bootstrap_nodes
        };
        
        info!("Bootstrapping with {} nodes", nodes_to_bootstrap.len());
        
        let network = self.network.as_ref()
            .ok_or_else(|| KademliaError::OperationFailed("Network not started".to_string()))?;
        
        // 尝试连接到引导节点
        let mut successful_connections = 0;
        
        for bootstrap_node in nodes_to_bootstrap {
            if bootstrap_node.id == self.local_node.id {
                continue; // 跳过自己
            }
            
            // Ping引导节点
            let ping_message = crate::dht::DhtMessage::Ping {
                sender: self.local_node.clone(),
                message_id: 0, // 临时ID，网络层会生成实际ID
            };
            
            for addr in &bootstrap_node.addresses {
                match network.send_request(
                    *addr,
                    ping_message.clone(),
                    std::time::Duration::from_secs(5)
                ).await {
                    Ok(crate::dht::DhtMessage::Pong { sender, .. }) => {
                        // 添加到路由表
                        if let Err(e) = self.routing_table.update_node(sender) {
                            warn!("Failed to add bootstrap node to routing table: {}", e);
                        } else {
                            successful_connections += 1;
                            debug!("Successfully connected to bootstrap node: {}", bootstrap_node.id);
                            break; // 成功连接，尝试下一个节点
                        }
                    },
                    Ok(_) => {
                        warn!("Unexpected response from bootstrap node {}", addr);
                    },
                    Err(e) => {
                        debug!("Failed to ping bootstrap node {}: {}", addr, e);
                    }
                }
            }
        }
        
        if successful_connections > 0 {
            info!("Successfully connected to {} bootstrap nodes", successful_connections);
            
            // 查找自己的ID以填充路由表
            let _ = self.find_node(&self.local_node.id).await;
        } else {
            warn!("Failed to connect to any bootstrap nodes");
        }
        
        Ok(())
    }
    
    /// 查找节点
    pub async fn find_node(&self, target: &NodeId) -> Result<Vec<NodeInfo>, KademliaError> {
        use log::{debug, warn};
        use std::collections::HashSet;
        
        let network = self.network.as_ref()
            .ok_or_else(|| KademliaError::OperationFailed("Network not started".to_string()))?;
        
        debug!("Starting node lookup for {}", target);
        
        // 从路由表获取最近的节点作为起点
        let initial_nodes = self.routing_table.get_closest(target, self.config.k_value);
        
        if initial_nodes.is_empty() {
            debug!("No nodes in routing table for lookup");
            return Ok(Vec::new());
        }
        
        let mut candidates = initial_nodes;
        let mut queried: HashSet<NodeId> = HashSet::new();
        let mut closest_nodes = Vec::new();
        
        // 迭代查找过程
        for _iteration in 0..10 { // 最多10次迭代
            // 选择alpha个最近且未查询的节点
            let mut to_query = Vec::new();
            for node in &candidates {
                if !queried.contains(&node.id) && to_query.len() < self.config.alpha_value {
                    to_query.push(node.clone());
                    queried.insert(node.id.clone());
                }
            }
            
            if to_query.is_empty() {
                break;
            }
            
            debug!("Querying {} nodes in this iteration", to_query.len());
            
            // 并行查询选中的节点
            let mut tasks = Vec::new();
            
            for node in to_query {
                let network_clone = network.clone();
                let local_node = self.local_node.clone();
                let target_clone = target.clone();
                
                let task = tokio::spawn(async move {
                    let find_request = crate::dht::DhtMessage::FindNodeRequest {
                        sender: local_node,
                        target: target_clone,
                        message_id: 0,
                    };
                    
                    for addr in &node.addresses {
                        match network_clone.send_request(
                            *addr,
                            find_request.clone(),
                            std::time::Duration::from_secs(5)
                        ).await {
                            Ok(crate::dht::DhtMessage::FindNodeResponse { nodes, .. }) => {
                                return Ok(nodes);
                            },
                            Ok(_) => {
                                warn!("Unexpected response from node {}", addr);
                            },
                            Err(e) => {
                                debug!("Failed to query node {}: {}", addr, e);
                            }
                        }
                    }
                    Err(KademliaError::OperationFailed("No response from node".to_string()))
                });
                
                tasks.push(task);
            }
            
            // 等待所有查询完成
            let mut new_nodes = Vec::new();
            for task in tasks {
                if let Ok(Ok(nodes)) = task.await {
                    new_nodes.extend(nodes);
                }
            }
            
            // 更新候选列表
            candidates.extend(new_nodes);
            
            // 按距离排序并保留最近的k个节点
            candidates.sort_by(|a, b| {
                let dist_a = a.id.distance(target);
                let dist_b = b.id.distance(target);
                dist_a.cmp(&dist_b)
            });
            candidates.truncate(self.config.k_value);
            
            // 检查是否找到了目标节点
            if let Some(exact_match) = candidates.iter().find(|n| n.id == *target) {
                debug!("Found exact match for target {}", target);
                return Ok(vec![exact_match.clone()]);
            }
            
            // 更新最近节点列表
            closest_nodes = candidates.clone();
        }
        
        debug!("Node lookup completed, found {} nodes", closest_nodes.len());
        Ok(closest_nodes)
    }
    
    /// 获取本地节点信息
    pub fn local_node(&self) -> &NodeInfo {
        &self.local_node
    }
    
    /// 获取路由表大小
    pub fn routing_table_size(&self) -> usize {
        self.routing_table.len()
    }
    
    /// 启动消息处理任务
    fn spawn_message_handler(&mut self) {
        if let Some(mut message_rx) = self.message_rx.take() {
            let local_node = self.local_node.clone();
            let running = self.running.clone();
            let network = self.network.as_ref().unwrap().clone();
            
            tokio::spawn(async move {
                use log::{debug, warn};
                
                while *running.read().unwrap() {
                    if let Some(route) = message_rx.recv().await {
                        debug!("Received message from {}", route.from);
                        
                        match route.message {
                            crate::dht::DhtMessage::Ping { sender, message_id } => {
                                // 响应Ping
                                let pong = crate::dht::DhtMessage::Pong {
                                    sender: local_node.clone(),
                                    message_id,
                                };
                                
                                if let Err(e) = network.send_response(route.from, pong).await {
                                    warn!("Failed to send pong response: {}", e);
                                }
                                
                                // 将发送者添加到路由表（在实际实现中）
                                debug!("Received ping from {}", sender.id);
                            },
                            
                            crate::dht::DhtMessage::FindNodeRequest { sender, target, message_id } => {
                                // 处理查找节点请求
                                debug!("Received find_node request for {} from {}", target, sender.id);
                                
                                // 在实际实现中，这里会查询路由表并返回最近的节点
                                let response = crate::dht::DhtMessage::FindNodeResponse {
                                    sender: local_node.clone(),
                                    nodes: Vec::new(), // 简化实现
                                    message_id,
                                };
                                
                                if let Err(e) = network.send_response(route.from, response).await {
                                    warn!("Failed to send find_node response: {}", e);
                                }
                            },
                            
                            _ => {
                                debug!("Received unhandled message type");
                            }
                        }
                    }
                }
                
                debug!("Message handler task stopped");
            });
        }
    }
}
