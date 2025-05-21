mod connection;
mod peer;
mod protocol;
mod message_pool;

pub use connection::{Connection, ConnectionType, ConnectionState, ConnectionError};
pub use peer::{Peer, PeerInfo, PeerState, PeerError};
pub use protocol::{Protocol, ProtocolMessage, ProtocolError, MessageType};
pub use message_pool::{MessagePool, MessagePoolError};

use crate::dht::NodeInfo;
use crate::nat::NatTraversal;
use std::net::SocketAddr;
use thiserror::Error;
use tokio::sync::{mpsc, RwLock};
use std::sync::Arc;
use std::collections::HashMap;
use std::time::Duration;
use log::{debug, error, info};
// 移除未使用的导入
// use log::warn;

/// 网络错误
#[derive(Error, Debug)]
pub enum NetworkError {
    #[error("Connection error: {0}")]
    ConnectionError(#[from] ConnectionError),
    
    #[error("Peer error: {0}")]
    PeerError(#[from] PeerError),
    
    #[error("Protocol error: {0}")]
    ProtocolError(#[from] ProtocolError),
    
    #[error("Message pool error: {0}")]
    MessagePoolError(#[from] MessagePoolError),
    
    #[error("NAT error: {0}")]
    NatError(#[from] crate::nat::NatError),
    
    #[error("Network initialization error: {0}")]
    InitializationError(String),
    
    #[error("Operation error: {0}")]
    OperationError(String),
    
    #[error("Timeout")]
    Timeout,
}

/// 网络配置
#[derive(Clone, Debug)]
pub struct NetworkConfig {
    /// 本地监听地址
    pub local_address: SocketAddr,
    
    /// 连接超时
    pub connection_timeout: Duration,
    
    /// 最大连接数
    pub max_connections: usize,
    
    /// 最大传输单元
    pub mtu: usize,
    
    /// 保活间隔
    pub keepalive_interval: Duration,
    
    /// 清理间隔
    pub cleanup_interval: Duration,
    
    /// 最大消息大小
    pub max_message_size: usize,
    
    /// 是否允许中继
    pub allow_relay: bool,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            local_address: "0.0.0.0:0".parse().unwrap(),
            connection_timeout: Duration::from_secs(30),
            max_connections: 100,
            mtu: 1400,
            keepalive_interval: Duration::from_secs(30),
            cleanup_interval: Duration::from_secs(60),
            max_message_size: 1024 * 1024, // 1 MB
            allow_relay: true,
        }
    }
}

/// 网络操作类型
enum NetworkOperation {
    /// 连接到对等点
    Connect {
        peer_info: PeerInfo,
        response_tx: mpsc::Sender<Result<Peer, NetworkError>>,
    },
    
    /// 发送消息
    SendMessage {
        peer_id: String,
        data: Vec<u8>,
        response_tx: mpsc::Sender<Result<(), NetworkError>>,
    },
    
    /// 关闭连接
    Disconnect {
        peer_id: String,
        response_tx: mpsc::Sender<Result<(), NetworkError>>,
    },
    
    /// 关闭网络
    Shutdown {
        response_tx: mpsc::Sender<Result<(), NetworkError>>,
    },
}

/// 网络管理器
pub struct NetworkManager {
    /// 配置
    config: NetworkConfig,
    
    /// NAT穿透管理器
    nat_traversal: Arc<NatTraversal>,
    
    /// 对等点映射
    peers: Arc<RwLock<HashMap<String, Peer>>>,
    
    /// 操作通道
    op_tx: mpsc::Sender<NetworkOperation>,
    
    /// 运行中标志
    running: Arc<RwLock<bool>>,
    
    /// 消息池
    message_pool: Arc<MessagePool>,
}

impl NetworkManager {
    /// 创建新的网络管理器
    pub async fn new(config: NetworkConfig, stun_servers: Vec<String>) -> Result<Self, NetworkError> {
        // 创建NAT穿透管理器
        let nat_traversal = Arc::new(NatTraversal::new(config.local_address, stun_servers));
        
        // 创建对等点映射
        let peers = Arc::new(RwLock::new(HashMap::new()));
        
        // 创建消息池
        let message_pool = Arc::new(MessagePool::new(config.max_message_size));
        
        // 创建操作通道
        let (op_tx, op_rx) = mpsc::channel(100);
        
        // 标记为未运行
        let running = Arc::new(RwLock::new(false));
        
        // 创建网络管理器
        let manager = Self {
            config,
            nat_traversal,
            peers,
            op_tx,
            running,
            message_pool,
        };
        
        // 启动后台任务
        manager.spawn_background_task(op_rx).await;
        
        Ok(manager)
    }
    
    /// 启动网络
    pub async fn start(&self) -> Result<(), NetworkError> {
        // 发现NAT映射
        let mut nat = self.nat_traversal.as_ref().clone();
        let nat_mapping = nat.discover_mapping().await?;
        
        info!("Network started with NAT mapping: {:?}", nat_mapping);
        
        // 标记为运行中
        let mut running = self.running.write().await;
        *running = true;
        
        Ok(())
    }
    
    /// 停止网络
    pub async fn stop(&self) -> Result<(), NetworkError> {
        let (tx, mut rx) = mpsc::channel(1);
        
        // 发送关闭操作
        self.op_tx.send(NetworkOperation::Shutdown {
            response_tx: tx,
        }).await.map_err(|e| NetworkError::OperationError(e.to_string()))?;
        
        // 等待响应
        rx.recv().await.ok_or_else(|| NetworkError::OperationError("Failed to receive shutdown response".to_string()))?
    }
    
    /// 启动后台任务
    async fn spawn_background_task(&self, mut op_rx: mpsc::Receiver<NetworkOperation>) {
        let peers = self.peers.clone();
        let config = self.config.clone();
        let nat_traversal = self.nat_traversal.clone();
        let running = self.running.clone();
        let message_pool = self.message_pool.clone();
        
        tokio::spawn(async move {
            info!("Network background task started");
            
            // 创建清理计时器
            let mut cleanup_interval = tokio::time::interval(config.cleanup_interval);
            
            loop {
                tokio::select! {
                    // 处理操作
                    Some(op) = op_rx.recv() => {
                        if !*running.read().await {
                            continue;
                        }
                        
                        match op {
                            NetworkOperation::Connect { peer_info, response_tx } => {
                                // 连接到对等点
                                let result = Self::handle_connect(
                                    &peers,
                                    &nat_traversal,
                                    peer_info,
                                    &config,
                                ).await;
                                
                                // 发送响应
                                let _ = response_tx.send(result).await;
                            },
                            NetworkOperation::SendMessage { peer_id, data, response_tx } => {
                                // 发送消息
                                let result = Self::handle_send_message(
                                    &peers,
                                    &peer_id,
                                    data,
                                    &message_pool,
                                ).await;
                                
                                // 发送响应
                                let _ = response_tx.send(result).await;
                            },
                            NetworkOperation::Disconnect { peer_id, response_tx } => {
                                // 断开连接
                                let result = Self::handle_disconnect(&peers, &peer_id).await;
                                
                                // 发送响应
                                let _ = response_tx.send(result).await;
                            },
                            NetworkOperation::Shutdown { response_tx } => {
                                // 关闭所有连接
                                let mut peers_map = peers.write().await;
                                for (_, peer) in peers_map.drain() {
                                    let _ = peer.disconnect().await;
                                }
                                
                                // 标记为不再运行
                                let mut running_guard = running.write().await;
                                *running_guard = false;
                                
                                // 发送响应
                                let _ = response_tx.send(Ok(())).await;
                                
                                // 退出循环
                                break;
                            }
                        }
                    },
                    // 清理计时器触发
                    _ = cleanup_interval.tick() => {
                        if !*running.read().await {
                            continue;
                        }
                        
                        // 清理过期连接
                        Self::cleanup_connections(&peers).await;
                    }
                }
            }
            
            info!("Network background task stopped");
        });
    }
    
    /// 处理连接请求
    async fn handle_connect(
        peers: &Arc<RwLock<HashMap<String, Peer>>>,
        nat_traversal: &Arc<NatTraversal>,
        peer_info: PeerInfo,
        config: &NetworkConfig,
    ) -> Result<Peer, NetworkError> {
        // 检查是否已经连接
        {
            let peers_map = peers.read().await;
            if let Some(peer) = peers_map.get(&peer_info.id) {
                return Ok(peer.clone());
            }
        }
        
        // 创建NodeInfo
        let node_info = NodeInfo {
            id: crate::dht::NodeId([0u8; 32]), // 临时ID
            public_key: peer_info.public_key.clone(),
            addresses: peer_info.addresses.clone(),
            last_updated: std::time::SystemTime::now(),
            protocol_version: 1,
            is_relay: false,
            signature: Vec::new(), // 不需要签名
        };
        
        // 尝试连接
        let connection = nat_traversal.connect_to_peer(&node_info).await?;
        
        // 创建对等点
        let peer = Peer::new(
            peer_info.clone(),
            Connection::new(
                connection,
                ConnectionType::Direct,
                config.mtu,
                config.keepalive_interval,
            ),
        ).await?;
        
        // 添加到映射
        {
            let mut peers_map = peers.write().await;
            peers_map.insert(peer_info.id.clone(), peer.clone());
        }
        
        Ok(peer)
    }
    
    /// 处理发送消息请求
    async fn handle_send_message(
        peers: &Arc<RwLock<HashMap<String, Peer>>>,
        peer_id: &str,
        data: Vec<u8>,
        message_pool: &Arc<MessagePool>,
    ) -> Result<(), NetworkError> {
        // 查找对等点
        let peer = {
            let peers_map = peers.read().await;
            peers_map.get(peer_id).cloned()
        };
        
        match peer {
            Some(peer) => {
                // 发送消息
                if data.len() <= peer.get_mtu().await {
                    // 消息小于MTU，直接发送
                    peer.send(&data).await?;
                } else {
                    // 消息大于MTU，使用消息池
                    message_pool.send_large_message(&peer, &data).await?;
                }
                
                Ok(())
            },
            None => Err(NetworkError::OperationError(format!("Peer not found: {}", peer_id))),
        }
    }
    
    /// 处理断开连接请求
    async fn handle_disconnect(
        peers: &Arc<RwLock<HashMap<String, Peer>>>,
        peer_id: &str,
    ) -> Result<(), NetworkError> {
        // 移除对等点
        let peer = {
            let mut peers_map = peers.write().await;
            peers_map.remove(peer_id)
        };
        
        match peer {
            Some(peer) => {
                // 断开连接
                peer.disconnect().await?;
                Ok(())
            },
            None => Err(NetworkError::OperationError(format!("Peer not found: {}", peer_id))),
        }
    }
    
    /// 清理过期连接
    async fn cleanup_connections(peers: &Arc<RwLock<HashMap<String, Peer>>>) {
        let expired_peers = {
            let peers_map = peers.read().await;
            let mut expired = Vec::new();
            
            for (id, peer) in peers_map.iter() {
                if peer.is_expired().await {
                    expired.push(id.clone());
                }
            }
            
            expired
        };
        
        if !expired_peers.is_empty() {
            let mut peers_map = peers.write().await;
            
            for id in expired_peers {
                if let Some(peer) = peers_map.remove(&id) {
                    let _ = peer.disconnect().await;
                    debug!("Removed expired peer: {}", id);
                }
            }
        }
    }
    
    /// 连接到对等点
    pub async fn connect_to_peer(&self, peer_info: PeerInfo) -> Result<Peer, NetworkError> {
        let (tx, mut rx) = mpsc::channel(1);
        
        // 发送连接操作
        self.op_tx.send(NetworkOperation::Connect {
            peer_info,
            response_tx: tx,
        }).await.map_err(|e| NetworkError::OperationError(e.to_string()))?;
        
        // 等待响应
        rx.recv().await.ok_or_else(|| NetworkError::OperationError("Failed to receive connect response".to_string()))?
    }
    
    /// 发送消息到对等点
    pub async fn send_to_peer(&self, peer_id: &str, data: &[u8]) -> Result<(), NetworkError> {
        let (tx, mut rx) = mpsc::channel(1);
        
        // 发送消息操作
        self.op_tx.send(NetworkOperation::SendMessage {
            peer_id: peer_id.to_string(),
            data: data.to_vec(),
            response_tx: tx,
        }).await.map_err(|e| NetworkError::OperationError(e.to_string()))?;
        
        // 等待响应
        rx.recv().await.ok_or_else(|| NetworkError::OperationError("Failed to receive send response".to_string()))?
    }
    
    /// 断开与对等点的连接
    pub async fn disconnect_peer(&self, peer_id: &str) -> Result<(), NetworkError> {
        let (tx, mut rx) = mpsc::channel(1);
        
        // 发送断开连接操作
        self.op_tx.send(NetworkOperation::Disconnect {
            peer_id: peer_id.to_string(),
            response_tx: tx,
        }).await.map_err(|e| NetworkError::OperationError(e.to_string()))?;
        
        // 等待响应
        rx.recv().await.ok_or_else(|| NetworkError::OperationError("Failed to receive disconnect response".to_string()))?
    }
    
    /// 获取已连接的对等点
    pub async fn get_connected_peers(&self) -> Vec<Peer> {
        let peers_map = self.peers.read().await;
        peers_map.values().cloned().collect()
    }
    
    /// 获取对等点数量
    pub async fn peer_count(&self) -> usize {
        let peers_map = self.peers.read().await;
        peers_map.len()
    }
}
