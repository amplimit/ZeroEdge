mod stun;
mod hole_punching;
mod relay;

pub use stun::{StunClient, NatMapping, NatType, StunError};
pub use hole_punching::{PunchingStrategy, start_hole_punching};
pub use relay::{RelayConnection, RelayError, RelayConfig, RelayType};
use crate::dht::{NodeId, NodeInfo};
use crate::crypto::PublicKey;

use std::net::SocketAddr;
use thiserror::Error;

/// NAT穿透错误
#[derive(Error, Debug)]
pub enum NatError {
    #[error("STUN error: {0}")]
    StunError(#[from] StunError),
    
    #[error("Hole punching error: {0}")]
    HolePunchingError(String),
    
    #[error("Relay error: {0}")]
    RelayError(#[from] RelayError),
    
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),
    
    #[error("Operation timeout")]
    Timeout,
}

/// NAT穿透管理器
#[derive(Clone)]
pub struct NatTraversal {
    /// 本地地址
    local_addr: SocketAddr,
    
    /// STUN服务器列表
    stun_servers: Vec<String>,
    
    /// 本地映射信息
    mapping: Option<NatMapping>,
}

impl NatTraversal {
    /// 创建新的NAT穿透管理器
    pub fn new(local_addr: SocketAddr, stun_servers: Vec<String>) -> Self {
        Self {
            local_addr,
            stun_servers,
            mapping: None,
        }
    }
    
    /// 发现NAT映射
    pub async fn discover_mapping(&mut self) -> Result<NatMapping, NatError> {
        let client = StunClient::new(self.local_addr, self.stun_servers.clone());
        let mapping = client.discover_mapping().await?;
        
        // 缓存映射信息
        self.mapping = Some(mapping.clone());
        
        Ok(mapping)
    }
    
    /// 获取已发现的NAT映射
    pub fn get_mapping(&self) -> Option<&NatMapping> {
        self.mapping.as_ref()
    }
    
    /// 尝试与远程节点建立直接连接
    pub async fn connect_to_peer(&self, peer_info: &NodeInfo) -> Result<tokio::net::UdpSocket, NatError> {
        // 确保已经发现了本地映射
        let local_mapping = match &self.mapping {
            Some(m) => m,
            None => return Err(NatError::ConnectionFailed("Local NAT mapping not discovered".to_string())),
        };
        
        // 选择目标地址
        // 在实际应用中，peer_info可能包含多个地址，需要尝试每一个
        let target_addr = match peer_info.addresses.first() {
            Some(addr) => addr,
            None => return Err(NatError::ConnectionFailed("Peer has no address".to_string())),
        };
        
        // 根据NAT类型选择连接策略
        match local_mapping.nat_type {
            NatType::Open => {
                // 直接连接
                self.direct_connect(target_addr).await
            },
            NatType::FullCone => {
                // 可以使用简单的UDP打洞
                self.udp_hole_punching(target_addr).await
            },
            NatType::RestrictedCone | NatType::PortRestrictedCone => {
                // 需要更复杂的UDP打洞
                self.udp_hole_punching(target_addr).await
            },
            NatType::Symmetric => {
                // 对称NAT很难穿透，尝试中继
                self.use_relay(target_addr).await
            },
            NatType::Unknown => {
                // 尝试所有方法
                match self.udp_hole_punching(target_addr).await {
                    Ok(socket) => Ok(socket),
                    Err(_) => self.use_relay(target_addr).await,
                }
            },
        }
    }
    
    /// 直接连接
    async fn direct_connect(&self, target_addr: &SocketAddr) -> Result<tokio::net::UdpSocket, NatError> {
        // 创建UDP套接字
        let socket = tokio::net::UdpSocket::bind(self.local_addr).await
            .map_err(|e| NatError::ConnectionFailed(format!("Failed to bind socket: {}", e)))?;
        
        // 连接到目标地址
        socket.connect(target_addr).await
            .map_err(|e| NatError::ConnectionFailed(format!("Failed to connect to peer: {}", e)))?;
        
        Ok(socket)
    }
    
    /// UDP打洞
    async fn udp_hole_punching(&self, target_addr: &SocketAddr) -> Result<tokio::net::UdpSocket, NatError> {
        // 创建UDP套接字
        let socket = tokio::net::UdpSocket::bind(self.local_addr).await
            .map_err(|e| NatError::ConnectionFailed(format!("Failed to bind socket: {}", e)))?;
        
        // 发送打洞包
        socket.send_to(&[1, 2, 3, 4], target_addr).await
            .map_err(|e| NatError::HolePunchingError(format!("Failed to send hole punching packet: {}", e)))?;
        
        // 在实际应用中，这里需要更复杂的打洞逻辑
        // 包括发送多个包、等待对方的打洞包等
        
        // 连接到目标地址
        socket.connect(target_addr).await
            .map_err(|e| NatError::ConnectionFailed(format!("Failed to connect to peer: {}", e)))?;
        
        Ok(socket)
    }
    
    /// 使用中继
    async fn use_relay(&self, target_addr: &SocketAddr) -> Result<tokio::net::UdpSocket, NatError> {
        // 获取本地映射
        let _local_mapping = match &self.mapping {
            Some(m) => m,
            None => return Err(NatError::ConnectionFailed("Local NAT mapping not discovered".to_string())),
        };
        
        // 创建UDP套接字用于本地绑定
        let local_socket = tokio::net::UdpSocket::bind(self.local_addr).await
            .map_err(|e| NatError::ConnectionFailed(format!("Failed to bind local socket: {}", e)))?;
        
        // 查找可用的中继节点
        // 在实际应用中，这应该通过DHT或其他方式动态发现
        // 这里我们简化为使用一个硬编码的中继节点列表
        let relay_nodes = self.discover_relay_nodes().await?;
        
        if relay_nodes.is_empty() {
            return Err(NatError::RelayError(relay::RelayError::RelayUnavailable("No relay nodes available".to_string())));
        }
        
        // 尝试每个中继节点
        for relay_node in relay_nodes {
            log::info!("Attempting to use relay node: {:?}", relay_node.addresses);
            
            // 创建中继配置
            let relay_config = RelayConfig::default();
            
            // 创建中继连接
            let mut relay_conn = RelayConnection::new(
                relay_node.clone(),
                target_addr.clone(),
                RelayType::Initiator,
                relay_config,
            );
            
            // 尝试连接
            match relay_conn.connect(self.local_addr).await {
                Ok(()) => {
                    log::info!("Successfully established relay connection through: {:?}", relay_node.addresses);
                    
                    // 创建一个新的UDP套接字，它将通过中继连接到目标
                    // 注意：这里我们返回原始套接字，但在实际应用中，
                    // 你可能需要创建一个包装器来通过中继转发所有流量
                    return Ok(local_socket);
                },
                Err(e) => {
                    log::warn!("Failed to establish relay connection: {}", e);
                    continue; // 尝试下一个中继节点
                }
            }
        }
        
        // 所有中继节点都失败
        Err(NatError::ConnectionFailed("All relay attempts failed".to_string()))
    }
    
    /// 发现可用的中继节点
    async fn discover_relay_nodes(&self) -> Result<Vec<NodeInfo>, NatError> {
        // 在实际应用中，这应该通过DHT或其他服务发现机制实现
        // 这里我们简化为返回一个硬编码的中继节点列表
        
        // 创建一个示例中继节点
        let mut relay_nodes = Vec::new();
        
        // 添加一些公共STUN服务器作为潜在的中继节点
        // 注意：在实际应用中，你需要使用专门的中继服务器
        for stun_server in &self.stun_servers {
            if let Some((host, port_str)) = stun_server.split_once(':') {
                if let Ok(port) = port_str.parse::<u16>() {
                    // 尝试解析主机名
                    if let Ok(addrs) = tokio::net::lookup_host(format!("{host}:{port}")).await {
                        let addresses: Vec<SocketAddr> = addrs.collect();
                        if !addresses.is_empty() {
                            // 创建一个节点信息
                            let node_id = NodeId::random(); // 在实际应用中，这应该是节点的真实ID
                            let node_info = NodeInfo {
                                id: node_id,
                                addresses,
                                last_updated: std::time::SystemTime::now(),
                                protocol_version: 1,
                                is_relay: true,
                                public_key: PublicKey::dummy(), // 在实际应用中，这应该是节点的真实公钥
                                signature: Vec::new(),
                            };
                            relay_nodes.push(node_info);
                        }
                    }
                }
            }
        }
        
        Ok(relay_nodes)
    }
}
