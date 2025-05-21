mod stun;
mod hole_punching;
mod relay;

pub use stun::{StunClient, NatMapping, NatType, StunError};
pub use hole_punching::{PunchingStrategy, start_hole_punching};
pub use relay::{RelayConnection, RelayError, RelayConfig};

use crate::dht::NodeInfo;
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
    async fn use_relay(&self, _target_addr: &SocketAddr) -> Result<tokio::net::UdpSocket, NatError> {
        // 在实际应用中，这里需要实现中继逻辑
        // 包括找到合适的中继节点、建立中继连接等
        
        Err(NatError::ConnectionFailed("Relay not implemented yet".to_string()))
    }
}
