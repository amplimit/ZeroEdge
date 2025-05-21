use crate::network::{Connection, ConnectionState, ConnectionError};
use crate::crypto::PublicKey;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use std::sync::Arc;
use thiserror::Error;
use log::error;
// 移除未使用的导入
// use log::{debug, info, warn};

#[derive(Error, Debug)]
pub enum PeerError {
    #[error("Connection error: {0}")]
    ConnectionError(#[from] ConnectionError),
    
    #[error("Peer not connected")]
    NotConnected,
    
    #[error("Timeout")]
    Timeout,
    
    #[error("Invalid state: {0}")]
    InvalidState(String),
}

/// 对等点状态
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    /// 已连接
    Connected,
    
    /// 已断开连接
    Disconnected,
}

/// 对等点信息
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// 对等点ID
    pub id: String,
    
    /// 对等点名称
    pub name: Option<String>,
    
    /// 对等点公钥
    pub public_key: PublicKey,
    
    /// 对等点地址列表
    pub addresses: Vec<SocketAddr>,
    
    /// 发现时间
    pub discovered_at: Instant,
    
    /// 最后更新时间
    pub last_updated: Instant,
}

impl PeerInfo {
    /// 创建新的对等点信息
    pub fn new(id: String, public_key: PublicKey, addresses: Vec<SocketAddr>) -> Self {
        let now = Instant::now();
        
        Self {
            id,
            name: None,
            public_key,
            addresses,
            discovered_at: now,
            last_updated: now,
        }
    }
    
    /// 更新地址列表
    pub fn update_addresses(&mut self, addresses: Vec<SocketAddr>) {
        self.addresses = addresses;
        self.last_updated = Instant::now();
    }
    
    /// 设置名称
    pub fn set_name(&mut self, name: String) {
        self.name = Some(name);
        self.last_updated = Instant::now();
    }
}

/// 代表网络中的一个对等点
#[derive(Clone)]
pub struct Peer {
    /// 对等点信息
    info: PeerInfo,
    
    /// 连接
    connection: Connection,
    
    /// 状态
    state: Arc<RwLock<PeerState>>,
    
    /// 连接时间
    connected_at: Instant,
    
    /// 最后活动时间
    last_activity: Arc<RwLock<Instant>>,
}

impl Peer {
    /// 创建新的对等点
    pub async fn new(info: PeerInfo, connection: Connection) -> Result<Self, PeerError> {
        let now = Instant::now();
        
        // 检查连接状态
        match connection.get_state().await {
            ConnectionState::Connected => {
                // 创建对等点
                let peer = Self {
                    info,
                    connection,
                    state: Arc::new(RwLock::new(PeerState::Connected)),
                    connected_at: now,
                    last_activity: Arc::new(RwLock::new(now)),
                };
                
                Ok(peer)
            },
            ConnectionState::Connecting => {
                // 等待连接建立
                Err(PeerError::NotConnected)
            },
            _ => {
                // 连接已断开或出错
                Err(PeerError::NotConnected)
            },
        }
    }
    
    /// 发送数据
    pub async fn send(&self, data: &[u8]) -> Result<(), PeerError> {
        // 检查状态
        if *self.state.read().await == PeerState::Disconnected {
            return Err(PeerError::NotConnected);
        }
        
        // 更新活动时间
        {
            let mut last_activity = self.last_activity.write().await;
            *last_activity = Instant::now();
        }
        
        // 发送数据
        self.connection.send(data).await?;
        
        Ok(())
    }
    
    /// 接收数据
    pub async fn receive(&self) -> Result<Vec<u8>, PeerError> {
        // 检查状态
        if *self.state.read().await == PeerState::Disconnected {
            return Err(PeerError::NotConnected);
        }
        
        // 接收数据
        match self.connection.receive().await {
            Ok(data) => {
                // 更新活动时间
                {
                    let mut last_activity = self.last_activity.write().await;
                    *last_activity = Instant::now();
                }
                
                Ok(data)
            },
            Err(e) => Err(e.into()),
        }
    }
    
    /// 等待数据
    pub async fn wait_for_data(&self, timeout: Duration) -> Result<Vec<u8>, PeerError> {
        // 检查状态
        if *self.state.read().await == PeerState::Disconnected {
            return Err(PeerError::NotConnected);
        }
        
        // 等待数据
        match self.connection.wait_for_data(timeout).await {
            Ok(data) => {
                // 更新活动时间
                {
                    let mut last_activity = self.last_activity.write().await;
                    *last_activity = Instant::now();
                }
                
                Ok(data)
            },
            Err(e) => Err(e.into()),
        }
    }
    
    /// 断开连接
    pub async fn disconnect(&self) -> Result<(), PeerError> {
        // 更新状态
        {
            let mut state_guard = self.state.write().await;
            *state_guard = PeerState::Disconnected;
        }
        
        // 断开连接
        self.connection.disconnect().await?;
        
        Ok(())
    }
    
    /// 获取对等点ID
    pub fn get_id(&self) -> &str {
        &self.info.id
    }
    
    /// 获取对等点信息
    pub fn get_info(&self) -> &PeerInfo {
        &self.info
    }
    
    /// 获取对等点可变信息
    pub fn get_info_mut(&mut self) -> &mut PeerInfo {
        &mut self.info
    }
    
    /// 获取对等点状态
    pub async fn get_state(&self) -> PeerState {
        *self.state.read().await
    }
    
    /// 获取连接统计信息
    pub async fn get_stats(&self) -> crate::network::connection::TrafficStats {
        self.connection.get_stats().await
    }
    
    /// 获取MTU
    pub async fn get_mtu(&self) -> usize {
        self.connection.get_mtu()
    }
    
    /// 检查对等点是否空闲
    pub async fn is_idle(&self, duration: Duration) -> bool {
        let last_activity = *self.last_activity.read().await;
        Instant::now().duration_since(last_activity) >= duration
    }
    
    /// 检查连接是否过期
    pub async fn is_expired(&self) -> bool {
        // 检查连接状态
        if *self.state.read().await == PeerState::Disconnected {
            return true;
        }
        
        // 检查连接状态
        match self.connection.get_state().await {
            ConnectionState::Connected => false,
            _ => true,
        }
    }
    
    /// 创建对等点副本
    pub fn clone(&self) -> Self {
        Self {
            info: self.info.clone(),
            connection: self.connection.clone(),
            state: self.state.clone(),
            connected_at: self.connected_at,
            last_activity: self.last_activity.clone(),
        }
    }
}
