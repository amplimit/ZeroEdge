use crate::dht::NodeInfo;
use std::net::SocketAddr;
use std::time::Duration;
use thiserror::Error;
use log::{error, warn};
// 移除未使用的导入
// use log::{debug, info};
use rand::Rng;

/// 中继错误
#[derive(Error, Debug)]
pub enum RelayError {
    #[error("Network error: {0}")]
    NetworkError(String),
    
    #[error("Relay unavailable: {0}")]
    RelayUnavailable(String),
    
    #[error("Handshake failed: {0}")]
    HandshakeFailed(String),
    
    #[error("Timeout")]
    Timeout,
}

/// 中继配置
#[derive(Clone, Debug)]
pub struct RelayConfig {
    /// 连接超时
    pub connection_timeout: Duration,
    
    /// 中继超时
    pub relay_timeout: Duration,
    
    /// 握手重试次数
    pub handshake_retries: u8,
    
    /// 是否加密流量
    pub encrypt_traffic: bool,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            connection_timeout: Duration::from_secs(10),
            relay_timeout: Duration::from_secs(3600), // 1小时
            handshake_retries: 3,
            encrypt_traffic: true,
        }
    }
}

/// 中继连接类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayType {
    /// 连接发起方
    Initiator,
    
    /// 连接接收方
    Responder,
}

/// 中继连接
pub struct RelayConnection {
    /// 中继节点信息
    relay_node: NodeInfo,
    
    /// 对等点地址
    peer_addr: SocketAddr,
    
    /// 配置
    config: RelayConfig,
    
    /// 连接类型
    connection_type: RelayType,
    
    /// 会话ID
    session_id: [u8; 16],
    
    /// 底层UDP套接字
    socket: Option<tokio::net::UdpSocket>,
    
    /// 是否连接已建立
    connected: bool,
}

impl RelayConnection {
    /// 创建中继连接
    pub fn new(
        relay_node: NodeInfo,
        peer_addr: SocketAddr,
        connection_type: RelayType,
        config: RelayConfig,
    ) -> Self {
        // 生成随机会话ID
        let mut session_id = [0u8; 16];
        rand::thread_rng().fill(&mut session_id);
        
        Self {
            relay_node,
            peer_addr,
            config,
            connection_type,
            session_id,
            socket: None,
            connected: false,
        }
    }
    
    /// 建立中继连接
    pub async fn connect(&mut self, local_addr: SocketAddr) -> Result<(), RelayError> {
        // 创建UDP套接字
        let socket = tokio::net::UdpSocket::bind(local_addr).await
            .map_err(|e| RelayError::NetworkError(format!("Failed to bind socket: {}", e)))?;
        
        // 选择一个中继地址
        let relay_addr = match self.relay_node.addresses.first() {
            Some(addr) => addr,
            None => return Err(RelayError::RelayUnavailable("Relay node has no address".to_string())),
        };
        
        // 连接到中继
        socket.connect(relay_addr).await
            .map_err(|e| RelayError::NetworkError(format!("Failed to connect to relay: {}", e)))?;
        
        self.socket = Some(socket);
        
        // 执行握手过程
        self.perform_handshake().await?;
        
        self.connected = true;
        
        Ok(())
    }
    
    /// 执行握手过程
    async fn perform_handshake(&self) -> Result<(), RelayError> {
        let socket = match &self.socket {
            Some(s) => s,
            None => return Err(RelayError::HandshakeFailed("Socket not initialized".to_string())),
        };
        
        // 构建握手消息
        let mut handshake = Vec::with_capacity(64);
        
        // 魔数 "RELAY"
        handshake.extend_from_slice(&[0x52, 0x45, 0x4C, 0x41, 0x59]);
        
        // 版本
        handshake.push(1);
        
        // 连接类型
        handshake.push(match self.connection_type {
            RelayType::Initiator => 0,
            RelayType::Responder => 1,
        });
        
        // 会话ID
        handshake.extend_from_slice(&self.session_id);
        
        // 对等点地址
        let peer_ip = match self.peer_addr.ip() {
            std::net::IpAddr::V4(ipv4) => ipv4.octets().to_vec(),
            std::net::IpAddr::V6(ipv6) => ipv6.octets().to_vec(),
        };
        
        // IP类型 (4为IPv4, 6为IPv6)
        handshake.push(if peer_ip.len() == 4 { 4 } else { 6 });
        
        // IP长度
        handshake.push(peer_ip.len() as u8);
        
        // IP地址
        handshake.extend_from_slice(&peer_ip);
        
        // 端口
        handshake.extend_from_slice(&self.peer_addr.port().to_be_bytes());
        
        // 发送握手消息
        for _ in 0..self.config.handshake_retries {
            socket.send(&handshake).await
                .map_err(|e| RelayError::NetworkError(format!("Failed to send handshake: {}", e)))?;
            
            // 等待响应
            let mut buf = [0u8; 64];
            match tokio::time::timeout(Duration::from_secs(2), socket.recv(&mut buf)).await {
                Ok(Ok(len)) => {
                    // 检查响应
                    if len < 5 || &buf[0..5] != &[0x52, 0x45, 0x4C, 0x41, 0x59] {
                        continue; // 无效响应，重试
                    }
                    
                    // 检查版本
                    if buf[5] != 1 {
                        continue; // 版本不匹配，重试
                    }
                    
                    // 检查状态
                    if buf[6] != 0 {
                        let status = buf[6];
                        return Err(RelayError::HandshakeFailed(format!("Relay handshake failed with status: {}", status)));
                    }
                    
                    // 握手成功
                    return Ok(());
                },
                Ok(Err(e)) => {
                    warn!("Failed to receive handshake response: {}", e);
                },
                Err(_) => {
                    warn!("Timeout waiting for handshake response");
                }
            }
            
            // 等待一段时间再重试
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        
        Err(RelayError::HandshakeFailed("Handshake failed after retries".to_string()))
    }
    
    /// 发送数据
    pub async fn send(&self, data: &[u8]) -> Result<(), RelayError> {
        if !self.connected {
            return Err(RelayError::NetworkError("Not connected".to_string()));
        }
        
        let socket = match &self.socket {
            Some(s) => s,
            None => return Err(RelayError::NetworkError("Socket not initialized".to_string())),
        };
        
        // 构建中继消息
        let mut message = Vec::with_capacity(data.len() + 32);
        
        // 魔数 "RELAY"
        message.extend_from_slice(&[0x52, 0x45, 0x4C, 0x41, 0x59]);
        
        // 版本
        message.push(1);
        
        // 消息类型 (0为数据)
        message.push(0);
        
        // 会话ID
        message.extend_from_slice(&self.session_id);
        
        // 数据长度
        message.extend_from_slice(&(data.len() as u32).to_be_bytes());
        
        // 数据
        message.extend_from_slice(data);
        
        // 发送消息
        socket.send(&message).await
            .map_err(|e| RelayError::NetworkError(format!("Failed to send data: {}", e)))?;
        
        Ok(())
    }
    
    /// 接收数据
    pub async fn receive(&self, buf: &mut [u8]) -> Result<usize, RelayError> {
        if !self.connected {
            return Err(RelayError::NetworkError("Not connected".to_string()));
        }
        
        let socket = match &self.socket {
            Some(s) => s,
            None => return Err(RelayError::NetworkError("Socket not initialized".to_string())),
        };
        
        // 接收消息
        let mut relay_buf = vec![0u8; buf.len() + 32];
        
        let len = socket.recv(&mut relay_buf).await
            .map_err(|e| RelayError::NetworkError(format!("Failed to receive data: {}", e)))?;
        
        // 检查最小长度
        if len < 24 {
            return Err(RelayError::NetworkError("Received message too short".to_string()));
        }
        
        // 检查魔数
        if &relay_buf[0..5] != &[0x52, 0x45, 0x4C, 0x41, 0x59] {
            return Err(RelayError::NetworkError("Invalid relay message".to_string()));
        }
        
        // 检查版本
        if relay_buf[5] != 1 {
            return Err(RelayError::NetworkError("Unsupported relay protocol version".to_string()));
        }
        
        // 检查消息类型
        if relay_buf[6] != 0 {
            return Err(RelayError::NetworkError("Unexpected relay message type".to_string()));
        }
        
        // 检查会话ID
        if &relay_buf[7..23] != &self.session_id {
            return Err(RelayError::NetworkError("Session ID mismatch".to_string()));
        }
        
        // 解析数据长度
        let data_len = u32::from_be_bytes([relay_buf[23], relay_buf[24], relay_buf[25], relay_buf[26]]) as usize;
        
        // 检查数据长度
        if 27 + data_len > len {
            return Err(RelayError::NetworkError("Incomplete relay message".to_string()));
        }
        
        // 复制数据
        let actual_len = std::cmp::min(data_len, buf.len());
        buf[..actual_len].copy_from_slice(&relay_buf[27..27 + actual_len]);
        
        Ok(actual_len)
    }
    
    /// 关闭连接
    pub async fn close(&mut self) -> Result<(), RelayError> {
        if !self.connected {
            return Ok(()); // 已经关闭
        }
        
        let socket = match &self.socket {
            Some(s) => s,
            None => return Ok(()), // 没有套接字
        };
        
        // 构建关闭消息
        let mut message = Vec::with_capacity(32);
        
        // 魔数 "RELAY"
        message.extend_from_slice(&[0x52, 0x45, 0x4C, 0x41, 0x59]);
        
        // 版本
        message.push(1);
        
        // 消息类型 (2为关闭)
        message.push(2);
        
        // 会话ID
        message.extend_from_slice(&self.session_id);
        
        // 发送关闭消息
        let _ = socket.send(&message).await;
        
        self.connected = false;
        self.socket = None;
        
        Ok(())
    }
    
    /// 检查连接是否已建立
    pub fn is_connected(&self) -> bool {
        self.connected
    }
    
    /// 获取会话ID
    pub fn session_id(&self) -> &[u8; 16] {
        &self.session_id
    }
}

impl Drop for RelayConnection {
    fn drop(&mut self) {
        if self.connected {
            // 在实际应用中，可能需要使用阻塞方式发送关闭消息
            // 或者使用一个任务池来处理异步关闭
        }
    }
}
