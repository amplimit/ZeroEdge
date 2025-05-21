use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use thiserror::Error;
use log::error;
// 移除未使用的导入
// use log::{debug, info, warn};
use rand::Rng;

/// STUN协议实现的错误
#[derive(Error, Debug)]
pub enum StunError {
    #[error("Network error: {0}")]
    NetworkError(String),
    
    #[error("Invalid STUN message: {0}")]
    InvalidMessage(String),
    
    #[error("STUN server error: {0}")]
    ServerError(String),
    
    #[error("Timeout waiting for response")]
    Timeout,
    
    #[error("Failed to find public IP: {0}")]
    PublicIpDiscoveryFailed(String),
}

/// NAT类型枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatType {
    /// 无NAT，直接连接到互联网
    Open,
    /// 完全锥形NAT，接受所有外部连接
    FullCone,
    /// 受限锥形NAT，只接受之前发送过数据的IP
    RestrictedCone,
    /// 端口受限锥形NAT，只接受之前发送过数据的IP和端口
    PortRestrictedCone,
    /// 对称NAT，每个目的地使用不同的外部IP:端口
    Symmetric,
    /// 未知NAT类型
    Unknown,
}

impl std::fmt::Display for NatType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NatType::Open => write!(f, "Open Internet (No NAT)"),
            NatType::FullCone => write!(f, "Full Cone NAT"),
            NatType::RestrictedCone => write!(f, "Restricted Cone NAT"),
            NatType::PortRestrictedCone => write!(f, "Port Restricted Cone NAT"),
            NatType::Symmetric => write!(f, "Symmetric NAT"),
            NatType::Unknown => write!(f, "Unknown NAT type"),
        }
    }
}

/// NAT映射信息
#[derive(Debug, Clone)]
pub struct NatMapping {
    /// 本地地址
    pub local_addr: SocketAddr,
    
    /// 公网地址
    pub public_addr: SocketAddr,
    
    /// NAT类型
    pub nat_type: NatType,
}

/// STUN消息类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StunMessageType {
    /// 绑定请求
    BindingRequest = 0x0001,
    /// 绑定响应
    BindingResponse = 0x0101,
    /// 绑定错误响应
    BindingErrorResponse = 0x0111,
}

/// STUN属性类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StunAttributeType {
    /// 映射地址
    MappedAddress = 0x0001,
    /// 响应地址
    ResponseAddress = 0x0002,
    /// 变更请求
    ChangeRequest = 0x0003,
    /// 源地址
    SourceAddress = 0x0004,
    /// 已更改地址
    ChangedAddress = 0x0005,
    /// 用户名
    Username = 0x0006,
    /// 消息完整性
    MessageIntegrity = 0x0008,
    /// 错误码
    ErrorCode = 0x0009,
    /// 未知属性
    UnknownAttributes = 0x000A,
    /// XOR映射地址
    XorMappedAddress = 0x0020,
}

/// STUN客户端
pub struct StunClient {
    /// 本地地址
    local_addr: SocketAddr,
    
    /// STUN服务器列表
    servers: Vec<String>,
    
    /// 超时时间
    timeout: Duration,
}

impl StunClient {
    /// 创建新的STUN客户端
    pub fn new(local_addr: SocketAddr, servers: Vec<String>) -> Self {
        Self {
            local_addr,
            servers,
            timeout: Duration::from_secs(5),
        }
    }
    
    /// 设置超时时间
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }
    
    /// 发现NAT映射
    pub async fn discover_mapping(&self) -> Result<NatMapping, StunError> {
        // 如果没有STUN服务器，则直接返回错误
        if self.servers.is_empty() {
            return Err(StunError::PublicIpDiscoveryFailed("No STUN servers configured".to_string()));
        }
        
        // 随机选择一个STUN服务器
        let server = self.select_server().await?;
        
        // 创建UDP套接字
        let socket = tokio::net::UdpSocket::bind(self.local_addr).await
            .map_err(|e| StunError::NetworkError(e.to_string()))?;
        
        // 发送绑定请求
        let public_addr = self.send_binding_request(&socket, &server).await?;
        
        // 确定NAT类型
        let nat_type = self.determine_nat_type(&socket, &server, &public_addr).await?;
        
        Ok(NatMapping {
            local_addr: self.local_addr,
            public_addr,
            nat_type,
        })
    }
    
    /// 选择STUN服务器
    async fn select_server(&self) -> Result<SocketAddr, StunError> {
        let mut rng = rand::thread_rng();
        let index = rng.gen_range(0..self.servers.len());
        let server = &self.servers[index];
        
        // 解析服务器地址
        let server_addr = tokio::net::lookup_host(server).await
            .map_err(|e| StunError::NetworkError(format!("Failed to resolve STUN server {}: {}", server, e)))?
            .next()
            .ok_or_else(|| StunError::NetworkError(format!("Failed to resolve STUN server {}", server)))?;
        
        Ok(server_addr)
    }
    
    /// 发送绑定请求
    async fn send_binding_request(&self, socket: &tokio::net::UdpSocket, server: &SocketAddr) -> Result<SocketAddr, StunError> {
        // 构建绑定请求消息
        let request = self.build_binding_request();
        
        // 发送请求
        socket.send_to(&request, server).await
            .map_err(|e| StunError::NetworkError(format!("Failed to send STUN request: {}", e)))?;
        
        // 接收响应
        let mut buf = [0u8; 512];
        let (len, _) = tokio::time::timeout(self.timeout, socket.recv_from(&mut buf)).await
            .map_err(|_| StunError::Timeout)?
            .map_err(|e| StunError::NetworkError(format!("Failed to receive STUN response: {}", e)))?;
        
        // 解析响应
        self.parse_binding_response(&buf[..len])
    }
    
    /// 构建绑定请求消息
    fn build_binding_request(&self) -> Vec<u8> {
        let mut request = vec![0u8; 20]; // STUN消息头部是20字节
        
        // 设置消息类型 (绑定请求)
        request[0] = 0x00;
        request[1] = 0x01;
        
        // 设置消息长度 (暂时为0)
        request[2] = 0x00;
        request[3] = 0x00;
        
        // 设置魔数 (固定值)
        request[4] = 0x21;
        request[5] = 0x12;
        request[6] = 0xA4;
        request[7] = 0x42;
        
        // 生成随机事务ID
        let mut rng = rand::thread_rng();
        for i in 8..20 {
            request[i] = rng.gen();
        }
        
        request
    }
    
    /// 解析绑定响应
    fn parse_binding_response(&self, response: &[u8]) -> Result<SocketAddr, StunError> {
        // 检查响应长度
        if response.len() < 20 {
            return Err(StunError::InvalidMessage("Response too short".to_string()));
        }
        
        // 检查响应类型
        let msg_type = (response[0] as u16) << 8 | response[1] as u16;
        if msg_type != StunMessageType::BindingResponse as u16 {
            return Err(StunError::InvalidMessage(format!("Unexpected message type: {:04x}", msg_type)));
        }
        
        // 解析属性
        let mut pos = 20; // 跳过头部
        let msg_len = (response[2] as usize) << 8 | response[3] as usize;
        
        while pos < 20 + msg_len {
            // 检查剩余长度
            if pos + 4 > response.len() {
                return Err(StunError::InvalidMessage("Truncated attribute header".to_string()));
            }
            
            // 解析属性类型和长度
            let attr_type = (response[pos] as u16) << 8 | response[pos + 1] as u16;
            let attr_len = (response[pos + 2] as usize) << 8 | response[pos + 3] as usize;
            pos += 4;
            
            // 检查属性长度
            if pos + attr_len > response.len() {
                return Err(StunError::InvalidMessage("Truncated attribute value".to_string()));
            }
            
            // 处理映射地址属性
            if attr_type == StunAttributeType::MappedAddress as u16 || attr_type == StunAttributeType::XorMappedAddress as u16 {
                // 映射地址格式: 1字节保留 + 1字节家族 + 2字节端口 + 4或16字节IP
                if attr_len < 8 {
                    return Err(StunError::InvalidMessage("Invalid address attribute length".to_string()));
                }
                
                // 检查地址族
                let family = response[pos + 1];
                if family != 1 {
                    return Err(StunError::InvalidMessage("Only IPv4 is supported".to_string()));
                }
                
                // 解析端口
                let mut port = (response[pos + 2] as u16) << 8 | response[pos + 3] as u16;
                
                // 解析IP地址
                let mut ip = [
                    response[pos + 4],
                    response[pos + 5],
                    response[pos + 6],
                    response[pos + 7],
                ];
                
                // 如果是XOR映射地址，需要异或处理
                if attr_type == StunAttributeType::XorMappedAddress as u16 {
                    port ^= 0x2112; // 魔数的前16位
                    
                    // IP与魔数异或
                    ip[0] ^= 0x21;
                    ip[1] ^= 0x12;
                    ip[2] ^= 0xA4;
                    ip[3] ^= 0x42;
                }
                
                return Ok(SocketAddr::new(
                    IpAddr::V4(std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])),
                    port
                ));
            }
            
            // 跳到下一个属性
            pos += attr_len;
            
            // 属性长度对齐到4字节边界
            let padding = (4 - (attr_len % 4)) % 4;
            pos += padding;
        }
        
        Err(StunError::InvalidMessage("Mapped address not found in response".to_string()))
    }
    
    /// 确定NAT类型
    async fn determine_nat_type(&self, _socket: &tokio::net::UdpSocket, _server: &SocketAddr, public_addr: &SocketAddr) -> Result<NatType, StunError> {
        // 在实际实现中，需要进行多次测试来确定NAT类型
        // 这是一个简化版本
        
        // 如果公网IP与本地IP相同，则没有NAT
        if let IpAddr::V4(local_ip) = self.local_addr.ip() {
            if let IpAddr::V4(public_ip) = public_addr.ip() {
                if local_ip == public_ip {
                    return Ok(NatType::Open);
                }
            }
        }
        
        // 默认假设为端口受限锥形NAT
        // 在实际实现中，需要更复杂的测试来确定具体NAT类型
        Ok(NatType::PortRestrictedCone)
    }
}
