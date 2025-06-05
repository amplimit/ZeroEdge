use crate::dht::{NodeId, NodeInfo, DhtValue};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::SystemTime;

/// DHT网络协议消息定义
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DhtMessage {
    /// Ping消息 - 用于检查节点是否在线
    Ping {
        sender: NodeInfo,
        message_id: u64,
    },
    
    /// Pong消息 - Ping的响应
    Pong {
        sender: NodeInfo,
        message_id: u64,
    },
    
    /// FindNode请求 - 查找特定节点或最近的k个节点
    FindNodeRequest {
        sender: NodeInfo,
        target: NodeId,
        message_id: u64,
    },
    
    /// FindNode响应 - 返回找到的节点列表
    FindNodeResponse {
        sender: NodeInfo,
        nodes: Vec<NodeInfo>,
        message_id: u64,
    },
    
    /// FindValue请求 - 查找特定键的值
    FindValueRequest {
        sender: NodeInfo,
        key: Vec<u8>,
        message_id: u64,
    },
    
    /// FindValue响应 - 返回值或最近的节点
    FindValueResponse {
        sender: NodeInfo,
        result: FindValueResult,
        message_id: u64,
    },
    
    /// Store请求 - 存储键值对
    StoreRequest {
        sender: NodeInfo,
        value: DhtValue,
        message_id: u64,
    },
    
    /// Store响应 - 确认存储结果
    StoreResponse {
        sender: NodeInfo,
        success: bool,
        message_id: u64,
    },
}

/// FindValue操作的结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FindValueResult {
    /// 找到了值
    Found(DhtValue),
    /// 没找到值，返回最近的节点
    NotFound(Vec<NodeInfo>),
}

impl DhtMessage {
    /// 获取消息的发送者信息
    pub fn sender(&self) -> &NodeInfo {
        match self {
            DhtMessage::Ping { sender, .. } => sender,
            DhtMessage::Pong { sender, .. } => sender,
            DhtMessage::FindNodeRequest { sender, .. } => sender,
            DhtMessage::FindNodeResponse { sender, .. } => sender,
            DhtMessage::FindValueRequest { sender, .. } => sender,
            DhtMessage::FindValueResponse { sender, .. } => sender,
            DhtMessage::StoreRequest { sender, .. } => sender,
            DhtMessage::StoreResponse { sender, .. } => sender,
        }
    }
    
    /// 获取消息ID
    pub fn message_id(&self) -> u64 {
        match self {
            DhtMessage::Ping { message_id, .. } => *message_id,
            DhtMessage::Pong { message_id, .. } => *message_id,
            DhtMessage::FindNodeRequest { message_id, .. } => *message_id,
            DhtMessage::FindNodeResponse { message_id, .. } => *message_id,
            DhtMessage::FindValueRequest { message_id, .. } => *message_id,
            DhtMessage::FindValueResponse { message_id, .. } => *message_id,
            DhtMessage::StoreRequest { message_id, .. } => *message_id,
            DhtMessage::StoreResponse { message_id, .. } => *message_id,
        }
    }
    
    /// 序列化消息为字节
    pub fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }
    
    /// 从字节反序列化消息
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

/// 网络请求的上下文信息
#[derive(Debug, Clone)]
pub struct RequestContext {
    /// 请求的目标地址
    pub target_addr: SocketAddr,
    /// 请求的超时时间
    pub timeout: std::time::Duration,
    /// 请求发送时间
    pub sent_at: SystemTime,
    /// 重试次数
    pub retry_count: u32,
}

impl RequestContext {
    /// 创建新的请求上下文
    pub fn new(target_addr: SocketAddr, timeout: std::time::Duration) -> Self {
        Self {
            target_addr,
            timeout,
            sent_at: SystemTime::now(),
            retry_count: 0,
        }
    }
    
    /// 检查请求是否超时
    pub fn is_expired(&self) -> bool {
        match SystemTime::now().duration_since(self.sent_at) {
            Ok(elapsed) => elapsed > self.timeout,
            Err(_) => false,
        }
    }
    
    /// 增加重试次数
    pub fn increment_retry(&mut self) {
        self.retry_count += 1;
        self.sent_at = SystemTime::now();
    }
}

/// 消息路由信息
#[derive(Debug, Clone)]
pub struct MessageRoute {
    /// 发送者地址
    pub from: SocketAddr,
    /// 接收者地址  
    pub to: SocketAddr,
    /// 消息内容
    pub message: DhtMessage,
}

impl MessageRoute {
    /// 创建新的消息路由
    pub fn new(from: SocketAddr, to: SocketAddr, message: DhtMessage) -> Self {
        Self { from, to, message }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;
    use std::net::{IpAddr, Ipv4Addr};

    fn create_test_node_info() -> NodeInfo {
        let keypair = KeyPair::generate().unwrap();
        let id = NodeId::from_public_key(&keypair.public).unwrap();
        NodeInfo::new_signed(
            id,
            keypair.public,
            vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8000)],
            1,
            false,
            &keypair.secret,
        ).unwrap()
    }

    #[test]
    fn test_message_serialization() {
        let node_info = create_test_node_info();
        let target = NodeId::random();
        
        let message = DhtMessage::FindNodeRequest {
            sender: node_info,
            target,
            message_id: 12345,
        };
        
        // 测试序列化和反序列化
        let bytes = message.to_bytes().unwrap();
        let deserialized = DhtMessage::from_bytes(&bytes).unwrap();
        
        // 验证消息ID保持一致
        assert_eq!(message.message_id(), deserialized.message_id());
        assert_eq!(message.message_id(), 12345);
    }
    
    #[test]
    fn test_request_context_timeout() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8000);
        let timeout = std::time::Duration::from_millis(100);
        
        let mut context = RequestContext::new(addr, timeout);
        assert!(!context.is_expired());
        
        // 等待超时
        std::thread::sleep(std::time::Duration::from_millis(150));
        assert!(context.is_expired());
        
        // 测试重试计数
        assert_eq!(context.retry_count, 0);
        context.increment_retry();
        assert_eq!(context.retry_count, 1);
    }
}