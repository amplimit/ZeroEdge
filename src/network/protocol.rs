use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use thiserror::Error;
use log::error;

#[derive(Error, Debug)]
pub enum ProtocolError {
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("Deserialization error: {0}")]
    DeserializationError(String),
    
    #[error("Invalid message: {0}")]
    InvalidMessage(String),
    
    #[error("Unsupported protocol version: {0}")]
    UnsupportedVersion(u8),
}

/// 消息类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageType {
    /// 握手消息
    Handshake = 0,
    
    /// 握手确认
    HandshakeAck = 1,
    
    /// 保持活动
    KeepAlive = 2,
    
    /// 断开连接
    Disconnect = 3,
    
    /// 查找节点
    FindNode = 4,
    
    /// 节点列表
    NodeList = 5,
    
    /// 存储值
    StoreValue = 6,
    
    /// 查找值
    FindValue = 7,
    
    /// 值结果
    ValueResult = 8,
    
    /// 直接消息
    DirectMessage = 9,
    
    /// 分段消息
    FragmentedMessage = 10,
    
    /// 确认
    Ack = 11,
    
    /// 中继请求
    RelayRequest = 12,
    
    /// 中继响应
    RelayResponse = 13,
    
    /// 穿透请求
    PunchRequest = 14,
    
    /// 穿透响应
    PunchResponse = 15,
}

/// 协议头
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolHeader {
    /// 协议版本
    pub version: u8,
    
    /// 消息类型
    pub message_type: MessageType,
    
    /// 消息ID
    pub message_id: u32,
    
    /// 时间戳
    pub timestamp: u64,
    
    /// 发送者ID
    pub sender_id: String,
    
    /// 接收者ID (可选)
    pub recipient_id: Option<String>,
    
    /// 标志
    pub flags: u8,
}

impl ProtocolHeader {
    /// 创建新的协议头
    pub fn new(
        message_type: MessageType,
        message_id: u32,
        sender_id: String,
        recipient_id: Option<String>,
    ) -> Self {
        // 获取当前时间戳
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        Self {
            version: 1, // 当前协议版本
            message_type,
            message_id,
            timestamp: now,
            sender_id,
            recipient_id,
            flags: 0,
        }
    }
}

/// 协议消息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolMessage {
    /// 消息头
    pub header: ProtocolHeader,
    
    /// 消息负载
    pub payload: Vec<u8>,
}

impl ProtocolMessage {
    /// 创建新的协议消息
    pub fn new(
        message_type: MessageType,
        message_id: u32,
        sender_id: String,
        recipient_id: Option<String>,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            header: ProtocolHeader::new(
                message_type,
                message_id,
                sender_id,
                recipient_id,
            ),
            payload,
        }
    }
    
    /// 序列化消息
    pub fn serialize(&self) -> Result<Vec<u8>, ProtocolError> {
        bincode::serialize(self)
            .map_err(|e| ProtocolError::SerializationError(e.to_string()))
    }
    
    /// 反序列化消息
    pub fn deserialize(data: &[u8]) -> Result<Self, ProtocolError> {
        bincode::deserialize(data)
            .map_err(|e| ProtocolError::DeserializationError(e.to_string()))
    }
}

/// 握手消息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeMessage {
    /// 节点ID
    pub node_id: String,
    
    /// 公钥
    pub public_key: Vec<u8>,
    
    /// 协议版本
    pub protocol_version: u8,
    
    /// 客户端版本
    pub client_version: String,
    
    /// 地址列表
    pub addresses: Vec<String>,
    
    /// 功能标志
    pub capabilities: u32,
    
    /// 随机数
    pub nonce: u64,
}

/// 节点信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfoMessage {
    /// 节点ID
    pub node_id: String,
    
    /// 地址列表
    pub addresses: Vec<String>,
    
    /// 最后活动时间
    pub last_seen: u64,
    
    /// 功能标志
    pub capabilities: u32,
}

/// 存储值消息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreValueMessage {
    /// 键
    pub key: Vec<u8>,
    
    /// 值
    pub value: Vec<u8>,
    
    /// 存储模式
    pub mode: u8,
    
    /// 存储时间 (秒)
    pub ttl: u32,
}

/// 查找值消息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindValueMessage {
    /// 键
    pub key: Vec<u8>,
}

/// 直接消息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectMessagePayload {
    /// 内容类型
    pub content_type: String,
    
    /// 消息内容
    pub content: Vec<u8>,
    
    /// 消息ID
    pub content_id: String,
    
    /// 附加数据
    pub metadata: Option<Vec<u8>>,
}

/// 分段消息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FragmentedMessagePayload {
    /// 原始消息ID
    pub original_message_id: u32,
    
    /// 片段索引
    pub fragment_index: u16,
    
    /// 总片段数
    pub fragment_count: u16,
    
    /// 片段数据
    pub fragment_data: Vec<u8>,
}

/// 协议实现
pub struct Protocol {
    /// 当前节点ID
    node_id: String,
    
    /// 协议版本
    version: u8,
    
    /// 下一个消息ID
    next_message_id: u32,
}

impl Protocol {
    /// 创建新的协议实例
    pub fn new(node_id: String) -> Self {
        Self {
            node_id,
            version: 1,
            next_message_id: 1,
        }
    }
    
    /// 获取下一个消息ID
    pub fn next_message_id(&mut self) -> u32 {
        let id = self.next_message_id;
        self.next_message_id = self.next_message_id.wrapping_add(1);
        id
    }
    
    /// 创建握手消息
    pub fn create_handshake(
        &mut self,
        public_key: Vec<u8>,
        client_version: String,
        addresses: Vec<String>,
        capabilities: u32,
    ) -> Result<Vec<u8>, ProtocolError> {
        // 创建随机数
        let nonce = rand::random::<u64>();
        
        // 创建握手负载
        let handshake = HandshakeMessage {
            node_id: self.node_id.clone(),
            public_key,
            protocol_version: self.version,
            client_version,
            addresses,
            capabilities,
            nonce,
        };
        
        // 序列化握手负载
        let payload = bincode::serialize(&handshake)
            .map_err(|e| ProtocolError::SerializationError(e.to_string()))?;
        
        // 创建协议消息
        let message = ProtocolMessage::new(
            MessageType::Handshake,
            self.next_message_id(),
            self.node_id.clone(),
            None,
            payload,
        );
        
        // 序列化消息
        message.serialize()
    }
    
    /// 创建握手确认消息
    pub fn create_handshake_ack(
        &mut self,
        recipient_id: String,
        original_nonce: u64,
    ) -> Result<Vec<u8>, ProtocolError> {
        // 创建握手确认负载
        let payload = bincode::serialize(&original_nonce)
            .map_err(|e| ProtocolError::SerializationError(e.to_string()))?;
        
        // 创建协议消息
        let message = ProtocolMessage::new(
            MessageType::HandshakeAck,
            self.next_message_id(),
            self.node_id.clone(),
            Some(recipient_id),
            payload,
        );
        
        // 序列化消息
        message.serialize()
    }
    
    /// 创建保持活动消息
    pub fn create_keepalive(&mut self) -> Result<Vec<u8>, ProtocolError> {
        // 创建协议消息
        let message = ProtocolMessage::new(
            MessageType::KeepAlive,
            self.next_message_id(),
            self.node_id.clone(),
            None,
            Vec::new(),
        );
        
        // 序列化消息
        message.serialize()
    }
    
    /// 创建断开连接消息
    pub fn create_disconnect(&mut self, reason: &str) -> Result<Vec<u8>, ProtocolError> {
        // 创建协议消息
        let message = ProtocolMessage::new(
            MessageType::Disconnect,
            self.next_message_id(),
            self.node_id.clone(),
            None,
            reason.as_bytes().to_vec(),
        );
        
        // 序列化消息
        message.serialize()
    }
    
    /// 创建查找节点消息
    pub fn create_find_node(
        &mut self,
        target_id: String,
    ) -> Result<Vec<u8>, ProtocolError> {
        // 创建协议消息
        let message = ProtocolMessage::new(
            MessageType::FindNode,
            self.next_message_id(),
            self.node_id.clone(),
            None,
            target_id.as_bytes().to_vec(),
        );
        
        // 序列化消息
        message.serialize()
    }
    
    /// 创建节点列表消息
    pub fn create_node_list(
        &mut self,
        recipient_id: String,
        nodes: Vec<NodeInfoMessage>,
    ) -> Result<Vec<u8>, ProtocolError> {
        // 序列化节点列表
        let payload = bincode::serialize(&nodes)
            .map_err(|e| ProtocolError::SerializationError(e.to_string()))?;
        
        // 创建协议消息
        let message = ProtocolMessage::new(
            MessageType::NodeList,
            self.next_message_id(),
            self.node_id.clone(),
            Some(recipient_id),
            payload,
        );
        
        // 序列化消息
        message.serialize()
    }
    
    /// 创建存储值消息
    pub fn create_store_value(
        &mut self,
        key: Vec<u8>,
        value: Vec<u8>,
        ttl: u32,
    ) -> Result<Vec<u8>, ProtocolError> {
        // 创建存储值负载
        let store_value = StoreValueMessage {
            key,
            value,
            mode: 0, // 默认模式
            ttl,
        };
        
        // 序列化存储值负载
        let payload = bincode::serialize(&store_value)
            .map_err(|e| ProtocolError::SerializationError(e.to_string()))?;
        
        // 创建协议消息
        let message = ProtocolMessage::new(
            MessageType::StoreValue,
            self.next_message_id(),
            self.node_id.clone(),
            None,
            payload,
        );
        
        // 序列化消息
        message.serialize()
    }
    
    /// 创建查找值消息
    pub fn create_find_value(
        &mut self,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, ProtocolError> {
        // 创建查找值负载
        let find_value = FindValueMessage {
            key,
        };
        
        // 序列化查找值负载
        let payload = bincode::serialize(&find_value)
            .map_err(|e| ProtocolError::SerializationError(e.to_string()))?;
        
        // 创建协议消息
        let message = ProtocolMessage::new(
            MessageType::FindValue,
            self.next_message_id(),
            self.node_id.clone(),
            None,
            payload,
        );
        
        // 序列化消息
        message.serialize()
    }
    
    /// 创建直接消息
    pub fn create_direct_message(
        &mut self,
        recipient_id: String,
        content_type: String,
        content: Vec<u8>,
        content_id: String,
        metadata: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, ProtocolError> {
        // 创建直接消息负载
        let direct_message = DirectMessagePayload {
            content_type,
            content,
            content_id,
            metadata,
        };
        
        // 序列化直接消息负载
        let payload = bincode::serialize(&direct_message)
            .map_err(|e| ProtocolError::SerializationError(e.to_string()))?;
        
        // 创建协议消息
        let message = ProtocolMessage::new(
            MessageType::DirectMessage,
            self.next_message_id(),
            self.node_id.clone(),
            Some(recipient_id),
            payload,
        );
        
        // 序列化消息
        message.serialize()
    }
    
    /// 创建分段消息
    pub fn create_fragmented_message(
        &mut self,
        recipient_id: String,
        original_message_id: u32,
        fragment_index: u16,
        fragment_count: u16,
        fragment_data: Vec<u8>,
    ) -> Result<Vec<u8>, ProtocolError> {
        // 创建分段消息负载
        let fragmented_message = FragmentedMessagePayload {
            original_message_id,
            fragment_index,
            fragment_count,
            fragment_data,
        };
        
        // 序列化分段消息负载
        let payload = bincode::serialize(&fragmented_message)
            .map_err(|e| ProtocolError::SerializationError(e.to_string()))?;
        
        // 创建协议消息
        let message = ProtocolMessage::new(
            MessageType::FragmentedMessage,
            self.next_message_id(),
            self.node_id.clone(),
            Some(recipient_id),
            payload,
        );
        
        // 序列化消息
        message.serialize()
    }
    
    /// 创建确认消息
    pub fn create_ack(
        &mut self,
        recipient_id: String,
        ack_message_id: u32,
    ) -> Result<Vec<u8>, ProtocolError> {
        // 序列化确认的消息ID
        let payload = bincode::serialize(&ack_message_id)
            .map_err(|e| ProtocolError::SerializationError(e.to_string()))?;
        
        // 创建协议消息
        let message = ProtocolMessage::new(
            MessageType::Ack,
            self.next_message_id(),
            self.node_id.clone(),
            Some(recipient_id),
            payload,
        );
        
        // 序列化消息
        message.serialize()
    }
    
    /// 解析消息
    pub fn parse_message(&self, data: &[u8]) -> Result<ProtocolMessage, ProtocolError> {
        // 反序列化消息
        let message = ProtocolMessage::deserialize(data)?;
        
        // 检查协议版本
        if message.header.version > self.version {
            return Err(ProtocolError::UnsupportedVersion(message.header.version));
        }
        
        Ok(message)
    }
    
    /// 解析握手消息
    pub fn parse_handshake(&self, message: &ProtocolMessage) -> Result<HandshakeMessage, ProtocolError> {
        // 检查消息类型
        if message.header.message_type != MessageType::Handshake {
            return Err(ProtocolError::InvalidMessage(
                format!("Expected Handshake message, got {:?}", message.header.message_type)
            ));
        }
        
        // 反序列化握手负载
        bincode::deserialize(&message.payload)
            .map_err(|e| ProtocolError::DeserializationError(e.to_string()))
    }
    
    /// 解析握手确认消息
    pub fn parse_handshake_ack(&self, message: &ProtocolMessage) -> Result<u64, ProtocolError> {
        // 检查消息类型
        if message.header.message_type != MessageType::HandshakeAck {
            return Err(ProtocolError::InvalidMessage(
                format!("Expected HandshakeAck message, got {:?}", message.header.message_type)
            ));
        }
        
        // 反序列化握手确认负载
        bincode::deserialize(&message.payload)
            .map_err(|e| ProtocolError::DeserializationError(e.to_string()))
    }
    
    /// 解析节点列表消息
    pub fn parse_node_list(&self, message: &ProtocolMessage) -> Result<Vec<NodeInfoMessage>, ProtocolError> {
        // 检查消息类型
        if message.header.message_type != MessageType::NodeList {
            return Err(ProtocolError::InvalidMessage(
                format!("Expected NodeList message, got {:?}", message.header.message_type)
            ));
        }
        
        // 反序列化节点列表负载
        bincode::deserialize(&message.payload)
            .map_err(|e| ProtocolError::DeserializationError(e.to_string()))
    }
    
    /// 解析存储值消息
    pub fn parse_store_value(&self, message: &ProtocolMessage) -> Result<StoreValueMessage, ProtocolError> {
        // 检查消息类型
        if message.header.message_type != MessageType::StoreValue {
            return Err(ProtocolError::InvalidMessage(
                format!("Expected StoreValue message, got {:?}", message.header.message_type)
            ));
        }
        
        // 反序列化存储值负载
        bincode::deserialize(&message.payload)
            .map_err(|e| ProtocolError::DeserializationError(e.to_string()))
    }
    
    /// 解析查找值消息
    pub fn parse_find_value(&self, message: &ProtocolMessage) -> Result<FindValueMessage, ProtocolError> {
        // 检查消息类型
        if message.header.message_type != MessageType::FindValue {
            return Err(ProtocolError::InvalidMessage(
                format!("Expected FindValue message, got {:?}", message.header.message_type)
            ));
        }
        
        // 反序列化查找值负载
        bincode::deserialize(&message.payload)
            .map_err(|e| ProtocolError::DeserializationError(e.to_string()))
    }
    
    /// 解析直接消息
    pub fn parse_direct_message(&self, message: &ProtocolMessage) -> Result<DirectMessagePayload, ProtocolError> {
        // 检查消息类型
        if message.header.message_type != MessageType::DirectMessage {
            return Err(ProtocolError::InvalidMessage(
                format!("Expected DirectMessage message, got {:?}", message.header.message_type)
            ));
        }
        
        // 反序列化直接消息负载
        bincode::deserialize(&message.payload)
            .map_err(|e| ProtocolError::DeserializationError(e.to_string()))
    }
    
    /// 解析分段消息
    pub fn parse_fragmented_message(&self, message: &ProtocolMessage) -> Result<FragmentedMessagePayload, ProtocolError> {
        // 检查消息类型
        if message.header.message_type != MessageType::FragmentedMessage {
            return Err(ProtocolError::InvalidMessage(
                format!("Expected FragmentedMessage message, got {:?}", message.header.message_type)
            ));
        }
        
        // 反序列化分段消息负载
        bincode::deserialize(&message.payload)
            .map_err(|e| ProtocolError::DeserializationError(e.to_string()))
    }
    
    /// 解析确认消息
    pub fn parse_ack(&self, message: &ProtocolMessage) -> Result<u32, ProtocolError> {
        // 检查消息类型
        if message.header.message_type != MessageType::Ack {
            return Err(ProtocolError::InvalidMessage(
                format!("Expected Ack message, got {:?}", message.header.message_type)
            ));
        }
        
        // 反序列化确认消息负载
        bincode::deserialize(&message.payload)
            .map_err(|e| ProtocolError::DeserializationError(e.to_string()))
    }
}
