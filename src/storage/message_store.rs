use crate::storage::Database;
use crate::message::{Message, MessageType, MessageStatus};
use crate::identity::UserId;
use serde::{Serialize, Deserialize};
use thiserror::Error;
use log::error;
// 移除未使用的导入
// use log::{debug, info, warn};
use std::time::{SystemTime, Duration};
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum MessageStoreError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] crate::storage::DatabaseError),
    
    #[error("Message not found: {0}")]
    MessageNotFound(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("Invalid message: {0}")]
    InvalidMessage(String),
}

/// 消息索引结构
#[derive(Debug, Clone, Serialize, Deserialize)]
struct MessageIndex {
    /// 消息ID
    message_id: Uuid,
    
    /// 消息发送者
    sender_id: UserId,
    
    /// 消息接收者（可选，群消息为空）
    recipient_id: Option<UserId>,
    
    /// 消息类型
    message_type: MessageType,
    
    /// 消息状态
    status: MessageStatus,
    
    /// 时间戳
    timestamp: u64,
    
    /// 会话ID（对于一对一聊天是另一方的ID，对于群组是群组ID）
    conversation_id: String,
    
    /// 引用的消息ID（可选，回复消息时有效）
    references: Option<Uuid>,
    
    /// 序列号（用于排序）
    sequence: u64,
}

/// 消息存储
pub struct MessageStore {
    /// 数据库实例
    db: Database,
    
    /// 下一个序列号
    next_sequence: u64,
}

impl MessageStore {
    /// 创建新的消息存储
    pub fn new(db: &Database) -> Result<Self, MessageStoreError> {
        // 初始化消息表
        let _ = db.get_tree("messages")?;
        let _ = db.get_tree("message_indices")?;
        let _ = db.get_tree("conversations")?;
        
        // 加载最大序列号
        let sequences = db.scan_prefix("message_indices", b"seq_")?
            .map(|(_key, value)| {
                let seq_bytes = value.as_slice();
                if seq_bytes.len() >= 8 {
                    let mut bytes = [0u8; 8];
                    bytes.copy_from_slice(&seq_bytes[0..8]);
                    u64::from_be_bytes(bytes)
                } else {
                    0
                }
            })
            .collect::<Vec<_>>();
        
        let next_sequence = sequences.into_iter().max().unwrap_or(0) + 1;
        
        Ok(Self {
            db: db.clone(),
            next_sequence,
        })
    }
    
    /// 保存消息
    pub fn save_message(&mut self, message: &Message) -> Result<(), MessageStoreError> {
        // 序列化消息
        let message_data = bincode::serialize(message)
            .map_err(|e| MessageStoreError::SerializationError(e.to_string()))?;
        
        // 消息ID
        let message_id = message.id.as_bytes().to_vec();
        
        // 保存消息
        self.db.put("messages", &message_id, &message_data)?;
        
        // 确定会话ID
        let conversation_id = match message.message_type {
            MessageType::Direct => {
                // 直接消息，会话ID是对方的ID
                if let Some(recipient_id) = message.references.as_ref() {
                    recipient_id.to_string()
                } else {
                    return Err(MessageStoreError::InvalidMessage("Direct message without recipient".to_string()));
                }
            },
            MessageType::Group => {
                // 群组消息，会话ID是群组ID
                if let Some(group_id) = message.references.as_ref() {
                    format!("group:{}", group_id)
                } else {
                    return Err(MessageStoreError::InvalidMessage("Group message without group ID".to_string()));
                }
            },
            MessageType::System => {
                // 系统消息，会话ID是系统
                "system".to_string()
            },
        };
        
        // 获取当前时间戳
        let timestamp = message.timestamp;
        
        // 创建消息索引
        let index = MessageIndex {
            message_id: message.id,
            sender_id: message.sender_id.clone(),
            recipient_id: None, // 将在具体消息类型中设置
            message_type: message.message_type,
            status: MessageStatus::Created,
            timestamp,
            conversation_id: conversation_id.clone(),
            references: message.references,
            sequence: self.next_sequence,
        };
        
        // 序列化索引
        let index_data = bincode::serialize(&index)
            .map_err(|e| MessageStoreError::SerializationError(e.to_string()))?;
        
        // 保存消息索引
        self.db.put("message_indices", &message_id, &index_data)?;
        
        // 保存会话索引
        let conv_key = format!("conv_{}", conversation_id).into_bytes();
        let msg_key = format!("{}_{}", timestamp, message.id).into_bytes();
        self.db.put("conversations", &msg_key, &conv_key)?;
        
        // 增加序列号
        self.next_sequence += 1;
        
        // 保存序列号
        let seq_key = format!("seq_{}", self.next_sequence - 1).into_bytes();
        let seq_value = self.next_sequence.to_be_bytes();
        self.db.put("message_indices", &seq_key, &seq_value)?;
        
        Ok(())
    }
    
    /// 获取消息
    pub fn get_message(&self, message_id: &Uuid) -> Result<Message, MessageStoreError> {
        // 获取消息
        let message_data = self.db.get("messages", message_id.as_bytes())?
            .ok_or_else(|| MessageStoreError::MessageNotFound(message_id.to_string()))?;
        
        // 反序列化消息
        let message: Message = bincode::deserialize(&message_data)
            .map_err(|e| MessageStoreError::SerializationError(e.to_string()))?;
        
        Ok(message)
    }
    
    /// 更新消息状态
    pub fn update_message_status(&self, message_id: &Uuid, status: MessageStatus) -> Result<(), MessageStoreError> {
        // 获取消息索引
        let index_data = self.db.get("message_indices", message_id.as_bytes())?
            .ok_or_else(|| MessageStoreError::MessageNotFound(message_id.to_string()))?;
        
        // 反序列化索引
        let mut index: MessageIndex = bincode::deserialize(&index_data)
            .map_err(|e| MessageStoreError::SerializationError(e.to_string()))?;
        
        // 更新状态
        index.status = status;
        
        // 序列化索引
        let index_data = bincode::serialize(&index)
            .map_err(|e| MessageStoreError::SerializationError(e.to_string()))?;
        
        // 保存消息索引
        self.db.put("message_indices", message_id.as_bytes(), &index_data)?;
        
        Ok(())
    }
    
    /// 获取会话消息
    pub fn get_conversation_messages(
        &self,
        conversation_id: &str,
        limit: usize,
        before: Option<u64>,
    ) -> Result<Vec<Message>, MessageStoreError> {
        // 构造前缀
        let prefix = format!("conv_{}", conversation_id).into_bytes();
        
        // 查询符合前缀的所有会话记录
        let mut messages = Vec::new();
        
        for (key, _value) in self.db.scan_prefix("conversations", &prefix)? {
            // 解析时间戳和消息ID
            let key_str = String::from_utf8_lossy(&key);
            let parts: Vec<&str> = key_str.split('_').collect();
            
            if parts.len() >= 2 {
                let timestamp = parts[0].parse::<u64>().unwrap_or(0);
                
                // 如果指定了时间戳，跳过较新的消息
                if let Some(before_ts) = before {
                    if timestamp >= before_ts {
                        continue;
                    }
                }
                
                // 尝试解析消息ID
                if let Ok(message_id) = Uuid::parse_str(parts[1]) {
                    // 获取消息
                    if let Ok(message) = self.get_message(&message_id) {
                        messages.push(message);
                    }
                }
            }
        }
        
        // 按时间戳降序排序
        messages.sort_by(|a, b| {
            // 使用安全的方式访问字段
            let a_time = a.timestamp;
            let b_time = b.timestamp;
            b_time.cmp(&a_time)
        });
        
        // 限制数量
        if messages.len() > limit {
            messages.truncate(limit);
        }
        
        Ok(messages)
    }
    
    /// 获取未读消息数量
    pub fn get_unread_count(&self, conversation_id: &str) -> Result<usize, MessageStoreError> {
        // 构造前缀
        let prefix = format!("conv_{}", conversation_id).into_bytes();
        
        // 查询符合前缀的所有会话记录
        let mut count = 0;
        
        for (key, _) in self.db.scan_prefix("conversations", &prefix)? {
            // 解析消息ID
            let key_str = String::from_utf8_lossy(&key);
            let parts: Vec<&str> = key_str.split('_').collect();
            
            if parts.len() >= 2 {
                if let Ok(message_id) = Uuid::parse_str(parts[1]) {
                    // 获取消息索引
                    if let Ok(Some(index_data)) = self.db.get("message_indices", message_id.as_bytes()) {
                        // 反序列化索引
                        if let Ok(index) = bincode::deserialize::<MessageIndex>(&index_data) {
                            // 检查状态
                            if index.status != MessageStatus::Read {
                                count += 1;
                            }
                        }
                    }
                }
            }
        }
        
        Ok(count)
    }
    
    /// 标记会话所有消息为已读
    pub fn mark_conversation_as_read(&self, conversation_id: &str) -> Result<usize, MessageStoreError> {
        // 构造前缀
        let prefix = format!("conv_{}", conversation_id).into_bytes();
        
        // 查询符合前缀的所有会话记录
        let mut count = 0;
        
        for (key, _) in self.db.scan_prefix("conversations", &prefix)? {
            // 解析消息ID
            let key_str = String::from_utf8_lossy(&key);
            let parts: Vec<&str> = key_str.split('_').collect();
            
            if parts.len() >= 2 {
                if let Ok(message_id) = Uuid::parse_str(parts[1]) {
                    // 更新消息状态
                    if let Ok(()) = self.update_message_status(&message_id, MessageStatus::Read) {
                        count += 1;
                    }
                }
            }
        }
        
        Ok(count)
    }
    
    /// 删除消息
    pub fn delete_message(&self, message_id: &Uuid) -> Result<(), MessageStoreError> {
        // 获取消息索引
        let index_data = self.db.get("message_indices", message_id.as_bytes())?
            .ok_or_else(|| MessageStoreError::MessageNotFound(message_id.to_string()))?;
        
        // 反序列化索引
        let index: MessageIndex = bincode::deserialize(&index_data)
            .map_err(|e| MessageStoreError::SerializationError(e.to_string()))?;
        
        // 删除会话索引
        let _conv_key = format!("conv_{}", index.conversation_id).into_bytes();
        let msg_key = format!("{}_{}", index.timestamp, message_id).into_bytes();
        self.db.delete("conversations", &msg_key)?;
        
        // 删除消息索引
        self.db.delete("message_indices", message_id.as_bytes())?;
        
        // 删除消息
        self.db.delete("messages", message_id.as_bytes())?;
        
        Ok(())
    }
    
    /// 删除会话所有消息
    pub fn delete_conversation(&self, conversation_id: &str) -> Result<usize, MessageStoreError> {
        // 构造前缀
        let prefix = format!("conv_{}", conversation_id).into_bytes();
        
        // 查询符合前缀的所有会话记录
        let mut count = 0;
        
        // 先收集所有符合条件的键
        let keys: Vec<Vec<u8>> = self.db.scan_prefix("conversations", &prefix)?
            .map(|(key, _)| key)
            .collect();
        
        // 然后删除这些消息
        for key in keys {
            // 解析消息ID
            let key_str = String::from_utf8_lossy(&key);
            let parts: Vec<&str> = key_str.split('_').collect();
            
            if parts.len() >= 2 {
                if let Ok(message_id) = Uuid::parse_str(parts[1]) {
                    // 删除消息
                    if let Ok(()) = self.delete_message(&message_id) {
                        count += 1;
                    }
                }
            }
            
            // 删除会话索引
            self.db.delete("conversations", &key)?;
        }
        
        Ok(count)
    }
    
    /// 获取所有会话ID
    pub fn get_all_conversations(&self) -> Result<Vec<String>, MessageStoreError> {
        let mut conversations = std::collections::HashSet::new();
        
        // 扫描所有索引
        for (_, index_data) in self.db.scan_prefix("message_indices", &[])? {
            // 反序列化索引
            if let Ok(index) = bincode::deserialize::<MessageIndex>(&index_data) {
                conversations.insert(index.conversation_id);
            }
        }
        
        Ok(conversations.into_iter().collect())
    }
    
    /// 清理过期消息
    pub fn cleanup_old_messages(&self, max_age: Duration) -> Result<usize, MessageStoreError> {
        // 获取当前时间戳
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        // 计算截止时间戳
        let cutoff = now.saturating_sub(max_age.as_secs());
        
        // 扫描所有索引
        let mut deleted_count = 0;
        
        // 先收集所有符合条件的消息ID
        let message_ids: Vec<Uuid> = self.db.scan_prefix("message_indices", &[])?
            .filter_map(|(_, index_data)| {
                // 反序列化索引
                if let Ok(index) = bincode::deserialize::<MessageIndex>(&index_data) {
                    // 检查时间戳
                    if index.timestamp < cutoff {
                        return Some(index.message_id);
                    }
                }
                None
            })
            .collect();
        
        // 删除这些消息
        for message_id in message_ids {
            if let Ok(()) = self.delete_message(&message_id) {
                deleted_count += 1;
            }
        }
        
        Ok(deleted_count)
    }
}
