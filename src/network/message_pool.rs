use crate::network::{Peer, PeerError, Protocol};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use thiserror::Error;
use log::{debug, error};
use rand::Rng;

#[derive(Error, Debug)]
pub enum MessagePoolError {
    #[error("Message too large: {0}")]
    MessageTooLarge(usize),
    
    #[error("Protocol error: {0}")]
    ProtocolError(#[from] crate::network::ProtocolError),
    
    #[error("Peer error: {0}")]
    PeerError(#[from] PeerError),
    
    #[error("Invalid fragment: {0}")]
    InvalidFragment(String),
    
    #[error("Incomplete message: {0}")]
    IncompleteMessage(String),
    
    #[error("Timeout")]
    Timeout,
}

/// 表示一个大型消息的片段
struct MessageFragment {
    /// 片段索引
    index: u16,
    
    /// 片段数据
    data: Vec<u8>,
}

/// 表示一个正在重组的大型消息
struct IncomingMessage {
    /// 原始消息ID
    original_message_id: u32,
    
    /// 发送者ID
    sender_id: String,
    
    /// 总片段数
    total_fragments: u16,
    
    /// 已接收的片段
    fragments: HashMap<u16, MessageFragment>,
    
    /// 最后更新时间
    last_updated: std::time::Instant,
}

impl IncomingMessage {
    /// 创建新的传入消息
    fn new(original_message_id: u32, sender_id: String, total_fragments: u16) -> Self {
        Self {
            original_message_id,
            sender_id,
            total_fragments,
            fragments: HashMap::new(),
            last_updated: std::time::Instant::now(),
        }
    }
    
    /// 添加片段
    fn add_fragment(&mut self, index: u16, data: Vec<u8>) {
        self.fragments.insert(index, MessageFragment { index, data });
        self.last_updated = std::time::Instant::now();
    }
    
    /// 检查是否所有片段都已接收
    fn is_complete(&self) -> bool {
        self.fragments.len() as u16 == self.total_fragments
    }
    
    /// 组装完整消息
    fn assemble(&self) -> Vec<u8> {
        // 按片段索引排序
        let mut sorted_fragments: Vec<_> = self.fragments.values().collect();
        sorted_fragments.sort_by_key(|f| f.index);
        
        // 合并所有片段数据
        let mut result = Vec::new();
        for fragment in sorted_fragments {
            result.extend_from_slice(&fragment.data);
        }
        
        result
    }
    
    /// 检查消息是否过期
    fn is_expired(&self, timeout: std::time::Duration) -> bool {
        self.last_updated.elapsed() > timeout
    }
}

/// 表示一个正在发送的大型消息
struct OutgoingMessage {
    /// 原始消息ID
    original_message_id: u32,
    
    /// 接收者ID
    recipient_id: String,
    
    /// 消息片段
    fragments: Vec<Vec<u8>>,
    
    /// 已确认的片段
    acknowledged: Vec<bool>,
    
    /// 最后更新时间
    last_updated: std::time::Instant,
}

impl OutgoingMessage {
    /// 创建新的发送消息
    fn new(original_message_id: u32, recipient_id: String, fragments: Vec<Vec<u8>>) -> Self {
        Self {
            original_message_id,
            recipient_id,
            acknowledged: vec![false; fragments.len()],
            fragments,
            last_updated: std::time::Instant::now(),
        }
    }
    
    /// 标记片段为已确认
    fn acknowledge_fragment(&mut self, index: u16) {
        if index as usize >= self.acknowledged.len() {
            return;
        }
        
        self.acknowledged[index as usize] = true;
        self.last_updated = std::time::Instant::now();
    }
    
    /// 检查是否所有片段都已确认
    fn is_complete(&self) -> bool {
        self.acknowledged.iter().all(|&ack| ack)
    }
    
    /// 获取未确认的片段
    fn get_unacknowledged_fragments(&self) -> Vec<(u16, &Vec<u8>)> {
        self.acknowledged.iter()
            .enumerate()
            .filter(|(_, &ack)| !ack)
            .map(|(i, _)| (i as u16, &self.fragments[i]))
            .collect()
    }
    
    /// 检查消息是否过期
    fn is_expired(&self, timeout: std::time::Duration) -> bool {
        self.last_updated.elapsed() > timeout
    }
}

/// 消息池管理大型消息的分片和重组
pub struct MessagePool {
    /// 最大消息大小
    max_message_size: usize,
    
    /// 片段大小
    fragment_size: usize,
    
    /// 传入消息
    incoming_messages: Arc<RwLock<HashMap<(String, u32), IncomingMessage>>>,
    
    /// 发送消息
    outgoing_messages: Arc<RwLock<HashMap<(String, u32), OutgoingMessage>>>,
    
    /// 消息超时
    message_timeout: std::time::Duration,
    
    /// 重试间隔
    retry_interval: std::time::Duration,
}

impl MessagePool {
    /// 创建新的消息池
    pub fn new(max_message_size: usize) -> Self {
        Self {
            max_message_size,
            fragment_size: 1024, // 默认片段大小
            incoming_messages: Arc::new(RwLock::new(HashMap::new())),
            outgoing_messages: Arc::new(RwLock::new(HashMap::new())),
            message_timeout: std::time::Duration::from_secs(300), // 5分钟超时
            retry_interval: std::time::Duration::from_secs(10), // 10秒重试间隔
        }
    }
    
    /// 设置片段大小
    pub fn set_fragment_size(&mut self, size: usize) {
        self.fragment_size = size;
    }
    
    /// 设置消息超时
    pub fn set_message_timeout(&mut self, timeout: std::time::Duration) {
        self.message_timeout = timeout;
    }
    
    /// 设置重试间隔
    pub fn set_retry_interval(&mut self, interval: std::time::Duration) {
        self.retry_interval = interval;
    }
    
    /// 发送大型消息
    pub async fn send_large_message(&self, peer: &Peer, data: &[u8]) -> Result<(), MessagePoolError> {
        // 检查消息大小
        if data.len() > self.max_message_size {
            return Err(MessagePoolError::MessageTooLarge(data.len()));
        }
        
        // 获取协议实例
        let mut protocol = Protocol::new(peer.get_id().to_string());
        
        // 生成原始消息ID
        let original_message_id = rand::thread_rng().gen();
        
        // 将消息分片
        let fragments = self.fragment_message(data);
        
        // 获取片段总数
        let fragment_count = fragments.len() as u16;
        
        // 获取接收者ID
        let recipient_id = peer.get_info().id.clone();
        
        // 创建发送消息记录
        {
            let mut outgoing = self.outgoing_messages.write().await;
            outgoing.insert(
                (recipient_id.clone(), original_message_id),
                OutgoingMessage::new(original_message_id, recipient_id.clone(), fragments.clone()),
            );
        }
        
        // 发送所有片段
        for (i, fragment) in fragments.iter().enumerate() {
            // 创建分段消息
            let message = protocol.create_fragmented_message(
                recipient_id.clone(),
                original_message_id,
                i as u16,
                fragment_count,
                fragment.clone(),
            )?;
            
            // 发送消息
            peer.send(&message).await?;
        }
        
        // 启动重试任务
        self.spawn_retry_task(peer.clone(), original_message_id, recipient_id);
        
        Ok(())
    }
    
    /// 处理传入的片段消息
    pub async fn handle_fragmented_message(
        &self,
        peer: &Peer,
        original_message_id: u32,
        fragment_index: u16,
        fragment_count: u16,
        fragment_data: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, MessagePoolError> {
        // 获取发送者ID
        let sender_id = peer.get_info().id.clone();
        
        // 添加片段
        let complete = {
            let mut incoming = self.incoming_messages.write().await;
            
            // 获取或创建传入消息记录
            let message = incoming.entry((sender_id.clone(), original_message_id))
                .or_insert_with(|| IncomingMessage::new(original_message_id, sender_id.clone(), fragment_count));
            
            // 检查片段索引是否有效
            if fragment_index >= fragment_count {
                return Err(MessagePoolError::InvalidFragment(
                    format!("Fragment index {} out of range (0-{})", fragment_index, fragment_count - 1)
                ));
            }
            
            // 添加片段
            message.add_fragment(fragment_index, fragment_data);
            
            // 检查是否完整
            message.is_complete()
        };
        
        // 如果消息完整，组装并返回
        if complete {
            // 获取完整消息
            let message_data = {
                let incoming = self.incoming_messages.read().await;
                let message = incoming.get(&(sender_id.clone(), original_message_id))
                    .ok_or_else(|| MessagePoolError::IncompleteMessage(
                        format!("Message {} from {} not found", original_message_id, sender_id)
                    ))?;
                
                message.assemble()
            };
            
            // 移除消息记录
            {
                let mut incoming = self.incoming_messages.write().await;
                incoming.remove(&(sender_id, original_message_id));
            }
            
            // 发送确认
            self.send_fragment_ack(peer, original_message_id, fragment_index).await?;
            
            Ok(Some(message_data))
        } else {
            // 发送确认
            self.send_fragment_ack(peer, original_message_id, fragment_index).await?;
            
            // 消息不完整，返回None
            Ok(None)
        }
    }
    
    /// 处理片段确认
    pub async fn handle_fragment_ack(
        &self,
        sender_id: String,
        original_message_id: u32,
        fragment_index: u16,
    ) -> Result<bool, MessagePoolError> {
        // 更新片段确认状态
        let complete = {
            let mut outgoing = self.outgoing_messages.write().await;
            
            // 获取发送消息记录
            if let Some(message) = outgoing.get_mut(&(sender_id.clone(), original_message_id)) {
                // 标记片段为已确认
                message.acknowledge_fragment(fragment_index);
                
                // 检查是否所有片段都已确认
                message.is_complete()
            } else {
                false
            }
        };
        
        // 如果所有片段都已确认，移除消息记录
        if complete {
            let mut outgoing = self.outgoing_messages.write().await;
            outgoing.remove(&(sender_id, original_message_id));
        }
        
        Ok(complete)
    }
    
    /// 发送片段确认
    async fn send_fragment_ack(
        &self,
        peer: &Peer,
        original_message_id: u32,
        _fragment_index: u16,
    ) -> Result<(), MessagePoolError> {
        // 获取协议实例
        let mut protocol = Protocol::new(peer.get_id().to_string());
        
        // 创建确认消息
        let ack_message = protocol.create_ack(
            peer.get_info().id.clone(),
            original_message_id,
        )?;
        
        // 发送确认消息
        peer.send(&ack_message).await?;
        
        Ok(())
    }
    
    /// 将消息分片
    fn fragment_message(&self, data: &[u8]) -> Vec<Vec<u8>> {
        let mut fragments = Vec::new();
        
        // 计算片段数
        let fragment_count = (data.len() + self.fragment_size - 1) / self.fragment_size;
        
        // 分片消息
        for i in 0..fragment_count {
            let start = i * self.fragment_size;
            let end = std::cmp::min(start + self.fragment_size, data.len());
            
            fragments.push(data[start..end].to_vec());
        }
        
        fragments
    }
    
    /// 清理过期消息
    pub async fn cleanup_expired(&self) {
        // 清理过期的传入消息
        {
            let mut incoming = self.incoming_messages.write().await;
            incoming.retain(|_, msg| !msg.is_expired(self.message_timeout));
        }
        
        // 清理过期的发送消息
        {
            let mut outgoing = self.outgoing_messages.write().await;
            outgoing.retain(|_, msg| !msg.is_expired(self.message_timeout));
        }
    }
    
    /// 启动重试任务
    fn spawn_retry_task(&self, peer: Peer, original_message_id: u32, recipient_id: String) {
        let outgoing_messages = self.outgoing_messages.clone();
        let retry_interval = self.retry_interval;
        let message_timeout = self.message_timeout;
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(retry_interval);
            
            loop {
                // 等待下一个间隔
                interval.tick().await;
                
                // 获取发送消息记录并获取未确认的片段
                // 先获取消息的状态
                let message_expired;
                let mut unacknowledged_fragments = Vec::new();
                
                {
                    let outgoing = outgoing_messages.read().await;
                    if let Some(message) = outgoing.get(&(recipient_id.clone(), original_message_id)) {
                        message_expired = message.is_expired(message_timeout);
                        
                        if !message_expired {
                            // 如果消息没有过期，复制其未确认的片段
                            unacknowledged_fragments = message.get_unacknowledged_fragments()
                                .into_iter()
                                .map(|(idx, data)| (idx, data.to_vec()))
                                .collect();
                        }
                    } else {
                        // 消息已完成或被移除
                        return;
                    }
                }
                
                // 如果消息过期，则从发送消息中移除
                if message_expired {
                    debug!("Message {} to {} expired", original_message_id, recipient_id);
                    let mut outgoing = outgoing_messages.write().await;
                    outgoing.remove(&(recipient_id.clone(), original_message_id));
                    return;
                }
                
                // 如果没有未确认的片段，退出
                if unacknowledged_fragments.is_empty() {
                    return;
                }
                
                // 计算片段总数，用于后续创建消息
                let total_fragments = unacknowledged_fragments.len() as u16;
                
                // 重新发送所有未确认的片段
                for (index, data) in &unacknowledged_fragments {
                    // 创建协议实例
                    let mut protocol = Protocol::new(peer.get_id().to_string());
                    
                    // 创建分段消息
                    match protocol.create_fragmented_message(
                        recipient_id.clone(),
                        original_message_id,
                        *index, // 解引用索引
                        total_fragments,
                        data.to_vec(),
                    ) {
                        Ok(message) => {
                            // 发送消息
                            if let Err(e) = peer.send(&message).await {
                                error!("Failed to retry fragment {} of message {} to {}: {}", 
                                    index, original_message_id, recipient_id, e);
                            }
                        },
                        Err(e) => {
                            error!("Failed to create retry fragment message: {}", e);
                        }
                    }
                }
            }
        });
    }
}
