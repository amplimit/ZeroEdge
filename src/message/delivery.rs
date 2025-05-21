use crate::identity::UserId;
use serde::{Serialize, Deserialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// 消息递送状态
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeliveryStatus {
    /// 已发送但未确认
    Sent,
    
    /// 已递送到接收者设备
    Delivered,
    
    /// 已被接收者查看
    Read,
    
    /// 递送失败
    Failed,
    
    /// 待递送
    Pending,
}

/// 递送回执
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryReceipt {
    /// 消息ID
    pub message_id: uuid::Uuid,
    
    /// 发送者ID
    pub sender_id: UserId,
    
    /// 接收者ID
    pub recipient_id: UserId,
    
    /// 递送状态
    pub status: DeliveryStatus,
    
    /// 递送时间戳
    pub timestamp: u64,
    
    /// 交互ID（用于关联多个回执）
    pub transaction_id: Option<uuid::Uuid>,
    
    /// 状态描述
    pub description: Option<String>,
}

impl DeliveryReceipt {
    /// 创建新的递送回执
    pub fn new(
        message_id: uuid::Uuid,
        sender_id: UserId,
        recipient_id: UserId,
        status: DeliveryStatus,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        Self {
            message_id,
            sender_id,
            recipient_id,
            status,
            timestamp: now,
            transaction_id: None,
            description: None,
        }
    }
    
    /// 添加交互ID
    pub fn with_transaction(mut self, transaction_id: uuid::Uuid) -> Self {
        self.transaction_id = Some(transaction_id);
        self
    }
    
    /// 添加状态描述
    pub fn with_description(mut self, description: String) -> Self {
        self.description = Some(description);
        self
    }
    
    /// 更新递送状态
    pub fn update_status(&mut self, status: DeliveryStatus) {
        self.status = status;
        self.timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }
    
    /// 检查是否为最终状态
    pub fn is_final(&self) -> bool {
        matches!(self.status, DeliveryStatus::Delivered | DeliveryStatus::Read | DeliveryStatus::Failed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_delivery_receipt_creation() {
        let message_id = uuid::Uuid::new_v4();
        let sender_id = UserId([1; 32]);
        let recipient_id = UserId([2; 32]);
        
        let receipt = DeliveryReceipt::new(
            message_id,
            sender_id.clone(),
            recipient_id.clone(),
            DeliveryStatus::Sent,
        );
        
        assert_eq!(receipt.message_id, message_id);
        assert_eq!(receipt.sender_id, sender_id);
        assert_eq!(receipt.recipient_id, recipient_id);
        assert_eq!(receipt.status, DeliveryStatus::Sent);
        assert!(receipt.transaction_id.is_none());
        assert!(receipt.description.is_none());
    }
    
    #[test]
    fn test_delivery_receipt_update() {
        let mut receipt = DeliveryReceipt::new(
            uuid::Uuid::new_v4(),
            UserId([1; 32]),
            UserId([2; 32]),
            DeliveryStatus::Sent,
        );
        
        // 记录原始时间戳
        let original_timestamp = receipt.timestamp;
        
        // 等待一小段时间
        std::thread::sleep(std::time::Duration::from_millis(10));
        
        // 更新状态
        receipt.update_status(DeliveryStatus::Delivered);
        
        assert_eq!(receipt.status, DeliveryStatus::Delivered);
        assert!(receipt.timestamp > original_timestamp);
    }
    
    #[test]
    fn test_final_status() {
        let receipt1 = DeliveryReceipt::new(
            uuid::Uuid::new_v4(),
            UserId([1; 32]),
            UserId([2; 32]),
            DeliveryStatus::Sent,
        );
        
        let receipt2 = DeliveryReceipt::new(
            uuid::Uuid::new_v4(),
            UserId([1; 32]),
            UserId([2; 32]),
            DeliveryStatus::Delivered,
        );
        
        let receipt3 = DeliveryReceipt::new(
            uuid::Uuid::new_v4(),
            UserId([1; 32]),
            UserId([2; 32]),
            DeliveryStatus::Failed,
        );
        
        assert!(!receipt1.is_final());
        assert!(receipt2.is_final());
        assert!(receipt3.is_final());
    }
}
