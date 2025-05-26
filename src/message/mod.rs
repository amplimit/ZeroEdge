mod message_types;
mod encryption;
mod offline_storage;
mod delivery;
pub mod group_messaging; // Made this module public

pub use message_types::{
    Message, MessageType, MessageStatus, 
    DirectMessage, GroupMessage, SystemMessage
};
pub use encryption::{EncryptedMessage, MessageEncryption};
pub use offline_storage::{OfflineStorage, OfflineMessage};
pub use delivery::{DeliveryReceipt, DeliveryStatus};
pub use group_messaging::{GroupId, GroupInfo, GroupMembership};

/*
 * Message handling module for ZeroEdge
 * 
 * This module handles all aspects of messages in the system:
 * - Message construction and parsing
 * - End-to-end encryption
 * - Offline message storage
 * - Message delivery status tracking
 * - Group messaging
 */

