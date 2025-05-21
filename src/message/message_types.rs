use crate::crypto::PublicKey;
use crate::identity::UserId;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum MessageError {
    #[error("Message construction failed: {0}")]
    ConstructionFailed(String),
    
    #[error("Message serialization failed: {0}")]
    SerializationFailed(String),
    
    #[error("Message validation failed: {0}")]
    ValidationFailed(String),
}

/// Status of a message's delivery
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageStatus {
    /// Message has been created but not yet sent
    Created,
    /// Message has been sent to the network
    Sent,
    /// Message has been delivered to recipient's device
    Delivered,
    /// Message has been read by recipient
    Read,
    /// Message failed to be delivered
    Failed,
}

/// Type of message
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageType {
    /// Direct message from one user to another
    Direct,
    /// Message sent to a group
    Group,
    /// System message (not sent by a user)
    System,
}

/// Base message struct containing common fields for all message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// Unique identifier for this message
    pub id: Uuid,
    
    /// Type of message
    pub message_type: MessageType,
    
    /// Time the message was created
    pub timestamp: u64,
    
    /// Sender's user ID
    pub sender_id: UserId,
    
    /// Recipient's user ID (optional, for direct messages)
    pub recipient_id: Option<UserId>,
    
    /// Sender's public key (for verification)
    pub sender_public_key: PublicKey,
    
    /// Message content (may be encrypted)
    pub content: Vec<u8>,
    
    /// Content type (e.g., "text/plain", "image/jpeg")
    pub content_type: String,
    
    /// Signature of the message
    pub signature: Vec<u8>,
    
    /// Sequence number from this sender (for ordering)
    pub sequence_number: u64,
    
    /// Optional reference to another message (for replies)
    pub references: Option<Uuid>,
}

impl Message {
    /// Creates a new message
    pub fn new(
        message_type: MessageType,
        sender_id: UserId,
        recipient_id: Option<UserId>,
        sender_public_key: PublicKey,
        content: Vec<u8>,
        content_type: String,
        sequence_number: u64,
        references: Option<Uuid>,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        Self {
            id: Uuid::new_v4(),
            message_type,
            timestamp: now,
            sender_id,
            recipient_id,
            sender_public_key,
            content,
            content_type,
            signature: Vec::new(), // Will be set by sign method
            sequence_number,
            references,
        }
    }
    
    /// Signs the message with the given secret key
    pub fn sign(&mut self, secret_key: &crate::crypto::SecretKey) -> Result<(), MessageError> {
        // Create a copy without the signature
        let mut message_copy = self.clone();
        message_copy.signature = Vec::new();
        
        // Serialize the message
        let message_bytes = bincode::serialize(&message_copy)
            .map_err(|e| MessageError::SerializationFailed(e.to_string()))?;
        
        // Sign the message
        let signature = crate::crypto::sign(secret_key, &message_bytes)
            .map_err(|e| MessageError::ConstructionFailed(e.to_string()))?;
        
        // Set the signature
        self.signature = signature;
        
        Ok(())
    }
    
    /// Verifies the message signature
    pub fn verify(&self) -> Result<(), MessageError> {
        // Create a copy without the signature
        let mut message_copy = self.clone();
        message_copy.signature = Vec::new();
        
        // Serialize the message
        let message_bytes = bincode::serialize(&message_copy)
            .map_err(|e| MessageError::SerializationFailed(e.to_string()))?;
        
        // Verify the signature
        crate::crypto::verify(
            &self.sender_public_key,
            &message_bytes,
            &self.signature
        ).map_err(|e| MessageError::ValidationFailed(e.to_string()))?;
        
        Ok(())
    }
    
    /// Converts the message to bytes for transmission
    pub fn to_bytes(&self) -> Result<Vec<u8>, MessageError> {
        bincode::serialize(self)
            .map_err(|e| MessageError::SerializationFailed(e.to_string()))
    }
    
    /// Creates a message from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MessageError> {
        bincode::deserialize(bytes)
            .map_err(|e| MessageError::SerializationFailed(e.to_string()))
    }
}

/// Direct message from one user to another
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectMessage {
    /// Base message
    pub message: Message,
    
    /// Recipient's user ID
    pub recipient_id: UserId,
    
    /// Recipient's public key (for encryption)
    pub recipient_public_key: PublicKey,
    
    /// Whether the message has been encrypted
    pub is_encrypted: bool,
}

impl DirectMessage {
    /// Creates a new direct message
    pub fn new(
        sender_id: UserId,
        sender_public_key: PublicKey,
        recipient_id: UserId,
        recipient_public_key: PublicKey,
        content: Vec<u8>,
        content_type: String,
        sequence_number: u64,
        references: Option<Uuid>,
    ) -> Self {
        let message = Message::new(
            MessageType::Direct,
            sender_id,
            Some(recipient_id.clone()),
            sender_public_key,
            content,
            content_type,
            sequence_number,
            references,
        );
        
        Self {
            message,
            recipient_id,
            recipient_public_key,
            is_encrypted: false,
        }
    }
    
    /// Encrypts the message content (if not already encrypted)
    pub fn encrypt(&mut self, _encryption_key: &[u8]) -> Result<(), MessageError> {
        if self.is_encrypted {
            return Ok(());
        }
        
        // The actual encryption will be implemented later
        // For now, we'll just mark it as encrypted
        self.is_encrypted = true;
        
        Ok(())
    }
    
    /// Decrypts the message content (if encrypted)
    pub fn decrypt(&mut self, _decryption_key: &[u8]) -> Result<(), MessageError> {
        if !self.is_encrypted {
            return Ok(());
        }
        
        // The actual decryption will be implemented later
        // For now, we'll just mark it as decrypted
        self.is_encrypted = false;
        
        Ok(())
    }
}

/// Group message sent to multiple recipients
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMessage {
    /// Base message
    pub message: Message,
    
    /// Group ID
    pub group_id: crate::message::GroupId,
    
    /// Group message sequence number
    pub group_sequence: u64,
    
    /// Whether the message has been encrypted
    pub is_encrypted: bool,
}

/// System message (not from a user)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMessage {
    /// Base message
    pub message: Message,
    
    /// Type of system message
    pub system_type: String,
    
    /// Target user ID (if applicable)
    pub target_id: Option<UserId>,
}
