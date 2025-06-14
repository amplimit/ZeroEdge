//! Integration tests for ZeroEdge message flow.
//!
//! These tests verify the complete flow of message processing, including
//! encryption, offline storage, sharding, and reconstruction.

use std::time::Duration;

use zero_edge::{
    crypto::KeyPair,
    dht::NodeId,
    identity::UserId,
    message::{
        EncryptedMessage, Message, MessageEncryption, MessagePriority, 
        MessageType, OfflineMessage, OfflineStorage,
    },
};

/// Tests the full offline message flow from encryption to storage to retrieval.
///
/// This test simulates a complete end-to-end scenario where a message is:
/// 1. Created and signed
/// 2. Encrypted for a recipient
/// 3. Stored as an offline message
/// 4. Sharded for distributed storage
/// 5. Rebuilt from shards (with fault tolerance)
/// 6. Decrypted by the recipient
#[test]
fn test_full_offline_encrypt_store_retrieve_flow() {
    // Setup keypairs and IDs
    let sender_keypair = KeyPair::generate().expect("Failed to generate sender keypair");
    let recipient_keypair = KeyPair::generate().expect("Failed to generate recipient keypair");
    let sender_id = UserId([1; 32]);
    let recipient_id = UserId([2; 32]);

    // Step 1: Create and sign message
    let mut msg = Message::new(
        MessageType::Direct,
        sender_id.clone(),
        Some(recipient_id.clone()),
        sender_keypair.public.clone(),
        b"Integration test".to_vec(),
        "text/plain".to_string(),
        1, // Sequence number
        None, // No expiry
    );
    msg.sign(&sender_keypair.secret).expect("Failed to sign message");
    msg.verify().expect("Failed to verify message signature");

    // Step 2: Encrypt message for recipient
    let encrypted_msg = MessageEncryption::encrypt_message(
        &msg, 
        &recipient_keypair.public, 
        &sender_keypair.secret
    ).expect("Failed to encrypt message");
    
    // Verify encryption worked correctly
    let decrypted_msg = MessageEncryption::decrypt_message(
        &encrypted_msg, 
        &recipient_keypair.secret
    ).expect("Failed to decrypt message");
    assert_eq!(decrypted_msg.content, msg.content, "Message content changed during encryption");

    // Step 3: Create offline message (for storage when recipient is offline)
    let mut offline_msg = OfflineMessage::new(
        recipient_id.clone(),
        sender_id.clone(),
        encrypted_msg.encrypted_content.clone(),
        encrypted_msg.content_type.clone(),
        Duration::from_secs(60), // 1 minute TTL
        MessagePriority::Normal,
    );
    
    // Sign the offline message for authenticity
    offline_msg.sign(&sender_keypair.secret).expect("Failed to sign offline message");
    offline_msg.verify(&sender_keypair.public).expect("Failed to verify offline message signature");

    // Step 4: Shard the message for distributed storage with fault tolerance
    let storage = OfflineStorage::new(NodeId::random(), 1024);
    let shards = storage.shard_message(&offline_msg, &sender_keypair)
        .expect("Failed to shard message");
    
    // Step 5: Rebuild message from shards (simulating one shard is lost)
    // This tests the Reed-Solomon error correction capability
    let available_shards = &shards[..shards.len()-1]; // Simulate loss of one shard
    let rebuilt_msg = storage.rebuild_message(available_shards)
        .expect("Failed to rebuild message from shards");
    
    // Verify rebuilt message matches original
    assert_eq!(rebuilt_msg.message_id, offline_msg.message_id, 
        "Message ID changed during rebuild");
    rebuilt_msg.verify(&sender_keypair.public)
        .expect("Failed to verify rebuilt message signature");

    // Step 6: Recipient decrypts the rebuilt message
    let recipient_encrypted_msg = EncryptedMessage::new(
        recipient_id.clone(),
        sender_id.clone(),
        sender_keypair.public.clone(),
        rebuilt_msg.encrypted_content.clone(),
        rebuilt_msg.content_type.clone()
    );
    
    let final_decrypted_msg = MessageEncryption::decrypt_message(
        &recipient_encrypted_msg, 
        &recipient_keypair.secret
    ).expect("Failed to decrypt rebuilt message");
    
    // Verify the final decrypted message matches the original
    assert_eq!(final_decrypted_msg.content, msg.content, 
        "Message content changed through the full offline flow");
}