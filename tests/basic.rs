//! Basic unit tests for ZeroEdge message functionality.
//!
//! These tests verify core message operations including signing, serialization,
//! and encryption/decryption.

use zero_edge::{  
    crypto::KeyPair,
    identity::UserId,
    message::{Message, MessageType, MessageEncryption},
};

/// Tests message signing and verification functionality.
///
/// This test ensures that messages can be properly signed with a private key
/// and then verified using the corresponding public key.
#[test]
fn test_message_sign_and_verify() {
    // Generate a keypair for signing
    let keypair = KeyPair::generate().expect("Failed to generate keypair");
    let sender_id = UserId([1; 32]);
    
    // Create a test message
    let mut msg = Message::new(
        MessageType::Direct,
        sender_id,
        None, // No recipient for this test
        keypair.public.clone(),
        b"hello".to_vec(),
        "text/plain".to_string(),
        0, // Sequence number
        None, // No expiry
    );
    
    // Sign and verify the message
    msg.sign(&keypair.secret).expect("Signing failed");
    assert!(msg.verify().is_ok(), "Message verification failed");
}

/// Tests message serialization and deserialization.
///
/// This test verifies that messages can be correctly converted to bytes
/// and then reconstructed from those bytes without data loss.
#[test]
fn test_message_to_bytes_and_from_bytes() {
    let keypair = KeyPair::generate().expect("Failed to generate keypair");
    let sender_id = UserId([1; 32]);
    
    // Create a test message
    let msg = Message::new(
        MessageType::Direct,
        sender_id,
        None, // No recipient for this test
        keypair.public.clone(),
        b"data".to_vec(),
        "text/plain".to_string(),
        1, // Sequence number
        None, // No expiry
    );
    
    // Serialize and deserialize the message
    let bytes = msg.to_bytes().expect("Serialization failed");
    let restored = Message::from_bytes(&bytes).expect("Deserialization failed");
    
    // Verify the restored message matches the original
    assert_eq!(restored.id, msg.id, "Message ID mismatch after serialization");
    assert_eq!(restored.content, msg.content, "Message content mismatch after serialization");
}

/// Tests end-to-end message encryption and decryption.
///
/// This test ensures that messages can be encrypted for a specific recipient
/// and then successfully decrypted by that recipient.
#[test]
fn test_message_encryption_decryption() {
    // Generate keypairs for sender and recipient
    let sender_keypair = KeyPair::generate().expect("Failed to generate sender keypair");
    let recipient_keypair = KeyPair::generate().expect("Failed to generate recipient keypair");
    
    let sender_id = UserId([1; 32]);
    let recipient_id = UserId([2; 32]);
    
    // Create a test message
    let msg = Message::new(
        MessageType::Direct,
        sender_id.clone(),
        Some(recipient_id.clone()),
        sender_keypair.public.clone(),
        b"secret".to_vec(),
        "text/plain".to_string(),
        2, // Sequence number
        None, // No expiry
    );
    
    // Encrypt the message for the recipient
    let encrypted = MessageEncryption::encrypt_message(
        &msg, 
        &recipient_keypair.public, 
        &sender_keypair.secret
    ).expect("Encryption failed");
    
    // Recipient decrypts the message
    let decrypted = MessageEncryption::decrypt_message(
        &encrypted, 
        &recipient_keypair.secret
    ).expect("Decryption failed");
    
    // Verify the decrypted message matches the original
    assert_eq!(decrypted.content, msg.content, "Message content changed during encryption/decryption");
    assert_eq!(decrypted.sender_id, msg.sender_id, "Sender ID changed during encryption/decryption");
    assert_eq!(decrypted.recipient_id, msg.recipient_id, "Recipient ID changed during encryption/decryption");
}
