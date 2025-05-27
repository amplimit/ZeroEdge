use zero_edge::{
    crypto::{KeyPair, encrypt, decrypt},
    dht::NodeId,
    identity::UserId,
    message::{Message, MessageType, MessageEncryption, OfflineMessage, OfflineStorage, MessagePriority},
};
use std::time::Duration;

#[test]
fn test_full_offline_encrypt_store_retrieve_flow() {
    // Setup keypairs and IDs
    let sender_kp = KeyPair::generate().unwrap();
    let recipient_kp = KeyPair::generate().unwrap();
    let sender_id = UserId([1; 32]);
    let recipient_id = UserId([2; 32]);

    // Create and sign message
    let mut msg = Message::new(
        MessageType::Direct,
        sender_id.clone(),
        Some(recipient_id.clone()),
        sender_kp.public.clone(),
        b"Integration test".to_vec(),
        "text/plain".to_string(),
        1,
        None,
    );
    msg.sign(&sender_kp.secret).unwrap();
    msg.verify().unwrap();

    // Encrypt message
    let encrypted_msg = MessageEncryption::encrypt_message(&msg, &recipient_kp.public, &sender_kp.secret).unwrap();
    let decrypted_msg = MessageEncryption::decrypt_message(&encrypted_msg, &recipient_kp.secret).unwrap();
    assert_eq!(decrypted_msg.content, msg.content);

    // Offline message creation and verify
    let mut offline = OfflineMessage::new(
        recipient_id.clone(),
        sender_id.clone(),
        encrypted_msg.encrypted_content.clone(),
        encrypted_msg.content_type.clone(),
        Duration::from_secs(60),
        MessagePriority::Normal,
    );
    offline.sign(&sender_kp.secret).unwrap();
    offline.verify(&sender_kp.public).unwrap();

    // Shard and rebuild with one missing shard
    let mut storage = OfflineStorage::new(NodeId::random(), 1024);
    let shards = storage.shard_message(&offline, &sender_kp).unwrap();
    let rebuilt = storage.rebuild_message(&shards[..shards.len()-1]).unwrap();
    assert_eq!(rebuilt.message_id, offline.message_id);
    rebuilt.verify(&sender_kp.public).unwrap();

    // Decrypt rebuilt encrypted content and reconstruct message
    let plaintext = decrypt(&recipient_kp.secret, &sender_kp.public, &rebuilt.encrypted_content).unwrap();
    let recovered = Message::from_bytes(&plaintext).unwrap();
    assert_eq!(recovered.content, msg.content);
}