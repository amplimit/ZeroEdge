use zero_edge::{
    crypto::KeyPair,
    identity::UserId,
    message::{Message, MessageType, MessageEncryption},
};


#[test]
fn test_message_sign_and_verify() {
    let kp = KeyPair::generate().unwrap();
    let sender_id = UserId([1; 32]);
    let mut msg = Message::new(
        MessageType::Direct,
        sender_id.clone(),
        None,
        kp.public.clone(),
        b"hello".to_vec(),
        "text/plain".to_string(),
        0,
        None,
    );
    msg.sign(&kp.secret).expect("Signing failed");
    assert!(msg.verify().is_ok());
}

#[test]
fn test_message_to_bytes_and_from_bytes() {
    let kp = KeyPair::generate().unwrap();
    let sender_id = UserId([1; 32]);
    let msg = Message::new(
        MessageType::Direct,
        sender_id.clone(),
        None,
        kp.public.clone(),
        b"data".to_vec(),
        "text/plain".to_string(),
        1,
        None,
    );
    let bytes = msg.to_bytes().expect("Serialization failed");
    let restored = Message::from_bytes(&bytes).expect("Deserialization failed");
    assert_eq!(restored.id, msg.id);
    assert_eq!(restored.content, msg.content);
}

#[test]
fn test_message_encryption_decryption() {
    let sender_kp = KeyPair::generate().unwrap();
    let recipient_kp = KeyPair::generate().unwrap();
    let sender_id = UserId([1; 32]);
    let recipient_id = UserId([2; 32]);
    let msg = Message::new(
        MessageType::Direct,
        sender_id.clone(),
        Some(recipient_id.clone()),
        sender_kp.public.clone(),
        b"secret".to_vec(),
        "text/plain".to_string(),
        2,
        None,
    );
    let encrypted = MessageEncryption::encrypt_message(&msg, &recipient_kp.public, &sender_kp.secret)
        .expect("Encryption failed");
    let decrypted = MessageEncryption::decrypt_message(&encrypted, &recipient_kp.secret)
        .expect("Decryption failed");
    assert_eq!(decrypted.content, msg.content);
    assert_eq!(decrypted.sender_id, msg.sender_id);
    assert_eq!(decrypted.recipient_id, msg.recipient_id);
}
