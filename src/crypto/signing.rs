use crate::crypto::{PublicKey, SecretKey};
use thiserror::Error;
use ed25519_dalek::Verifier;

#[derive(Error, Debug)]
pub enum SignatureError {
    #[error("Signing failed: {0}")]
    SigningFailed(String),
    
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
    
    #[error("Invalid key: {0}")]
    InvalidKey(String),
}

/// 使用私钥签名消息
pub fn sign(secret_key: &SecretKey, message: &[u8]) -> Result<Vec<u8>, SignatureError> {
    // 获取Ed25519签名密钥
    let signing_key = secret_key.signing_key();
    
    // 从密钥创建ExpandedSecretKey
    let expanded_key = ed25519_dalek::ExpandedSecretKey::from(signing_key);
    
    // 获取对应的公钥
    let public_key = ed25519_dalek::PublicKey::from(signing_key);
    
    // 对消息进行签名
    let signature = expanded_key.sign(message, &public_key).to_bytes().to_vec();
    
    Ok(signature)
}

/// 使用公钥验证签名
pub fn verify(public_key: &PublicKey, message: &[u8], signature: &[u8]) -> Result<(), SignatureError> {
    // 检查签名长度
    if signature.len() != 64 {
        return Err(SignatureError::VerificationFailed("Invalid signature length".to_string()));
    }
    
    // 获取Ed25519验证密钥
    let verifying_key = public_key.signing_key();
    
    // 从字节数组转换为签名对象
    // 需要把任意字节序列转换为64字节数组
    if signature.len() != 64 {
        return Err(SignatureError::VerificationFailed("Invalid signature length".to_string()));
    }
    
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(signature);
    
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes)
        .map_err(|e| SignatureError::VerificationFailed(e.to_string()))?;
    
    // 验证签名
    verifying_key.verify(message, &sig)
        .map_err(|e| SignatureError::VerificationFailed(format!("Verification failed: {}", e)))?;
    
    Ok(())
}

/// 生成消息摘要（哈希）
pub fn hash_message(message: &[u8]) -> Vec<u8> {
    let digest = ring::digest::digest(&ring::digest::SHA256, message);
    digest.as_ref().to_vec()
}

/// 对较大的消息使用哈希后签名
pub fn sign_hashed(secret_key: &SecretKey, message: &[u8]) -> Result<Vec<u8>, SignatureError> {
    // 先计算消息的哈希
    let message_hash = hash_message(message);
    
    // 对哈希签名
    sign(secret_key, &message_hash)
}

/// 对较大的消息验证哈希后的签名
pub fn verify_hashed(public_key: &PublicKey, message: &[u8], signature: &[u8]) -> Result<(), SignatureError> {
    // 先计算消息的哈希
    let message_hash = hash_message(message);
    
    // 验证签名
    verify(public_key, &message_hash, signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;
    
    #[test]
    fn test_sign_verify() {
        // 生成密钥对
        let keypair = KeyPair::generate().unwrap();
        
        // 测试消息
        let message = b"Hello, world! This is a test message.";
        
        // 签名消息
        let signature = sign(&keypair.secret, message).unwrap();
        
        // 验证签名
        let result = verify(&keypair.public, message, &signature);
        
        // 验证成功
        assert!(result.is_ok());
        
        // 更改消息应导致验证失败
        let altered_message = b"Hello, world! This is an altered message.";
        let result = verify(&keypair.public, altered_message, &signature);
        
        // 验证失败
        assert!(result.is_err());
    }
    
    #[test]
    fn test_sign_verify_hashed() {
        // 生成密钥对
        let keypair = KeyPair::generate().unwrap();
        
        // 测试消息
        let message = b"Hello, world! This is a test message.";
        
        // 签名消息
        let signature = sign_hashed(&keypair.secret, message).unwrap();
        
        // 验证签名
        let result = verify_hashed(&keypair.public, message, &signature);
        
        // 验证成功
        assert!(result.is_ok());
        
        // 更改消息应导致验证失败
        let altered_message = b"Hello, world! This is an altered message.";
        let result = verify_hashed(&keypair.public, altered_message, &signature);
        
        // 验证失败
        assert!(result.is_err());
    }
}
