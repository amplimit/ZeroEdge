use anyhow::Result;
use ed25519_dalek::{PublicKey as EdPublicKey, SecretKey as EdSecretKey};
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

#[derive(Error, Debug)]
pub enum KeyError {
    #[error("Key generation failed: {0}")]
    GenerationFailed(String),
    
    #[error("Key serialization failed: {0}")]
    SerializationFailed(String),
    
    #[error("Key deserialization failed: {0}")]
    DeserializationFailed(String),
}

/// Represents a public key in the ZeroEdge system.
#[derive(Clone)]
pub struct PublicKey {
    /// Ed25519 public key for signing
    signing_key: EdPublicKey,
    
    /// X25519 public key for encryption
    encryption_key: X25519PublicKey,
}

// 手动实现序列化和反序列化，因为ed25519_dalek::PublicKey没有实现Serialize/Deserialize
impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("PublicKey", 2)?;
        
        // 序列化Ed25519公钥
        let ed_key_bytes = self.signing_key.as_bytes();
        state.serialize_field("signing_key", ed_key_bytes)?;
        
        // 序列化X25519公钥
        let x_key_bytes = self.encryption_key.as_bytes();
        state.serialize_field("encryption_key", x_key_bytes)?;
        
        state.end()
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, MapAccess, Visitor};
        use std::fmt;
        
        struct PublicKeyVisitor;
        
        impl<'de> Visitor<'de> for PublicKeyVisitor {
            type Value = PublicKey;
            
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct PublicKey")
            }
            
            fn visit_map<V>(self, mut map: V) -> Result<PublicKey, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut signing_key_bytes = None;
                let mut encryption_key_bytes = None;
                
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "signing_key" => {
                            if signing_key_bytes.is_some() {
                                return Err(de::Error::duplicate_field("signing_key"));
                            }
                            signing_key_bytes = Some(map.next_value::<[u8; 32]>()?);
                        }
                        "encryption_key" => {
                            if encryption_key_bytes.is_some() {
                                return Err(de::Error::duplicate_field("encryption_key"));
                            }
                            encryption_key_bytes = Some(map.next_value::<[u8; 32]>()?);
                        }
                        _ => {
                            let _ = map.next_value::<serde::de::IgnoredAny>()?;
                        }
                    }
                }
                
                let signing_key_bytes = signing_key_bytes.ok_or_else(|| de::Error::missing_field("signing_key"))?;
                let encryption_key_bytes = encryption_key_bytes.ok_or_else(|| de::Error::missing_field("encryption_key"))?;
                
                let signing_key = EdPublicKey::from_bytes(&signing_key_bytes)
                    .map_err(|_| de::Error::custom("Invalid Ed25519 public key"))?;
                let encryption_key = X25519PublicKey::from(encryption_key_bytes);
                
                Ok(PublicKey {
                    signing_key,
                    encryption_key,
                })
            }
        }
        
        deserializer.deserialize_map(PublicKeyVisitor)
    }
}

impl PublicKey {
    /// Creates a new PublicKey from raw components
    pub fn new(signing_key: EdPublicKey, encryption_key: X25519PublicKey) -> Self {
        Self {
            signing_key,
            encryption_key,
        }
    }
    
    /// Creates a dummy PublicKey for testing purposes
    pub fn dummy() -> Self {
        // 创建一个全零的密钥用于测试
        let signing_key_bytes = [0u8; 32];
        let signing_key = EdPublicKey::from_bytes(&signing_key_bytes)
            .expect("Failed to create dummy signing key");
        
        let encryption_key_bytes = [0u8; 32];
        let encryption_key = X25519PublicKey::from(encryption_key_bytes);
        
        Self {
            signing_key,
            encryption_key,
        }
    }
    
    /// Returns the signing key
    pub fn signing_key(&self) -> &EdPublicKey {
        &self.signing_key
    }
    
    /// Returns the encryption key
    pub fn encryption_key(&self) -> &X25519PublicKey {
        &self.encryption_key
    }
    
    /// Converts the public key to a byte array for storage or transmission
    pub fn to_bytes(&self) -> Result<Vec<u8>, KeyError> {
        // 创建一个缓冲区来存储序列化的数据
        let mut buffer = Vec::with_capacity(64); // 两个32字节的密钥
        
        // 添加签名密钥
        buffer.extend_from_slice(self.signing_key.as_bytes());
        
        // 添加加密密钥
        buffer.extend_from_slice(&self.encryption_key.to_bytes());
        
        Ok(buffer)
    }
    
    /// Creates a public key from a byte array
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeyError> {
        // 检查字节数组长度是否正确
        if bytes.len() != 64 {
            return Err(KeyError::DeserializationFailed(format!("Expected 64 bytes, got {}", bytes.len())));
        }
        
        // 提取签名密钥（前32字节）
        let signing_key_bytes: [u8; 32] = bytes[0..32].try_into()
            .map_err(|_| KeyError::DeserializationFailed("Failed to extract signing key".to_string()))?;
        
        // 提取加密密钥（后32字节）
        let encryption_key_bytes: [u8; 32] = bytes[32..64].try_into()
            .map_err(|_| KeyError::DeserializationFailed("Failed to extract encryption key".to_string()))?;
        
        // 创建密钥对象
        let signing_key = EdPublicKey::from_bytes(&signing_key_bytes)
            .map_err(|e| KeyError::DeserializationFailed(e.to_string()))?;
        let encryption_key = X25519PublicKey::from(encryption_key_bytes);
        
        Ok(PublicKey {
            signing_key,
            encryption_key,
        })
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({}...)", hex::encode(&self.signing_key.as_bytes()[0..4]))
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        // 比较签名密钥和加密密钥的字节表示
        self.signing_key.as_bytes() == other.signing_key.as_bytes() &&
        self.encryption_key.as_bytes() == other.encryption_key.as_bytes()
    }
}

impl Eq for PublicKey {}

/// Represents a secret key in the ZeroEdge system.
// SecretKey不应该使用derive实现，需要手动实现序列化/反序列化
pub struct SecretKey {
    /// Ed25519 secret key for signing
    signing_key: EdSecretKey,
    
    /// X25519 secret key for encryption
    encryption_key: StaticSecret,
}

// 手动实现Clone trait
impl Clone for SecretKey {
    fn clone(&self) -> Self {
        // 由于EdSecretKey不支持Clone，我们需要从字节重新创建
        let signing_key_bytes = self.signing_key.as_bytes();
        let signing_key = EdSecretKey::from_bytes(signing_key_bytes)
            .expect("Failed to clone signing key");
            
        // StaticSecret支持Clone
        let encryption_key = self.encryption_key.clone();
        
        SecretKey {
            signing_key,
            encryption_key,
        }
    }
}

// 手动实现序列化和反序列化，因为Ed25519SecretKey没有实现Serialize/Deserialize
impl Serialize for SecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("SecretKey", 2)?;
        
        // 序列化Ed25519私钥 - 这里我们将私钥字节序列化，实际项目中应考虑加密存储
        let ed_key_bytes = self.signing_key.as_bytes();
        state.serialize_field("signing_key", ed_key_bytes)?;
        
        // 序列化X25519私钥
        let x_key_bytes = self.encryption_key.to_bytes();
        state.serialize_field("encryption_key", &x_key_bytes)?;
        
        state.end()
    }
}

impl<'de> Deserialize<'de> for SecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, MapAccess, Visitor};
        use std::fmt;
        
        struct SecretKeyVisitor;
        
        impl<'de> Visitor<'de> for SecretKeyVisitor {
            type Value = SecretKey;
            
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct SecretKey")
            }
            
            fn visit_map<V>(self, mut map: V) -> Result<SecretKey, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut signing_key_bytes = None;
                let mut encryption_key_bytes = None;
                
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "signing_key" => {
                            if signing_key_bytes.is_some() {
                                return Err(de::Error::duplicate_field("signing_key"));
                            }
                            signing_key_bytes = Some(map.next_value::<Vec<u8>>()?);
                        }
                        "encryption_key" => {
                            if encryption_key_bytes.is_some() {
                                return Err(de::Error::duplicate_field("encryption_key"));
                            }
                            encryption_key_bytes = Some(map.next_value::<Vec<u8>>()?);
                        }
                        _ => {
                            let _ = map.next_value::<serde::de::IgnoredAny>()?;
                        }
                    }
                }
                
                let signing_key_bytes = signing_key_bytes.ok_or_else(|| de::Error::missing_field("signing_key"))?;
                let encryption_key_bytes = encryption_key_bytes.ok_or_else(|| de::Error::missing_field("encryption_key"))?;
                
                let signing_key = EdSecretKey::from_bytes(&signing_key_bytes)
                    .map_err(|_| de::Error::custom("Invalid Ed25519 secret key"))?;
                
                let mut x_key_bytes = [0u8; 32];
                if encryption_key_bytes.len() >= 32 {
                    x_key_bytes.copy_from_slice(&encryption_key_bytes[0..32]);
                } else {
                    return Err(de::Error::custom("Invalid X25519 secret key length"));
                }
                
                let encryption_key = StaticSecret::from(x_key_bytes);
                
                Ok(SecretKey {
                    signing_key,
                    encryption_key,
                })
            }
        }
        
        deserializer.deserialize_map(SecretKeyVisitor)
    }
}

impl SecretKey {
    /// Creates a new SecretKey from raw components
    pub fn new(signing_key: EdSecretKey, encryption_key: StaticSecret) -> Self {
        Self {
            signing_key,
            encryption_key,
        }
    }
    
    /// Returns the signing key
    pub fn signing_key(&self) -> &EdSecretKey {
        &self.signing_key
    }
    
    /// Returns the encryption key
    pub fn encryption_key(&self) -> &StaticSecret {
        &self.encryption_key
    }
    
    /// Converts the secret key to a byte array for storage
    pub fn to_bytes(&self) -> Result<Vec<u8>, KeyError> {
        // 创建一个缓冲区来存储序列化的数据
        let mut buffer = Vec::with_capacity(64); // 两个32字节的密钥
        
        // 添加签名密钥
        buffer.extend_from_slice(self.signing_key.as_bytes());
        
        // 添加加密密钥
        buffer.extend_from_slice(&self.encryption_key.to_bytes());
        
        Ok(buffer)
    }
    
    /// Creates a secret key from a byte array
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeyError> {
        // 检查字节数组长度是否正确
        if bytes.len() != 64 {
            return Err(KeyError::DeserializationFailed(format!("Expected 64 bytes, got {}", bytes.len())));
        }
        
        // 提取签名密钥（前32字节）
        let signing_key_bytes: [u8; 32] = bytes[0..32].try_into()
            .map_err(|_| KeyError::DeserializationFailed("Failed to extract signing key".to_string()))?;
        
        // 提取加密密钥（后32字节）
        let encryption_key_bytes: [u8; 32] = bytes[32..64].try_into()
            .map_err(|_| KeyError::DeserializationFailed("Failed to extract encryption key".to_string()))?;
        
        // 创建密钥对象
        let signing_key = EdSecretKey::from_bytes(&signing_key_bytes)
            .map_err(|e| KeyError::DeserializationFailed(e.to_string()))?;
        let encryption_key = StaticSecret::from(encryption_key_bytes);
        
        Ok(SecretKey {
            signing_key,
            encryption_key,
        })
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretKey {{ <redacted> }}")
    }
}

/// Represents a key pair (public and secret keys) in the ZeroEdge system.
#[derive(Debug, Clone)]
#[derive(Serialize, Deserialize)]
pub struct KeyPair {
    pub public: PublicKey,
    pub secret: SecretKey,
}

impl KeyPair {
    /// Generates a new random key pair
    pub fn generate() -> Result<Self, KeyError> {
        // 生成随机字节作为秘钥
        let mut seed = [0u8; 32];
        rand::Rng::fill(&mut rand::thread_rng(), &mut seed);
        
        // 从随机字节创建Ed25519密钥对
        let signing_key = EdSecretKey::from_bytes(&seed)
            .map_err(|e| KeyError::GenerationFailed(e.to_string()))?;
        let verifying_key = EdPublicKey::from(&signing_key);
        
        // 使用相同的随机字节生成加密密钥对
        let encryption_secret = StaticSecret::from(seed);
        let encryption_public = X25519PublicKey::from(&encryption_secret);
        
        Ok(Self {
            public: PublicKey::new(verifying_key, encryption_public),
            secret: SecretKey::new(signing_key, encryption_secret),
        })
    }
    
    /// Creates a key pair from existing secret key
    pub fn from_secret(secret: SecretKey) -> Self {
        // 从EdSecretKey获取对应的EdPublicKey
        let verifying_key = EdPublicKey::from(&secret.signing_key);
        let encryption_public = X25519PublicKey::from(&secret.encryption_key);
        
        Self {
            public: PublicKey::new(verifying_key, encryption_public),
            secret,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = KeyPair::generate().expect("Failed to generate keypair");
        
        // Ensure we can access the public and secret keys
        let _public = &keypair.public;
        let _secret = &keypair.secret;
    }

    #[test]
    fn test_public_key_serialization() {
        let keypair = KeyPair::generate().expect("Failed to generate keypair");
        
        // Serialize and deserialize the public key
        let bytes = keypair.public.to_bytes().expect("Failed to serialize public key");
        let deserialized = PublicKey::from_bytes(&bytes).expect("Failed to deserialize public key");
        
        // Verify that the serialized and deserialized keys match
        // Note: We can't directly compare the keys due to lack of PartialEq implementation,
        // so we'd need to compare the serialized forms
        let reser = deserialized.to_bytes().expect("Failed to re-serialize public key");
        assert_eq!(bytes, reser);
    }
}
