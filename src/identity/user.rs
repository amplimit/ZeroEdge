use crate::crypto::{KeyPair, PublicKey};
use serde::{Deserialize, Serialize};
// 移除未使用的导入
// use ed25519_dalek::Signer;
use std::fmt;
use std::time::SystemTime;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum UserIdentityError {
    #[error("Identity creation failed: {0}")]
    CreationFailed(String),
    
    #[error("Identity verification failed: {0}")]
    VerificationFailed(String),
    
    #[error("Identity operation failed: {0}")]
    OperationFailed(String),
}

/// Unique identifier for a user
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UserId(pub [u8; 32]);

impl UserId {
    /// Derives a user ID from a public key
    pub fn from_public_key(public_key: &PublicKey) -> Result<Self, UserIdentityError> {
        let key_bytes = public_key.to_bytes()
            .map_err(|e| UserIdentityError::CreationFailed(e.to_string()))?;
        
        let mut hasher = ring::digest::Context::new(&ring::digest::SHA256);
        hasher.update(&key_bytes);
        let digest = hasher.finish();
        
        let mut id = [0u8; 32];
        id.copy_from_slice(digest.as_ref());
        
        Ok(Self(id))
    }
    
    /// Creates a new random UserId
    pub fn new_random() -> Self {
        let mut id = [0u8; 32];
        // 使用 rand::Rng trait 的 fill 方法
        rand::Rng::fill(&mut rand::thread_rng(), &mut id);
        Self(id)
    }
}

impl fmt::Debug for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UserId({})", hex::encode(&self.0[..6]))
    }
}

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

/// User's public profile information
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserProfile {
    /// The user's display name
    pub display_name: String,
    
    /// Optional user-provided status message
    pub status: Option<String>,
    
    /// Profile picture hash (if any)
    pub avatar_hash: Option<String>,
    
    /// When this profile was last updated
    pub last_updated: SystemTime,
    
    /// Profile version number (incremented on updates)
    pub version: u64,
    
    /// Proof that this profile belongs to the user (signature)
    pub signature: Vec<u8>,
}

impl UserProfile {
    /// Creates a new user profile
    pub fn new(display_name: String) -> Self {
        Self {
            display_name,
            status: None,
            avatar_hash: None,
            last_updated: SystemTime::now(),
            version: 1,
            signature: Vec::new(),
        }
    }
    
    /// Signs the profile with the given keypair
    pub fn sign(&mut self, keypair: &KeyPair) -> Result<(), UserIdentityError> {
        // Create a copy without the signature
        let mut profile_copy = self.clone();
        profile_copy.signature = Vec::new();
        
        // Serialize the profile
        let profile_bytes = bincode::serialize(&profile_copy)
            .map_err(|e| UserIdentityError::OperationFailed(e.to_string()))?;
        
        // Sign the profile
        self.signature = crate::crypto::sign(
            &keypair.secret, 
            &profile_bytes
        ).map_err(|e| UserIdentityError::OperationFailed(e.to_string()))?;
        
        Ok(())
    }
    
    /// Verifies the profile signature
    pub fn verify(&self, public_key: &PublicKey) -> Result<(), UserIdentityError> {
        // Create a copy without the signature
        let mut profile_copy = self.clone();
        profile_copy.signature = Vec::new();
        
        // Serialize the profile
        let profile_bytes = bincode::serialize(&profile_copy)
            .map_err(|e| UserIdentityError::VerificationFailed(e.to_string()))?;
        
        // Verify the signature
        crate::crypto::verify(
            public_key, 
            &profile_bytes, 
            &self.signature
        ).map_err(|e| UserIdentityError::VerificationFailed(e.to_string()))?;
        
        Ok(())
    }
}

/// Represents a user's full identity
#[derive(Serialize, Deserialize)]
pub struct UserIdentity {
    /// The user's ID
    pub id: UserId,
    
    /// The user's keypair
    #[serde(skip_serializing)]
    pub keypair: KeyPair,
    
    /// The user's profile
    pub profile: UserProfile,
    
    /// The devices associated with this identity
    pub devices: Vec<crate::identity::DeviceInfo>,
    
    /// User's contacts and their trust levels
    pub trust_store: crate::identity::TrustStore,
}

impl UserIdentity {
    /// Creates a new user identity
    pub fn new(display_name: String) -> Result<Self, UserIdentityError> {
        // Generate a new keypair
        let keypair = KeyPair::generate()
            .map_err(|e| UserIdentityError::CreationFailed(e.to_string()))?;
        
        // Derive the user ID from the public key
        let id = UserId::from_public_key(&keypair.public)?;
        
        // Create a profile
        let mut profile = UserProfile::new(display_name);
        profile.sign(&keypair)?;
        
        // Create an empty list of devices
        let devices = Vec::new();
        
        // Create an empty trust store
        let trust_store = crate::identity::TrustStore::new();
        
        Ok(Self {
            id,
            keypair,
            profile,
            devices,
            trust_store,
        })
    }
    
    /// Updates the user's profile
    pub fn update_profile(&mut self, display_name: Option<String>, status: Option<String>, avatar_hash: Option<String>) -> Result<(), UserIdentityError> {
        if let Some(name) = display_name {
            self.profile.display_name = name;
        }
        
        self.profile.status = status;
        self.profile.avatar_hash = avatar_hash;
        self.profile.last_updated = SystemTime::now();
        self.profile.version += 1;
        
        // Re-sign the profile
        self.profile.sign(&self.keypair)?;
        
        Ok(())
    }
    
    /// Adds a new device to this identity
    pub fn add_device(&mut self, device: crate::identity::DeviceInfo) -> Result<(), UserIdentityError> {
        // Ensure this device belongs to this identity
        if let Some(owner_id) = &device.owner_id {
            if owner_id != &self.id {
                return Err(UserIdentityError::OperationFailed(
                    "Device belongs to another identity".to_string()
                ));
            }
        }
        
        // Add the device
        self.devices.push(device);
        
        Ok(())
    }
}
