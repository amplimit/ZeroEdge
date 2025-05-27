use crate::crypto::PublicKey;
use libp2p::kad::record::Key;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::fmt;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum KademliaError {
    #[error("Node ID derivation failed: {0}")]
    NodeIdDerivationFailed(String),
    
    #[error("Invalid node info: {0}")]
    InvalidNodeInfo(String),
    
    #[error("DHT operation failed: {0}")]
    OperationFailed(String),
}

/// Configuration for the Kademlia DHT
#[derive(Debug, Clone)]
pub struct KademliaConfig {
    /// The number of nodes to keep in each k-bucket
    pub k_value: usize,
    /// The number of nodes to query in parallel during lookups
    pub alpha_value: usize,
    /// The interval for refreshing buckets
    pub refresh_interval: Duration,
    /// The interval for republishing keys
    pub republish_interval: Duration,
    /// The time after which a key should be republished
    pub record_ttl: Duration,
    /// The number of nodes to replicate a record to
    pub replication_factor: usize,
}

impl Default for KademliaConfig {
    fn default() -> Self {
        Self {
            k_value: 20,
            alpha_value: 3,
            refresh_interval: Duration::from_secs(3600), // 1 hour
            republish_interval: Duration::from_secs(21600), // 6 hours
            record_ttl: Duration::from_secs(86400), // 24 hours
            replication_factor: 5,
        }
    }
}

/// Represents a node's identifier in the DHT
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct NodeId(pub [u8; 32]);

impl NodeId {
    /// Generates a NodeId from a public key
    pub fn from_public_key(key: &PublicKey) -> Result<Self, KademliaError> {
        // Use the SHA-256 hash of the public key as the node ID
        let key_bytes = key.to_bytes()
            .map_err(|e| KademliaError::NodeIdDerivationFailed(e.to_string()))?;
        
        let mut hasher = ring::digest::Context::new(&ring::digest::SHA256);
        hasher.update(&key_bytes);
        let digest = hasher.finish();
        
        let mut id = [0u8; 32];
        id.copy_from_slice(digest.as_ref());
        
        Ok(Self(id))
    }
    
    /// Generates a random NodeId
    pub fn random() -> Self {
        let mut id = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut id);
        Self(id)
    }
    
    /// Calculates the XOR distance between two NodeIds
    pub fn distance(&self, other: &Self) -> [u8; 32] {
        let mut result = [0u8; 32];
        
        for i in 0..32 {
            result[i] = self.0[i] ^ other.0[i];
        }
        
        result
    }
    
    /// Converts the NodeId to a Kademlia Key
    pub fn to_kademlia_key(&self) -> Key {
        Key::from(self.0.to_vec())
    }
}

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeId({})", hex::encode(&self.0[..6]))
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

impl TryFrom<&[u8]> for NodeId {
    type Error = KademliaError;
    
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != 32 {
            return Err(KademliaError::NodeIdDerivationFailed(
                format!("Invalid length: expected 32, got {}", bytes.len())
            ));
        }
        
        let mut id = [0u8; 32];
        id.copy_from_slice(bytes);
        
        Ok(Self(id))
    }
}

/// Represents information about a node in the network
#[derive(Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    /// The node's ID
    pub id: NodeId,
    /// The node's public key
    pub public_key: PublicKey,
    /// The node's network addresses
    pub addresses: Vec<SocketAddr>,
    /// The time when this information was last updated
    pub last_updated: SystemTime,
    /// The node's protocol version
    pub protocol_version: u16,
    /// Whether the node is a relay
    pub is_relay: bool,
    /// The signature of this node info, signed by the node
    pub signature: Vec<u8>,
}

impl NodeInfo {
    /// Creates a new NodeInfo
    pub fn new(
        id: NodeId, 
        public_key: PublicKey, 
        addresses: Vec<SocketAddr>, 
        protocol_version: u16,
        is_relay: bool
    ) -> Self {
        Self {
            id,
            public_key,
            addresses,
            last_updated: SystemTime::now(),
            protocol_version,
            is_relay,
            signature: Vec::new(), // Will be set by sign method
        }
    }
    
    /// Creates a new NodeInfo and signs it
    pub fn new_signed(
        id: NodeId, 
        public_key: PublicKey, 
        addresses: Vec<SocketAddr>, 
        protocol_version: u16,
        is_relay: bool,
        secret_key: &crate::crypto::SecretKey,
    ) -> Result<Self, KademliaError> {
        let mut node_info = Self::new(id, public_key, addresses, protocol_version, is_relay);
        
        // 使用提供的密钥签名
        node_info.sign(secret_key)?;
        
        Ok(node_info)
    }
    
    /// Signs the node info with the given secret key
    pub fn sign(&mut self, secret_key: &crate::crypto::SecretKey) -> Result<(), KademliaError> {
        // Create a copy without the signature field
        let mut info_copy = self.clone();
        info_copy.signature = Vec::new();
        
        // Serialize the info
        let info_bytes = bincode::serialize(&info_copy)
            .map_err(|e| KademliaError::InvalidNodeInfo(e.to_string()))?;
        
        // Sign the info
        let signature = crate::crypto::sign(secret_key, &info_bytes)
            .map_err(|e| KademliaError::InvalidNodeInfo(e.to_string()))?;
        
        // Set the signature
        self.signature = signature;
        
        Ok(())
    }
    
    /// Verifies the signature on the node info
    pub fn verify(&self) -> Result<(), KademliaError> {
        // Create a copy without the signature field
        let mut info_copy = self.clone();
        info_copy.signature = Vec::new();
        
        // Serialize the info
        let info_bytes = bincode::serialize(&info_copy)
            .map_err(|e| KademliaError::InvalidNodeInfo(e.to_string()))?;
        
        // Verify the signature
        crate::crypto::verify(&self.public_key, &info_bytes, &self.signature)
            .map_err(|e| KademliaError::InvalidNodeInfo(e.to_string()))?;
        
        Ok(())
    }
    
    /// Checks if the node info is expired
    pub fn is_expired(&self, ttl: Duration) -> bool {
        match SystemTime::now().duration_since(self.last_updated) {
            Ok(age) => age > ttl,
            Err(_) => false, // Clock went backwards, consider not expired
        }
    }
}

impl fmt::Debug for NodeInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeInfo")
            .field("id", &self.id)
            .field("public_key", &self.public_key)
            .field("addresses", &self.addresses)
            .field("last_updated", &self.last_updated)
            .field("protocol_version", &self.protocol_version)
            .field("is_relay", &self.is_relay)
            .field("signature", &format!("[{} bytes]", self.signature.len()))
            .finish()
    }
}

/// Implementation of the Kademlia DHT node
pub struct KademliaNode {
    // Implementation will be added later
}

impl KademliaNode {
    /// Creates a new KademliaNode with the given configuration
    pub fn new(_config: KademliaConfig) -> Self {
        // Implementation will be added later
        Self {}
    }
    
    /// Starts the Kademlia node
    pub async fn start(&mut self) -> Result<(), KademliaError> {
        // Implementation will be added later
        Ok(())
    }
    
    /// Stops the Kademlia node
    pub async fn stop(&mut self) -> Result<(), KademliaError> {
        // Implementation will be added later
        Ok(())
    }
    
    /// Bootstraps the node by connecting to the given bootstrap nodes
    pub async fn bootstrap(&mut self, _bootstrap_nodes: Vec<NodeInfo>) -> Result<(), KademliaError> {
        // Implementation will be added later
        Ok(())
    }
}
