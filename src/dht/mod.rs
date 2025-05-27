mod kademlia;
mod routing;
mod storage;
mod public_dht;
mod private_dht;
mod validation;

pub use kademlia::{KademliaConfig, KademliaNode, KademliaError, NodeId, NodeInfo};
pub use routing::RoutingTable;
pub use storage::{DhtStorage, DhtValue};
pub use public_dht::{PublicDht, PublicDhtConfig};
pub use private_dht::{PrivateDht, PrivateDhtConfig};
pub use validation::validate_node_id;

/*
 * Distributed Hash Table (DHT) implementation for ZeroEdge
 * 
 * This module provides the DHT implementation based on Kademlia algorithm
 * with two separate layers:
 * 
 * 1. Public DHT - For node discovery and public information
 * 2. Private DHT - For authorized friend-only access
 * 
 * The DHT is responsible for storing and retrieving:
 * - Node location information
 * - User profiles
 * - Public keys
 * - Service records
 */

