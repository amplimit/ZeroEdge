mod keys;
mod encryption;
mod signing;
mod double_ratchet;

pub use keys::{KeyPair, PublicKey, SecretKey};
pub use encryption::{encrypt, decrypt, EncryptionError};
pub use signing::{sign, verify, SignatureError};
pub use double_ratchet::{DoubleRatchet, RatchetError};

/*
 * Cryptography module for ZeroEdge
 * 
 * This module handles all cryptographic operations including:
 * - Key generation and management
 * - Message encryption and decryption
 * - Signatures for authentication
 * - Double Ratchet algorithm for forward secrecy
 */

