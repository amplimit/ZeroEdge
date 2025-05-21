pub mod user;
pub mod device;
mod verification;
mod trust;

pub use user::{UserId, UserProfile, UserIdentity, UserIdentityError};
pub use device::{DeviceId, DeviceInfo};
pub use verification::{VerificationMethod, VerificationStatus};
pub use trust::{TrustLevel, TrustStore};

/*
 * Identity management module for ZeroEdge
 * 
 * This module handles user identities, device management,
 * verification of identities, and trust relationships.
 * 
 * Key features:
 * - Self-sovereign identities based on cryptographic keys
 * - Multi-device support with device-specific keys
 * - Out-of-band verification methods
 * - Social trust graph
 */

