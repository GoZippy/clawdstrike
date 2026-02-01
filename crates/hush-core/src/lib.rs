//! Hush Core Cryptographic Primitives
//!
//! Core cryptographic operations for the hushclaw attestation system:
//! - Ed25519 signing and verification
//! - SHA-256 and Keccak-256 hashing
//! - Merkle tree construction and proof verification
//! - Canonical JSON (RFC 8785)
//! - Receipt types and signing

pub mod canonical;
pub mod error;
pub mod hashing;
pub mod merkle;
pub mod receipt;
pub mod signing;

pub use canonical::canonicalize as canonicalize_json;
pub use error::{Error, Result};
pub use hashing::{keccak256, keccak256_hex, sha256, sha256_hex, Hash};
pub use merkle::{MerkleProof, MerkleTree};
pub use receipt::{Provenance, Receipt, SignedReceipt, Verdict};
pub use signing::{Keypair, PublicKey, Signature};

/// Commonly used types
pub mod prelude {
    pub use crate::{
        keccak256, sha256, Error, Hash, Keypair, MerkleProof, MerkleTree, PublicKey, Receipt,
        Result, Signature, SignedReceipt,
    };
}
