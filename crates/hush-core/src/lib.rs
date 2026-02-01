//! Hush Core Cryptographic Primitives
//!
//! Core cryptographic operations for the hushclaw attestation system:
//! - Ed25519 signing and verification
//! - SHA-256 and Keccak-256 hashing
//! - Merkle tree construction and proof verification
//! - Canonical JSON (RFC 8785)
//! - Receipt types and signing

pub mod signing;
pub mod hashing;
pub mod canonical;
pub mod merkle;
pub mod receipt;
pub mod error;

pub use signing::{Keypair, PublicKey, Signature};
pub use hashing::{Hash, sha256, sha256_hex, keccak256, keccak256_hex};
pub use canonical::canonicalize as canonicalize_json;
pub use merkle::{MerkleTree, MerkleProof};
pub use receipt::{Receipt, SignedReceipt, Verdict, Provenance};
pub use error::{Error, Result};

/// Commonly used types
pub mod prelude {
    pub use crate::{
        Keypair, PublicKey, Signature,
        Hash, sha256, keccak256,
        MerkleTree, MerkleProof,
        Receipt, SignedReceipt,
        Error, Result,
    };
}
