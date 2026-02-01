//! Native Rust bindings for hush Python SDK.
//!
//! Provides optimized implementations of cryptographic operations.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

/// Verify a signed receipt using native Rust implementation.
#[pyfunction]
fn verify_receipt_native(
    receipt_json: &str,
    signature_hex: &str,
    public_key_hex: &str,
) -> PyResult<bool> {
    use hush_core::signing::verify_ed25519;

    let signature = hex::decode(signature_hex.trim_start_matches("0x"))
        .map_err(|e| PyValueError::new_err(format!("Invalid signature hex: {}", e)))?;

    let public_key = hex::decode(public_key_hex.trim_start_matches("0x"))
        .map_err(|e| PyValueError::new_err(format!("Invalid public key hex: {}", e)))?;

    let message = receipt_json.as_bytes();

    match verify_ed25519(message, &signature, &public_key) {
        Ok(valid) => Ok(valid),
        Err(_) => Ok(false),
    }
}

/// Compute SHA-256 hash using native implementation.
#[pyfunction]
fn sha256_native(data: &[u8]) -> PyResult<Vec<u8>> {
    use hush_core::hashing::sha256;
    Ok(sha256(data).to_vec())
}

/// Compute Merkle root from leaf hashes.
#[pyfunction]
fn merkle_root_native(leaves: Vec<Vec<u8>>) -> PyResult<Vec<u8>> {
    use hush_core::merkle::MerkleTree;

    let tree = MerkleTree::from_leaves(&leaves);
    Ok(tree.root().to_vec())
}

/// Check if native backend is available.
#[pyfunction]
fn is_native_available() -> bool {
    true
}

/// Python module definition.
#[pymodule]
fn hush_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(verify_receipt_native, m)?)?;
    m.add_function(wrap_pyfunction!(sha256_native, m)?)?;
    m.add_function(wrap_pyfunction!(merkle_root_native, m)?)?;
    m.add_function(wrap_pyfunction!(is_native_available, m)?)?;
    Ok(())
}
