//! Error types for hushclaw

use thiserror::Error;

/// Errors that can occur during guard operations
#[derive(Error, Debug)]
pub enum Error {
    #[error("Guard check failed: {0}")]
    GuardFailed(String),

    #[error("Policy violation: {guard} - {message}")]
    PolicyViolation { guard: String, message: String },

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("YAML error: {0}")]
    YamlError(#[from] serde_yaml::Error),

    #[error("Regex error: {0}")]
    RegexError(#[from] regex::Error),

    #[error("Core error: {0}")]
    CoreError(#[from] hush_core::Error),
}

/// Result type for hushclaw operations
pub type Result<T> = std::result::Result<T, Error>;
