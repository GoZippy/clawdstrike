//! Error types for hushclaw guards

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Result type alias using hushclaw Error
pub type Result<T> = std::result::Result<T, Error>;

/// Hushclaw error types
#[derive(Debug, Error)]
pub enum Error {
    #[error("Policy violation: {reason}")]
    PolicyViolation { reason: String, severity: Severity },

    #[error("Invalid policy: {0}")]
    InvalidPolicy(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Regex error: {0}")]
    Regex(#[from] regex::Error),

    #[error("Glob pattern error: {0}")]
    GlobPattern(#[from] globset::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Severity levels for security violations
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational - no action needed
    Info,
    /// Low severity - log and continue
    Low,
    /// Medium severity - warn user
    #[default]
    Medium,
    /// High severity - block action
    High,
    /// Critical severity - block and alert
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(Severity::Critical.to_string(), "critical");
        assert_eq!(Severity::Info.to_string(), "info");
    }

    #[test]
    fn test_severity_serde() {
        let json = serde_json::to_string(&Severity::High).unwrap();
        assert_eq!(json, "\"high\"");
        let parsed: Severity = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, Severity::High);
    }
}
