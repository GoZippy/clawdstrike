//! Hushclaw - Security Guards and Policy Engine
//!
//! This crate provides security guards for AI agent execution:
//! - ForbiddenPathGuard: Blocks access to sensitive paths
//! - EgressAllowlistGuard: Controls network egress
//! - SecretLeakGuard: Detects potential secret exposure
//! - PatchIntegrityGuard: Validates patch safety
//! - McpToolGuard: Restricts MCP tool invocations
//!
//! Guards can be composed into rulesets and configured via YAML.

pub mod engine;
pub mod error;
pub mod guards;
pub mod policy;

pub use engine::HushEngine;
pub use error::{Error, Result};
pub use guards::{
    EgressAllowlistGuard, ForbiddenPathGuard, Guard, GuardContext, GuardResult, McpToolGuard,
    PatchIntegrityGuard, SecretLeakGuard, Severity,
};
pub use policy::{Policy, RuleSet};

/// Re-export core types
pub mod core {
    pub use hush_core::*;
}
