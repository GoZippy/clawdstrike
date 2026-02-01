//! Egress policy enforcement
//!
//! Provides domain allowlist/blocklist policy evaluation.

use serde::{Deserialize, Serialize};

use crate::dns::domain_matches;

/// Policy action for a domain
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyAction {
    /// Allow the connection
    Allow,
    /// Block the connection
    #[default]
    Block,
    /// Log but allow
    Log,
}

/// Domain policy configuration
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DomainPolicy {
    /// Allowed domain patterns (supports wildcards like *.example.com)
    #[serde(default)]
    pub allow: Vec<String>,
    /// Blocked domain patterns
    #[serde(default)]
    pub block: Vec<String>,
    /// Default action when no pattern matches
    #[serde(default = "default_action")]
    pub default_action: PolicyAction,
}

fn default_action() -> PolicyAction {
    PolicyAction::Block
}

impl DomainPolicy {
    /// Create a new policy with default deny
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a permissive policy (default allow)
    pub fn permissive() -> Self {
        Self {
            allow: vec![],
            block: vec![],
            default_action: PolicyAction::Allow,
        }
    }

    /// Add an allowed domain pattern
    pub fn allow(mut self, pattern: impl Into<String>) -> Self {
        self.allow.push(pattern.into());
        self
    }

    /// Add a blocked domain pattern
    pub fn block(mut self, pattern: impl Into<String>) -> Self {
        self.block.push(pattern.into());
        self
    }

    /// Evaluate a domain against the policy
    pub fn evaluate(&self, domain: &str) -> PolicyAction {
        // Check blocklist first (block takes precedence)
        for pattern in &self.block {
            if domain_matches(domain, pattern) {
                return PolicyAction::Block;
            }
        }

        // Check allowlist
        for pattern in &self.allow {
            if domain_matches(domain, pattern) {
                return PolicyAction::Allow;
            }
        }

        // Default action
        self.default_action.clone()
    }

    /// Check if a domain is allowed
    pub fn is_allowed(&self, domain: &str) -> bool {
        matches!(self.evaluate(domain), PolicyAction::Allow)
    }
}

/// Policy evaluation result with details
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyResult {
    /// The evaluated domain
    pub domain: String,
    /// The resulting action
    pub action: PolicyAction,
    /// The pattern that matched (if any)
    pub matched_pattern: Option<String>,
    /// Whether this was a default action
    pub is_default: bool,
}

impl DomainPolicy {
    /// Evaluate with detailed result
    pub fn evaluate_detailed(&self, domain: &str) -> PolicyResult {
        // Check blocklist first
        for pattern in &self.block {
            if domain_matches(domain, pattern) {
                return PolicyResult {
                    domain: domain.to_string(),
                    action: PolicyAction::Block,
                    matched_pattern: Some(pattern.clone()),
                    is_default: false,
                };
            }
        }

        // Check allowlist
        for pattern in &self.allow {
            if domain_matches(domain, pattern) {
                return PolicyResult {
                    domain: domain.to_string(),
                    action: PolicyAction::Allow,
                    matched_pattern: Some(pattern.clone()),
                    is_default: false,
                };
            }
        }

        // Default action
        PolicyResult {
            domain: domain.to_string(),
            action: self.default_action.clone(),
            matched_pattern: None,
            is_default: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_deny() {
        let policy = DomainPolicy::new();
        assert!(!policy.is_allowed("example.com"));
    }

    #[test]
    fn test_permissive() {
        let policy = DomainPolicy::permissive();
        assert!(policy.is_allowed("example.com"));
    }

    #[test]
    fn test_allowlist() {
        let policy = DomainPolicy::new()
            .allow("example.com")
            .allow("*.allowed.org");

        assert!(policy.is_allowed("example.com"));
        assert!(policy.is_allowed("sub.allowed.org"));
        assert!(!policy.is_allowed("other.com"));
    }

    #[test]
    fn test_blocklist_precedence() {
        let policy = DomainPolicy::permissive().block("bad.example.com");

        assert!(policy.is_allowed("good.example.com"));
        assert!(!policy.is_allowed("bad.example.com"));
    }

    #[test]
    fn test_wildcard_block() {
        let policy = DomainPolicy::permissive().block("*.blocked.com");

        assert!(policy.is_allowed("allowed.com"));
        assert!(!policy.is_allowed("sub.blocked.com"));
        assert!(!policy.is_allowed("blocked.com"));
    }

    #[test]
    fn test_evaluate_detailed() {
        let policy = DomainPolicy::new().allow("*.example.com");

        let result = policy.evaluate_detailed("sub.example.com");
        assert_eq!(result.action, PolicyAction::Allow);
        assert_eq!(result.matched_pattern, Some("*.example.com".to_string()));
        assert!(!result.is_default);

        let result = policy.evaluate_detailed("other.com");
        assert_eq!(result.action, PolicyAction::Block);
        assert!(result.matched_pattern.is_none());
        assert!(result.is_default);
    }
}
