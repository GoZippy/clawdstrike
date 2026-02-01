//! Security policy configuration

use serde::{Deserialize, Serialize};

/// Security policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Policy name/version
    #[serde(default)]
    pub name: String,

    /// Filesystem policy
    #[serde(default)]
    pub filesystem: FilesystemPolicy,

    /// Network egress policy
    #[serde(default)]
    pub egress: EgressPolicy,

    /// Execution policy
    #[serde(default)]
    pub execution: ExecutionPolicy,

    /// Tool policy
    #[serde(default)]
    pub tools: ToolPolicy,

    /// Guard toggles
    #[serde(default)]
    pub guards: GuardsConfig,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            name: "hushclaw-default".to_string(),
            filesystem: FilesystemPolicy::default(),
            egress: EgressPolicy::default(),
            execution: ExecutionPolicy::default(),
            tools: ToolPolicy::default(),
            guards: GuardsConfig::default(),
        }
    }
}

/// Filesystem access policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemPolicy {
    /// Paths that are always forbidden
    #[serde(default = "default_forbidden_paths")]
    pub forbidden_paths: Vec<String>,

    /// Allowed write roots (if empty, all writes allowed)
    #[serde(default)]
    pub allowed_write_roots: Vec<String>,
}

fn default_forbidden_paths() -> Vec<String> {
    vec![
        "/etc/shadow".to_string(),
        "/etc/passwd".to_string(),
        "/etc/sudoers".to_string(),
        "~/.ssh".to_string(),
        "~/.gnupg".to_string(),
        "~/.aws/credentials".to_string(),
        "~/.azure".to_string(),
        "~/.kube/config".to_string(),
        "~/.docker/config.json".to_string(),
    ]
}

impl Default for FilesystemPolicy {
    fn default() -> Self {
        Self {
            forbidden_paths: default_forbidden_paths(),
            allowed_write_roots: vec![],
        }
    }
}

/// Network egress policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressPolicy {
    /// Egress mode
    #[serde(default)]
    pub mode: EgressMode,

    /// Allowed domains (for allowlist mode)
    #[serde(default = "default_allowed_domains")]
    pub allowed_domains: Vec<String>,

    /// Denied domains (always blocked, takes precedence)
    #[serde(default = "default_denied_domains")]
    pub denied_domains: Vec<String>,

    /// Allowed IP CIDR ranges
    #[serde(default)]
    pub allowed_cidrs: Vec<String>,

    /// Block private IP ranges (SSRF prevention)
    #[serde(default = "default_true")]
    pub block_private_ips: bool,
}

fn default_allowed_domains() -> Vec<String> {
    vec![
        "api.anthropic.com".to_string(),
        "api.openai.com".to_string(),
        "github.com".to_string(),
        "api.github.com".to_string(),
        "raw.githubusercontent.com".to_string(),
        "pypi.org".to_string(),
        "files.pythonhosted.org".to_string(),
        "registry.npmjs.org".to_string(),
        "crates.io".to_string(),
    ]
}

fn default_denied_domains() -> Vec<String> {
    vec!["*.onion".to_string()]
}

fn default_true() -> bool {
    true
}

impl Default for EgressPolicy {
    fn default() -> Self {
        Self {
            mode: EgressMode::Allowlist,
            allowed_domains: default_allowed_domains(),
            denied_domains: default_denied_domains(),
            allowed_cidrs: vec![],
            block_private_ips: true,
        }
    }
}

/// Egress mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressMode {
    /// Block all egress
    DenyAll,
    /// Allow only allowlisted domains
    #[default]
    Allowlist,
    /// Allow all egress (not recommended)
    Open,
}

/// Execution policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionPolicy {
    /// Allowed commands (if empty, all allowed except denied)
    #[serde(default)]
    pub allowed_commands: Vec<String>,

    /// Denied command patterns (always blocked)
    #[serde(default = "default_denied_patterns")]
    pub denied_patterns: Vec<String>,
}

fn default_denied_patterns() -> Vec<String> {
    vec![
        "rm -rf /".to_string(),
        "rm -rf /*".to_string(),
        ":(){ :|:& };:".to_string(),
        "dd if=".to_string(),
        "mkfs.".to_string(),
    ]
}

impl Default for ExecutionPolicy {
    fn default() -> Self {
        Self {
            allowed_commands: vec![],
            denied_patterns: default_denied_patterns(),
        }
    }
}

/// Tool policy
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ToolPolicy {
    /// Allowed tools (if empty, all allowed except denied)
    #[serde(default)]
    pub allowed: Vec<String>,

    /// Denied tools (always blocked)
    #[serde(default)]
    pub denied: Vec<String>,
}

/// Guard enable/disable toggles
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardsConfig {
    pub forbidden_path: bool,
    pub egress_allowlist: bool,
    pub secret_leak: bool,
    pub patch_integrity: bool,
    pub mcp_tool: bool,
}

impl Default for GuardsConfig {
    fn default() -> Self {
        Self {
            forbidden_path: true,
            egress_allowlist: true,
            secret_leak: true,
            patch_integrity: true,
            mcp_tool: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_policy() {
        let policy = Policy::default();
        assert!(!policy.filesystem.forbidden_paths.is_empty());
        assert!(!policy.egress.allowed_domains.is_empty());
        assert_eq!(policy.egress.mode, EgressMode::Allowlist);
    }

    #[test]
    fn test_default_forbidden_paths() {
        let policy = Policy::default();
        assert!(policy
            .filesystem
            .forbidden_paths
            .contains(&"/etc/shadow".to_string()));
        assert!(policy
            .filesystem
            .forbidden_paths
            .contains(&"~/.ssh".to_string()));
    }

    #[test]
    fn test_guards_config_default() {
        let config = GuardsConfig::default();
        assert!(config.forbidden_path);
        assert!(config.egress_allowlist);
        assert!(config.secret_leak);
        assert!(config.patch_integrity);
        assert!(config.mcp_tool);
    }

    #[test]
    fn test_policy_serialization() {
        let policy = Policy::default();
        let json = serde_json::to_string(&policy).unwrap();
        let parsed: Policy = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, policy.name);
    }
}
