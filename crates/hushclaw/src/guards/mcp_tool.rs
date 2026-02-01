//! MCP tool guard - restricts tool invocations

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use super::{Guard, GuardAction, GuardContext, GuardResult, Severity};

/// Configuration for McpToolGuard
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct McpToolConfig {
    /// Allowed tool names (if empty, all are allowed except blocked)
    #[serde(default)]
    pub allow: Vec<String>,
    /// Blocked tool names (takes precedence)
    #[serde(default)]
    pub block: Vec<String>,
    /// Tools that require confirmation
    #[serde(default)]
    pub require_confirmation: Vec<String>,
    /// Default action (allow or block)
    #[serde(default = "default_action")]
    pub default_action: String,
    /// Maximum arguments size (bytes)
    #[serde(default = "default_max_args_size")]
    pub max_args_size: usize,
}

fn default_action() -> String {
    "allow".to_string()
}

fn default_max_args_size() -> usize {
    1024 * 1024 // 1MB
}

impl Default for McpToolConfig {
    fn default() -> Self {
        Self {
            allow: vec![],
            block: vec![
                // Dangerous shell operations
                "shell_exec".to_string(),
                "run_command".to_string(),
                // Direct file system access that bypasses guards
                "raw_file_write".to_string(),
                "raw_file_delete".to_string(),
            ],
            require_confirmation: vec![
                "file_write".to_string(),
                "file_delete".to_string(),
                "git_push".to_string(),
            ],
            default_action: "allow".to_string(),
            max_args_size: default_max_args_size(),
        }
    }
}

/// Guard that controls MCP tool invocations
pub struct McpToolGuard {
    name: String,
    config: McpToolConfig,
    allow_set: HashSet<String>,
    block_set: HashSet<String>,
    confirm_set: HashSet<String>,
}

impl McpToolGuard {
    /// Create with default configuration
    pub fn new() -> Self {
        Self::with_config(McpToolConfig::default())
    }

    /// Create with custom configuration
    pub fn with_config(config: McpToolConfig) -> Self {
        let allow_set: HashSet<_> = config.allow.iter().cloned().collect();
        let block_set: HashSet<_> = config.block.iter().cloned().collect();
        let confirm_set: HashSet<_> = config.require_confirmation.iter().cloned().collect();

        Self {
            name: "mcp_tool".to_string(),
            config,
            allow_set,
            block_set,
            confirm_set,
        }
    }

    /// Check if a tool is allowed
    pub fn is_allowed(&self, tool_name: &str) -> ToolDecision {
        // Blocked takes precedence
        if self.block_set.contains(tool_name) {
            return ToolDecision::Block;
        }

        // Check if requires confirmation
        if self.confirm_set.contains(tool_name) {
            return ToolDecision::RequireConfirmation;
        }

        // Check allowlist mode
        if !self.allow_set.is_empty() {
            // Allowlist mode: only allowed tools pass
            if self.allow_set.contains(tool_name) {
                return ToolDecision::Allow;
            } else {
                return ToolDecision::Block;
            }
        }

        // Default action
        if self.config.default_action == "block" {
            ToolDecision::Block
        } else {
            ToolDecision::Allow
        }
    }
}

impl Default for McpToolGuard {
    fn default() -> Self {
        Self::new()
    }
}

/// Decision for a tool invocation
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ToolDecision {
    Allow,
    Block,
    RequireConfirmation,
}

#[async_trait]
impl Guard for McpToolGuard {
    fn name(&self) -> &str {
        &self.name
    }

    fn handles(&self, action: &GuardAction<'_>) -> bool {
        matches!(action, GuardAction::McpTool(_, _))
    }

    async fn check(&self, action: &GuardAction<'_>, _context: &GuardContext) -> GuardResult {
        let (tool_name, args) = match action {
            GuardAction::McpTool(name, args) => (*name, *args),
            _ => return GuardResult::allow(&self.name),
        };

        // Check args size
        let args_size = args.to_string().len();
        if args_size > self.config.max_args_size {
            return GuardResult::block(
                &self.name,
                Severity::Error,
                format!(
                    "Tool arguments too large: {} bytes (max: {})",
                    args_size, self.config.max_args_size
                ),
            );
        }

        match self.is_allowed(tool_name) {
            ToolDecision::Allow => GuardResult::allow(&self.name),
            ToolDecision::Block => GuardResult::block(
                &self.name,
                Severity::Error,
                format!("Tool '{}' is blocked by policy", tool_name),
            )
            .with_details(serde_json::json!({
                "tool": tool_name,
                "reason": "blocked_by_policy",
            })),
            ToolDecision::RequireConfirmation => GuardResult::warn(
                &self.name,
                format!("Tool '{}' requires confirmation", tool_name),
            )
            .with_details(serde_json::json!({
                "tool": tool_name,
                "requires_confirmation": true,
            })),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_blocked() {
        let guard = McpToolGuard::new();

        assert_eq!(guard.is_allowed("shell_exec"), ToolDecision::Block);
        assert_eq!(guard.is_allowed("run_command"), ToolDecision::Block);
    }

    #[test]
    fn test_default_allowed() {
        let guard = McpToolGuard::new();

        assert_eq!(guard.is_allowed("read_file"), ToolDecision::Allow);
        assert_eq!(guard.is_allowed("list_directory"), ToolDecision::Allow);
    }

    #[test]
    fn test_require_confirmation() {
        let guard = McpToolGuard::new();

        assert_eq!(
            guard.is_allowed("file_write"),
            ToolDecision::RequireConfirmation
        );
        assert_eq!(
            guard.is_allowed("git_push"),
            ToolDecision::RequireConfirmation
        );
    }

    #[test]
    fn test_allowlist_mode() {
        let config = McpToolConfig {
            allow: vec!["safe_tool".to_string()],
            block: vec![],
            require_confirmation: vec![],
            default_action: "block".to_string(),
            max_args_size: 1024,
        };
        let guard = McpToolGuard::with_config(config);

        assert_eq!(guard.is_allowed("safe_tool"), ToolDecision::Allow);
        assert_eq!(guard.is_allowed("other_tool"), ToolDecision::Block);
    }

    #[tokio::test]
    async fn test_guard_check() {
        let guard = McpToolGuard::new();
        let context = GuardContext::new();

        let args = serde_json::json!({"path": "/app/file.txt"});
        let result = guard
            .check(&GuardAction::McpTool("read_file", &args), &context)
            .await;
        assert!(result.allowed);

        let result = guard
            .check(&GuardAction::McpTool("shell_exec", &args), &context)
            .await;
        assert!(!result.allowed);
    }

    #[tokio::test]
    async fn test_args_size_limit() {
        let config = McpToolConfig {
            max_args_size: 100,
            ..Default::default()
        };
        let guard = McpToolGuard::with_config(config);
        let context = GuardContext::new();

        let large_args = serde_json::json!({"data": "x".repeat(200)});
        let result = guard
            .check(&GuardAction::McpTool("some_tool", &large_args), &context)
            .await;
        assert!(!result.allowed);
    }
}
