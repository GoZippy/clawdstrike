//! MCP Tool Guard
//!
//! Controls which MCP tools and commands are allowed to execute.

use async_trait::async_trait;
use tracing::debug;

use super::{Guard, GuardResult};
use crate::error::Severity;
use crate::event::{Event, EventData, EventType};
use crate::policy::Policy;

/// Guard that enforces tool and command allowlists
pub struct McpToolGuard;

impl McpToolGuard {
    pub fn new() -> Self {
        Self
    }

    fn check_command(&self, command: &str, args: &[String], policy: &Policy) -> GuardResult {
        // Build full command string for pattern matching
        let full_cmd = if args.is_empty() {
            command.to_string()
        } else {
            format!("{} {}", command, args.join(" "))
        };

        // Check against deny patterns first (dangerous commands)
        for pattern in &policy.execution.denied_patterns {
            if full_cmd.contains(pattern) {
                debug!("Command '{}' matches deny pattern '{}'", full_cmd, pattern);
                return GuardResult::Deny {
                    reason: format!("Command matches dangerous pattern: {}", pattern),
                    severity: Severity::Critical,
                };
            }
        }

        // If allowed_commands is empty, all commands are allowed (except denied patterns)
        if policy.execution.allowed_commands.is_empty() {
            return GuardResult::Allow;
        }

        // Extract the base command (first word)
        let base_cmd = command.split_whitespace().next().unwrap_or("");

        // Also check the last path component for full paths
        let cmd_name = std::path::Path::new(base_cmd)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(base_cmd);

        // Check if command is in allowed list
        if policy.execution.allowed_commands.iter().any(|allowed| {
            allowed == cmd_name || allowed == base_cmd || cmd_name.starts_with(allowed)
        }) {
            return GuardResult::Allow;
        }

        GuardResult::Deny {
            reason: format!("Command '{}' is not in the allowed commands list", cmd_name),
            severity: Severity::Medium,
        }
    }

    fn check_tool(&self, tool_name: &str, policy: &Policy) -> GuardResult {
        // Check against denied tools first
        if policy.tools.denied.contains(&tool_name.to_string()) {
            return GuardResult::Deny {
                reason: format!("Tool '{}' is explicitly denied", tool_name),
                severity: Severity::High,
            };
        }

        // If allowed list is empty, all tools are allowed (except denied)
        if policy.tools.allowed.is_empty() {
            return GuardResult::Allow;
        }

        // Check if tool is in allowed list
        if policy.tools.allowed.contains(&tool_name.to_string()) {
            GuardResult::Allow
        } else {
            GuardResult::Deny {
                reason: format!("Tool '{}' is not in the allowed tools list", tool_name),
                severity: Severity::Medium,
            }
        }
    }
}

impl Default for McpToolGuard {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Guard for McpToolGuard {
    fn name(&self) -> &str {
        "mcp_tool"
    }

    async fn check(&self, event: &Event, policy: &Policy) -> GuardResult {
        match (&event.event_type, &event.data) {
            (EventType::CommandExec, EventData::Command(data)) => {
                self.check_command(&data.command, &data.args, policy)
            }
            (EventType::ToolCall, EventData::Tool(data)) => {
                self.check_tool(&data.tool_name, policy)
            }
            _ => GuardResult::Allow,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_command_event(command: &str, args: Vec<&str>) -> Event {
        Event::command_exec(command, args.into_iter().map(String::from).collect())
    }

    fn make_tool_event(tool_name: &str) -> Event {
        Event::tool_call(tool_name)
    }

    #[tokio::test]
    async fn test_allows_any_command_with_empty_allowlist() {
        let guard = McpToolGuard::new();
        let policy = Policy::default(); // Empty allowed_commands by default

        let event = make_command_event("git", vec!["status"]);
        let result = guard.check(&event, &policy).await;
        assert!(result.is_allowed());
    }

    #[tokio::test]
    async fn test_allows_command_in_allowlist() {
        let guard = McpToolGuard::new();
        let mut policy = Policy::default();
        policy.execution.allowed_commands = vec!["git".to_string(), "python".to_string()];

        let event = make_command_event("git", vec!["status"]);
        let result = guard.check(&event, &policy).await;
        assert!(result.is_allowed());
    }

    #[tokio::test]
    async fn test_blocks_command_not_in_allowlist() {
        let guard = McpToolGuard::new();
        let mut policy = Policy::default();
        policy.execution.allowed_commands = vec!["git".to_string()];

        let event = make_command_event("curl", vec!["https://example.com"]);
        let result = guard.check(&event, &policy).await;
        assert!(result.is_denied());
    }

    #[tokio::test]
    async fn test_blocks_dangerous_pattern() {
        let guard = McpToolGuard::new();
        let policy = Policy::default(); // Has default denied patterns

        let event = make_command_event("rm", vec!["-rf", "/"]);
        let result = guard.check(&event, &policy).await;
        assert!(result.is_denied());
    }

    #[tokio::test]
    async fn test_blocks_dangerous_pattern_even_if_allowed() {
        let guard = McpToolGuard::new();
        let mut policy = Policy::default();
        policy.execution.allowed_commands = vec!["rm".to_string()];

        let event = make_command_event("rm", vec!["-rf", "/"]);
        let result = guard.check(&event, &policy).await;
        assert!(result.is_denied());
    }

    #[tokio::test]
    async fn test_allows_full_path_command() {
        let guard = McpToolGuard::new();
        let mut policy = Policy::default();
        policy.execution.allowed_commands = vec!["python".to_string()];

        let event = make_command_event("/usr/bin/python", vec!["script.py"]);
        let result = guard.check(&event, &policy).await;
        assert!(result.is_allowed());
    }

    #[tokio::test]
    async fn test_allows_tool_with_empty_allowlist() {
        let guard = McpToolGuard::new();
        let policy = Policy::default();

        let event = make_tool_event("read_file");
        let result = guard.check(&event, &policy).await;
        assert!(result.is_allowed());
    }

    #[tokio::test]
    async fn test_allows_tool_in_allowlist() {
        let guard = McpToolGuard::new();
        let mut policy = Policy::default();
        policy.tools.allowed = vec!["read_file".to_string(), "write_file".to_string()];

        let event = make_tool_event("read_file");
        let result = guard.check(&event, &policy).await;
        assert!(result.is_allowed());
    }

    #[tokio::test]
    async fn test_blocks_tool_not_in_allowlist() {
        let guard = McpToolGuard::new();
        let mut policy = Policy::default();
        policy.tools.allowed = vec!["read_file".to_string()];

        let event = make_tool_event("exec_command");
        let result = guard.check(&event, &policy).await;
        assert!(result.is_denied());
    }

    #[tokio::test]
    async fn test_blocks_denied_tool() {
        let guard = McpToolGuard::new();
        let mut policy = Policy::default();
        policy.tools.denied = vec!["dangerous_tool".to_string()];

        let event = make_tool_event("dangerous_tool");
        let result = guard.check(&event, &policy).await;
        assert!(result.is_denied());
    }

    #[tokio::test]
    async fn test_denied_tool_takes_precedence() {
        let guard = McpToolGuard::new();
        let mut policy = Policy::default();
        policy.tools.allowed = vec!["dangerous_tool".to_string()];
        policy.tools.denied = vec!["dangerous_tool".to_string()];

        let event = make_tool_event("dangerous_tool");
        let result = guard.check(&event, &policy).await;
        assert!(result.is_denied());
    }

    #[tokio::test]
    async fn test_ignores_file_events() {
        let guard = McpToolGuard::new();
        let mut policy = Policy::default();
        policy.execution.allowed_commands = vec!["git".to_string()]; // Restrictive

        let event = Event::file_read("/etc/passwd");
        let result = guard.check(&event, &policy).await;
        assert!(result.is_allowed());
    }

    #[tokio::test]
    async fn test_ignores_network_events() {
        let guard = McpToolGuard::new();
        let mut policy = Policy::default();
        policy.tools.allowed = vec!["read_file".to_string()]; // Restrictive

        let event = Event::network_egress("api.github.com", 443);
        let result = guard.check(&event, &policy).await;
        assert!(result.is_allowed());
    }
}
