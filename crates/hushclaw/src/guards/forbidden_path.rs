//! Forbidden Path Guard
//!
//! Blocks access to sensitive filesystem paths like /etc/shadow, ~/.ssh, etc.

use async_trait::async_trait;
use globset::{Glob, GlobSet, GlobSetBuilder};
use tracing::debug;

use super::{Guard, GuardResult};
use crate::error::Severity;
use crate::event::{Event, EventData, EventType};
use crate::policy::Policy;

/// Guard that blocks access to forbidden filesystem paths
pub struct ForbiddenPathGuard {
    /// Precompiled glob patterns for common sensitive paths
    sensitive_globs: GlobSet,
}

impl ForbiddenPathGuard {
    pub fn new() -> Self {
        let mut builder = GlobSetBuilder::new();

        // Add common sensitive path patterns
        let patterns = [
            // System security files
            "**/etc/shadow",
            "**/etc/passwd",
            "**/etc/sudoers",
            "**/etc/sudoers.d/**",
            // SSH keys
            "**/.ssh/**",
            "**/id_rsa",
            "**/id_rsa.pub",
            "**/id_ed25519",
            "**/id_ed25519.pub",
            "**/id_ecdsa",
            "**/authorized_keys",
            "**/known_hosts",
            // GPG keys
            "**/.gnupg/**",
            // Cloud credentials
            "**/.aws/credentials",
            "**/.aws/config",
            "**/.azure/**",
            "**/.kube/config",
            "**/.config/gcloud/**",
            "**/.docker/config.json",
            // Environment files
            "**/.env",
            "**/.env.*",
            "**/env.local",
            // Private keys
            "**/*.pem",
            "**/*.key",
            "**/private/**",
            // Sensitive config
            "**/secrets.yaml",
            "**/secrets.json",
            "**/credentials.json",
        ];

        for pattern in patterns {
            if let Ok(glob) = Glob::new(pattern) {
                builder.add(glob);
            }
        }

        Self {
            sensitive_globs: builder.build().unwrap_or_else(|_| GlobSet::empty()),
        }
    }

    /// Expand home directory in path
    fn expand_home(&self, path: &str) -> String {
        if path.starts_with("~/") {
            if let Ok(home) = std::env::var("HOME") {
                return path.replacen("~", &home, 1);
            }
        }
        path.to_string()
    }

    /// Check if a path matches forbidden patterns
    fn check_path_string(&self, path: &str, policy: &Policy) -> GuardResult {
        let expanded = self.expand_home(path);

        // Check against policy forbidden paths
        for forbidden in &policy.filesystem.forbidden_paths {
            let forbidden_expanded = self.expand_home(forbidden);

            // Direct match or prefix match
            if expanded == forbidden_expanded
                || expanded.starts_with(&format!("{}/", forbidden_expanded))
                || expanded.contains(&forbidden_expanded)
            {
                debug!("Path {} matches forbidden pattern {}", path, forbidden);
                return GuardResult::Deny {
                    reason: format!("Path '{}' is forbidden by policy", path),
                    severity: Severity::Critical,
                };
            }
        }

        // Check against built-in sensitive globs
        if self.sensitive_globs.is_match(&expanded) {
            return GuardResult::Deny {
                reason: format!("Path '{}' matches sensitive file pattern", path),
                severity: Severity::Critical,
            };
        }

        GuardResult::Allow
    }

    /// Check path with symlink resolution
    async fn check_path(&self, path: &str, policy: &Policy) -> GuardResult {
        // Always check the original path string first
        let direct = self.check_path_string(path, policy);
        if direct.is_denied() {
            return direct;
        }

        // Best-effort symlink/path traversal defense: canonicalize and re-check
        // If the path doesn't exist, fall back to string checks only
        let expanded = self.expand_home(path);
        match tokio::fs::canonicalize(&expanded).await {
            Ok(real) => {
                let real = real.to_string_lossy().to_string();
                let resolved = self.check_path_string(&real, policy);
                if resolved.is_denied() {
                    return GuardResult::Deny {
                        reason: format!("Path '{}' resolves to forbidden target '{}'", path, real),
                        severity: Severity::Critical,
                    };
                }
            }
            Err(_) => {
                // Path doesn't exist or can't be resolved - that's fine
            }
        }

        GuardResult::Allow
    }
}

impl Default for ForbiddenPathGuard {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Guard for ForbiddenPathGuard {
    fn name(&self) -> &str {
        "forbidden_path"
    }

    async fn check(&self, event: &Event, policy: &Policy) -> GuardResult {
        match (&event.event_type, &event.data) {
            (EventType::FileRead | EventType::FileWrite, EventData::File(data)) => {
                self.check_path(&data.path, policy).await
            }
            (EventType::PatchApply, EventData::Patch(data)) => {
                self.check_path(&data.file_path, policy).await
            }
            _ => GuardResult::Allow,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_file_event(path: &str, write: bool) -> Event {
        if write {
            Event::file_write(path)
        } else {
            Event::file_read(path)
        }
    }

    #[tokio::test]
    async fn test_allows_normal_paths() {
        let guard = ForbiddenPathGuard::new();
        let policy = Policy::default();

        let event = make_file_event("/home/user/code/main.rs", false);
        let result = guard.check(&event, &policy).await;
        assert!(result.is_allowed());
    }

    #[tokio::test]
    async fn test_allows_workspace_paths() {
        let guard = ForbiddenPathGuard::new();
        let policy = Policy::default();

        let event = make_file_event("/workspace/src/lib.rs", false);
        let result = guard.check(&event, &policy).await;
        assert!(result.is_allowed());
    }

    #[tokio::test]
    async fn test_blocks_etc_shadow() {
        let guard = ForbiddenPathGuard::new();
        let policy = Policy::default();

        let event = make_file_event("/etc/shadow", false);
        let result = guard.check(&event, &policy).await;
        assert!(result.is_denied());
    }

    #[tokio::test]
    async fn test_blocks_etc_passwd() {
        let guard = ForbiddenPathGuard::new();
        let policy = Policy::default();

        let event = make_file_event("/etc/passwd", false);
        let result = guard.check(&event, &policy).await;
        assert!(result.is_denied());
    }

    #[tokio::test]
    async fn test_blocks_ssh_keys() {
        let guard = ForbiddenPathGuard::new();
        let policy = Policy::default();

        let event = make_file_event("/home/user/.ssh/id_rsa", false);
        let result = guard.check(&event, &policy).await;
        assert!(result.is_denied());
    }

    #[tokio::test]
    async fn test_blocks_ssh_directory() {
        let guard = ForbiddenPathGuard::new();
        let policy = Policy::default();

        let event = make_file_event("/home/user/.ssh/config", false);
        let result = guard.check(&event, &policy).await;
        assert!(result.is_denied());
    }

    #[tokio::test]
    async fn test_blocks_aws_credentials() {
        let guard = ForbiddenPathGuard::new();
        let policy = Policy::default();

        let event = make_file_event("/home/user/.aws/credentials", false);
        let result = guard.check(&event, &policy).await;
        assert!(result.is_denied());
    }

    #[tokio::test]
    async fn test_blocks_gnupg() {
        let guard = ForbiddenPathGuard::new();
        let policy = Policy::default();

        let event = make_file_event("/home/user/.gnupg/private-keys-v1.d/key.key", false);
        let result = guard.check(&event, &policy).await;
        assert!(result.is_denied());
    }

    #[tokio::test]
    async fn test_blocks_pem_files() {
        let guard = ForbiddenPathGuard::new();
        let policy = Policy::default();

        let event = make_file_event("/home/user/certs/server.pem", false);
        let result = guard.check(&event, &policy).await;
        assert!(result.is_denied());
    }

    #[tokio::test]
    async fn test_blocks_env_files() {
        let guard = ForbiddenPathGuard::new();
        let policy = Policy::default();

        let event = make_file_event("/home/user/project/.env", false);
        let result = guard.check(&event, &policy).await;
        assert!(result.is_denied());
    }

    #[tokio::test]
    async fn test_blocks_env_local() {
        let guard = ForbiddenPathGuard::new();
        let policy = Policy::default();

        let event = make_file_event("/home/user/project/.env.local", false);
        let result = guard.check(&event, &policy).await;
        assert!(result.is_denied());
    }

    #[tokio::test]
    async fn test_blocks_custom_forbidden_path() {
        let guard = ForbiddenPathGuard::new();
        let mut policy = Policy::default();
        policy
            .filesystem
            .forbidden_paths
            .push("/secret/data".to_string());

        let event = make_file_event("/secret/data/file.txt", false);
        let result = guard.check(&event, &policy).await;
        assert!(result.is_denied());
    }

    #[tokio::test]
    async fn test_blocks_write_to_forbidden() {
        let guard = ForbiddenPathGuard::new();
        let policy = Policy::default();

        let event = make_file_event("/etc/shadow", true);
        let result = guard.check(&event, &policy).await;
        assert!(result.is_denied());
    }

    #[tokio::test]
    async fn test_blocks_patch_to_forbidden() {
        let guard = ForbiddenPathGuard::new();
        let policy = Policy::default();

        let event = Event::patch_apply("/etc/passwd", "root:x:0:0::/root:/bin/bash");
        let result = guard.check(&event, &policy).await;
        assert!(result.is_denied());
    }

    #[tokio::test]
    async fn test_allows_patch_to_normal_path() {
        let guard = ForbiddenPathGuard::new();
        let policy = Policy::default();

        let event = Event::patch_apply("/workspace/main.py", "print('hello')");
        let result = guard.check(&event, &policy).await;
        assert!(result.is_allowed());
    }

    #[tokio::test]
    async fn test_ignores_network_events() {
        let guard = ForbiddenPathGuard::new();
        let policy = Policy::default();

        let event = Event::network_egress("api.github.com", 443);
        let result = guard.check(&event, &policy).await;
        assert!(result.is_allowed());
    }
}
