//! Secret Leak Guard
//!
//! Detects potential secrets (API keys, tokens, passwords) in outputs and patches.

use async_trait::async_trait;
use regex::Regex;
use tracing::debug;

use super::{Guard, GuardResult};
use crate::error::Severity;
use crate::event::{Event, EventData, EventType};
use crate::policy::Policy;

/// Guard that detects secrets in outputs
pub struct SecretLeakGuard {
    patterns: Vec<SecretPattern>,
}

struct SecretPattern {
    name: &'static str,
    regex: Regex,
    severity: Severity,
}

impl SecretLeakGuard {
    pub fn new() -> Self {
        let patterns = vec![
            // AWS
            SecretPattern {
                name: "AWS Access Key ID",
                regex: Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
                severity: Severity::Critical,
            },
            SecretPattern {
                name: "AWS Secret Access Key",
                regex: Regex::new(r#"(?i)aws.{0,20}secret.{0,20}['"][0-9a-zA-Z/+]{40}['"]"#)
                    .unwrap(),
                severity: Severity::Critical,
            },
            SecretPattern {
                name: "AWS Session Token",
                regex: Regex::new(r"(?i)aws.{0,20}session.{0,20}token").unwrap(),
                severity: Severity::High,
            },
            // GitHub
            SecretPattern {
                name: "GitHub Personal Access Token (Classic)",
                regex: Regex::new(r"ghp_[a-zA-Z0-9]{36}").unwrap(),
                severity: Severity::Critical,
            },
            SecretPattern {
                name: "GitHub OAuth Access Token",
                regex: Regex::new(r"gho_[a-zA-Z0-9]{36}").unwrap(),
                severity: Severity::Critical,
            },
            SecretPattern {
                name: "GitHub App Token",
                regex: Regex::new(r"ghu_[a-zA-Z0-9]{36}").unwrap(),
                severity: Severity::Critical,
            },
            SecretPattern {
                name: "GitHub Server Token",
                regex: Regex::new(r"ghs_[a-zA-Z0-9]{36}").unwrap(),
                severity: Severity::Critical,
            },
            SecretPattern {
                name: "GitHub Fine-Grained PAT",
                regex: Regex::new(r"github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}").unwrap(),
                severity: Severity::Critical,
            },
            // AI Provider Keys
            SecretPattern {
                name: "OpenAI API Key",
                regex: Regex::new(r"sk-[a-zA-Z0-9]{48}").unwrap(),
                severity: Severity::High,
            },
            SecretPattern {
                name: "OpenAI Project Key",
                regex: Regex::new(r"sk-proj-[a-zA-Z0-9]{48}").unwrap(),
                severity: Severity::High,
            },
            SecretPattern {
                name: "Anthropic API Key",
                regex: Regex::new(r"sk-ant-[a-zA-Z0-9-]{93}").unwrap(),
                severity: Severity::High,
            },
            // Slack
            SecretPattern {
                name: "Slack Bot Token",
                regex: Regex::new(r"xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*").unwrap(),
                severity: Severity::High,
            },
            SecretPattern {
                name: "Slack User Token",
                regex: Regex::new(r"xoxp-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*").unwrap(),
                severity: Severity::High,
            },
            SecretPattern {
                name: "Slack Webhook URL",
                regex: Regex::new(
                    r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
                )
                .unwrap(),
                severity: Severity::High,
            },
            // Stripe
            SecretPattern {
                name: "Stripe Secret Key",
                regex: Regex::new(r"sk_live_[a-zA-Z0-9]{24,}").unwrap(),
                severity: Severity::Critical,
            },
            SecretPattern {
                name: "Stripe Restricted Key",
                regex: Regex::new(r"rk_live_[a-zA-Z0-9]{24,}").unwrap(),
                severity: Severity::Critical,
            },
            // Private Keys
            SecretPattern {
                name: "RSA Private Key",
                regex: Regex::new(r"-----BEGIN RSA PRIVATE KEY-----").unwrap(),
                severity: Severity::Critical,
            },
            SecretPattern {
                name: "EC Private Key",
                regex: Regex::new(r"-----BEGIN EC PRIVATE KEY-----").unwrap(),
                severity: Severity::Critical,
            },
            SecretPattern {
                name: "OpenSSH Private Key",
                regex: Regex::new(r"-----BEGIN OPENSSH PRIVATE KEY-----").unwrap(),
                severity: Severity::Critical,
            },
            SecretPattern {
                name: "PGP Private Key",
                regex: Regex::new(r"-----BEGIN PGP PRIVATE KEY BLOCK-----").unwrap(),
                severity: Severity::Critical,
            },
            // JWT
            SecretPattern {
                name: "JSON Web Token",
                regex: Regex::new(r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*").unwrap(),
                severity: Severity::High,
            },
            // Database URLs
            SecretPattern {
                name: "PostgreSQL Connection String",
                regex: Regex::new(r"postgres://[^:]+:[^@]+@[^/]+").unwrap(),
                severity: Severity::Critical,
            },
            SecretPattern {
                name: "MySQL Connection String",
                regex: Regex::new(r"mysql://[^:]+:[^@]+@[^/]+").unwrap(),
                severity: Severity::Critical,
            },
            SecretPattern {
                name: "MongoDB Connection String",
                regex: Regex::new(r"mongodb(\+srv)?://[^:]+:[^@]+@").unwrap(),
                severity: Severity::Critical,
            },
            SecretPattern {
                name: "Redis Connection String",
                regex: Regex::new(r"redis://[^:]*:[^@]+@").unwrap(),
                severity: Severity::Critical,
            },
            // Generic patterns
            SecretPattern {
                name: "Generic API Key Assignment",
                regex: Regex::new(r#"(?i)(?:api[_-]?key|apikey)\s*[:=]\s*['"][a-zA-Z0-9]{20,}['"]"#)
                    .unwrap(),
                severity: Severity::Medium,
            },
            SecretPattern {
                name: "Generic Secret Assignment",
                regex: Regex::new(r#"(?i)(?:secret|password|passwd|pwd)\s*[:=]\s*['"][^'"]{8,}['"]"#)
                    .unwrap(),
                severity: Severity::Medium,
            },
            SecretPattern {
                name: "Bearer Token",
                regex: Regex::new(r"(?i)bearer\s+[a-zA-Z0-9_.~+/=-]{20,}").unwrap(),
                severity: Severity::High,
            },
            SecretPattern {
                name: "Basic Auth Header",
                regex: Regex::new(r"(?i)basic\s+[a-zA-Z0-9+/=]{20,}").unwrap(),
                severity: Severity::High,
            },
            // Crypto
            SecretPattern {
                name: "Solana Private Key (byte array)",
                regex: Regex::new(r"\[(?:\s*\d{1,3}\s*,){63}\s*\d{1,3}\s*\]").unwrap(),
                severity: Severity::Critical,
            },
        ];

        Self { patterns }
    }

    /// Scan content for secrets
    fn scan_content(&self, content: &str) -> Option<(String, Severity)> {
        for pattern in &self.patterns {
            if pattern.regex.is_match(content) {
                debug!("Detected potential secret: {}", pattern.name);
                return Some((pattern.name.to_string(), pattern.severity));
            }
        }
        None
    }

    /// Get number of patterns
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }
}

impl Default for SecretLeakGuard {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Guard for SecretLeakGuard {
    fn name(&self) -> &str {
        "secret_leak"
    }

    async fn check(&self, event: &Event, _policy: &Policy) -> GuardResult {
        let content_to_scan = match (&event.event_type, &event.data) {
            (EventType::PatchApply, EventData::Patch(data)) => Some(&data.patch_content),
            _ => None,
        };

        if let Some(content) = content_to_scan {
            if let Some((secret_type, severity)) = self.scan_content(content) {
                return GuardResult::Deny {
                    reason: format!("Potential {} detected in content", secret_type),
                    severity,
                };
            }
        }

        GuardResult::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_patch_event(content: &str) -> Event {
        Event::patch_apply("/tmp/file.py", content)
    }

    #[test]
    fn test_has_sufficient_patterns() {
        let guard = SecretLeakGuard::new();
        assert!(
            guard.pattern_count() >= 15,
            "Should have at least 15 patterns"
        );
    }

    #[tokio::test]
    async fn test_allows_clean_content() {
        let guard = SecretLeakGuard::new();
        let policy = Policy::default();

        let event = make_patch_event("def hello():\n    print('Hello, world!')");
        let result = guard.check(&event, &policy).await;
        assert!(result.is_allowed());
    }

    #[tokio::test]
    async fn test_allows_normal_code() {
        let guard = SecretLeakGuard::new();
        let policy = Policy::default();

        let event = make_patch_event(
            r#"
            import os

            def main():
                config = load_config()
                return config.get('setting')
        "#,
        );
        let result = guard.check(&event, &policy).await;
        assert!(result.is_allowed());
    }

    #[tokio::test]
    async fn test_detects_aws_access_key() {
        let guard = SecretLeakGuard::new();
        let policy = Policy::default();

        let event = make_patch_event("AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'");
        let result = guard.check(&event, &policy).await;
        assert!(result.is_denied());
    }

    #[tokio::test]
    async fn test_detects_github_token_ghp() {
        let guard = SecretLeakGuard::new();
        let policy = Policy::default();

        let event = make_patch_event("token = 'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'");
        let result = guard.check(&event, &policy).await;
        assert!(result.is_denied());
    }

    #[tokio::test]
    async fn test_detects_github_token_gho() {
        let guard = SecretLeakGuard::new();
        let policy = Policy::default();

        let event = make_patch_event("GITHUB_TOKEN=gho_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
        let result = guard.check(&event, &policy).await;
        assert!(result.is_denied());
    }

    #[tokio::test]
    async fn test_detects_openai_key() {
        let guard = SecretLeakGuard::new();
        let policy = Policy::default();

        let event = make_patch_event(
            "OPENAI_API_KEY = 'sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'",
        );
        let result = guard.check(&event, &policy).await;
        assert!(result.is_denied());
    }

    #[tokio::test]
    async fn test_detects_anthropic_key() {
        let guard = SecretLeakGuard::new();
        let policy = Policy::default();

        // 93 character key after sk-ant-
        let key = "sk-ant-".to_string() + &"x".repeat(93);
        let event = make_patch_event(&format!("ANTHROPIC_API_KEY = '{}'", key));
        let result = guard.check(&event, &policy).await;
        assert!(result.is_denied());
    }

    #[tokio::test]
    async fn test_detects_rsa_private_key() {
        let guard = SecretLeakGuard::new();
        let policy = Policy::default();

        let event = make_patch_event(
            "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----",
        );
        let result = guard.check(&event, &policy).await;
        assert!(result.is_denied());
    }

    #[tokio::test]
    async fn test_detects_openssh_private_key() {
        let guard = SecretLeakGuard::new();
        let policy = Policy::default();

        let event = make_patch_event(
            "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXkt...\n-----END OPENSSH PRIVATE KEY-----",
        );
        let result = guard.check(&event, &policy).await;
        assert!(result.is_denied());
    }

    #[tokio::test]
    async fn test_detects_postgres_url() {
        let guard = SecretLeakGuard::new();
        let policy = Policy::default();

        let event =
            make_patch_event("DATABASE_URL = 'postgres://user:password123@localhost:5432/mydb'");
        let result = guard.check(&event, &policy).await;
        assert!(result.is_denied());
    }

    #[tokio::test]
    async fn test_detects_mongodb_url() {
        let guard = SecretLeakGuard::new();
        let policy = Policy::default();

        let event =
            make_patch_event("MONGO_URI = 'mongodb+srv://user:pass@cluster.mongodb.net/db'");
        let result = guard.check(&event, &policy).await;
        assert!(result.is_denied());
    }

    #[tokio::test]
    async fn test_detects_slack_bot_token() {
        let guard = SecretLeakGuard::new();
        let policy = Policy::default();

        let event = make_patch_event(
            "SLACK_TOKEN = 'xoxb-1234567890123-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx'",
        );
        let result = guard.check(&event, &policy).await;
        assert!(result.is_denied());
    }

    #[tokio::test]
    async fn test_detects_stripe_live_key() {
        let guard = SecretLeakGuard::new();
        let policy = Policy::default();

        let event = make_patch_event("STRIPE_KEY = 'sk_live_xxxxxxxxxxxxxxxxxxxxxxxx'");
        let result = guard.check(&event, &policy).await;
        assert!(result.is_denied());
    }

    #[tokio::test]
    async fn test_detects_jwt() {
        let guard = SecretLeakGuard::new();
        let policy = Policy::default();

        let event = make_patch_event("token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U'");
        let result = guard.check(&event, &policy).await;
        assert!(result.is_denied());
    }

    #[tokio::test]
    async fn test_detects_bearer_token() {
        let guard = SecretLeakGuard::new();
        let policy = Policy::default();

        let event = make_patch_event("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");
        let result = guard.check(&event, &policy).await;
        assert!(result.is_denied());
    }

    #[tokio::test]
    async fn test_ignores_file_read_events() {
        let guard = SecretLeakGuard::new();
        let policy = Policy::default();

        // File read events don't have content to scan
        let event = Event::file_read("/path/to/secrets.json");
        let result = guard.check(&event, &policy).await;
        assert!(result.is_allowed());
    }

    #[tokio::test]
    async fn test_ignores_network_events() {
        let guard = SecretLeakGuard::new();
        let policy = Policy::default();

        let event = Event::network_egress("api.github.com", 443);
        let result = guard.check(&event, &policy).await;
        assert!(result.is_allowed());
    }
}
