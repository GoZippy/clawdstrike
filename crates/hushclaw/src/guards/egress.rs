//! Egress Allowlist Guard
//!
//! Controls outbound network connections based on domain allowlist and CIDR ranges.

use std::net::IpAddr;
use std::str::FromStr;

use async_trait::async_trait;
use ipnet::IpNet;
use tracing::debug;

use super::{Guard, GuardResult};
use crate::error::Severity;
use crate::event::{Event, EventData, EventType};
use crate::policy::{EgressMode, Policy};

/// Guard that enforces network egress policies
pub struct EgressAllowlistGuard;

impl EgressAllowlistGuard {
    pub fn new() -> Self {
        Self
    }

    /// Check if host is a private IP address (SSRF prevention)
    fn is_private_ip(&self, host: &str) -> bool {
        if let Ok(ip) = IpAddr::from_str(host) {
            return match ip {
                IpAddr::V4(v4) => {
                    v4.is_loopback()           // 127.0.0.0/8
                        || v4.is_private()     // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                        || v4.is_link_local()  // 169.254.0.0/16
                        || v4.is_broadcast()
                        || v4.octets()[0] == 0 // 0.0.0.0/8
                }
                IpAddr::V6(v6) => {
                    v6.is_loopback() || v6.is_unspecified()
                    // Note: is_unique_local() and is_unicast_link_local() are unstable
                }
            };
        }
        false
    }

    /// Check if domain matches a pattern (supports wildcards)
    fn matches_domain(&self, domain: &str, pattern: &str) -> bool {
        let domain = domain.to_lowercase();
        let pattern = pattern.to_lowercase();

        if let Some(base) = pattern.strip_prefix("*.") {
            // Wildcard match: *.github.com matches api.github.com
            let suffix = &pattern[1..]; // ".github.com"
            domain.ends_with(suffix) || domain == base
        } else {
            // Exact match or subdomain match
            domain == pattern || domain.ends_with(&format!(".{}", pattern))
        }
    }

    /// Check domain against policy
    fn check_domain(&self, domain: &str, policy: &Policy) -> GuardResult {
        let egress = &policy.egress;

        // Deny list always takes precedence
        for deny in &egress.denied_domains {
            if self.matches_domain(domain, deny) {
                debug!("Domain {} matches deny pattern {}", domain, deny);
                return GuardResult::Deny {
                    reason: format!("Domain '{}' is explicitly blocked", domain),
                    severity: Severity::High,
                };
            }
        }

        // Check private IP blocking
        if egress.block_private_ips && self.is_private_ip(domain) {
            return GuardResult::Deny {
                reason: format!("Private IP address '{}' blocked (SSRF prevention)", domain),
                severity: Severity::High,
            };
        }

        match egress.mode {
            EgressMode::Open => GuardResult::Allow,
            EgressMode::DenyAll => GuardResult::Deny {
                reason: "All network egress is blocked".to_string(),
                severity: Severity::Medium,
            },
            EgressMode::Allowlist => {
                // Check if domain matches allowlist
                for allowed in &egress.allowed_domains {
                    if self.matches_domain(domain, allowed) {
                        debug!("Domain {} matches allowlist entry {}", domain, allowed);
                        return GuardResult::Allow;
                    }
                }

                GuardResult::Deny {
                    reason: format!("Domain '{}' is not in the allowlist", domain),
                    severity: Severity::Medium,
                }
            }
        }
    }

    /// Check IP address against policy
    fn check_ip(&self, ip_str: &str, policy: &Policy) -> GuardResult {
        let ip: IpAddr = match IpAddr::from_str(ip_str) {
            Ok(ip) => ip,
            Err(_) => {
                // Not a valid IP, treat as domain
                return self.check_domain(ip_str, policy);
            }
        };

        let egress = &policy.egress;

        // Check private IP blocking
        if egress.block_private_ips && self.is_private_ip(ip_str) {
            return GuardResult::Deny {
                reason: format!("Private IP address '{}' blocked (SSRF prevention)", ip_str),
                severity: Severity::High,
            };
        }

        match egress.mode {
            EgressMode::Open => GuardResult::Allow,
            EgressMode::DenyAll => GuardResult::Deny {
                reason: "All network egress is blocked".to_string(),
                severity: Severity::Medium,
            },
            EgressMode::Allowlist => {
                // Check against allowed CIDRs
                for cidr_str in &egress.allowed_cidrs {
                    if let Ok(cidr) = IpNet::from_str(cidr_str) {
                        if cidr.contains(&ip) {
                            debug!("IP {} matches allowed CIDR {}", ip, cidr);
                            return GuardResult::Allow;
                        }
                    }
                }

                GuardResult::Deny {
                    reason: format!("IP '{}' is not in any allowed CIDR range", ip),
                    severity: Severity::Medium,
                }
            }
        }
    }
}

impl Default for EgressAllowlistGuard {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Guard for EgressAllowlistGuard {
    fn name(&self) -> &str {
        "egress_allowlist"
    }

    async fn check(&self, event: &Event, policy: &Policy) -> GuardResult {
        match (&event.event_type, &event.data) {
            (EventType::NetworkEgress, EventData::Network(data)) => {
                // First try as IP, then as domain
                let result = self.check_ip(&data.host, policy);
                if matches!(result, GuardResult::Deny { .. })
                    && data.host.parse::<IpAddr>().is_err()
                {
                    // It's a hostname, check as domain
                    self.check_domain(&data.host, policy)
                } else {
                    result
                }
            }
            _ => GuardResult::Allow,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_network_event(host: &str, port: u16) -> Event {
        Event::network_egress(host, port)
    }

    #[tokio::test]
    async fn test_allows_allowlisted_domain() {
        let guard = EgressAllowlistGuard::new();
        let policy = Policy::default();

        let event = make_network_event("api.openai.com", 443);
        let result = guard.check(&event, &policy).await;
        assert!(result.is_allowed());
    }

    #[tokio::test]
    async fn test_allows_github() {
        let guard = EgressAllowlistGuard::new();
        let policy = Policy::default();

        let event = make_network_event("api.github.com", 443);
        let result = guard.check(&event, &policy).await;
        assert!(result.is_allowed());
    }

    #[tokio::test]
    async fn test_allows_subdomain_of_allowlisted() {
        let guard = EgressAllowlistGuard::new();
        let policy = Policy::default();

        let event = make_network_event("raw.githubusercontent.com", 443);
        let result = guard.check(&event, &policy).await;
        assert!(result.is_allowed());
    }

    #[tokio::test]
    async fn test_blocks_unknown_domain() {
        let guard = EgressAllowlistGuard::new();
        let policy = Policy::default();

        let event = make_network_event("evil.com", 443);
        let result = guard.check(&event, &policy).await;
        assert!(result.is_denied());
    }

    #[tokio::test]
    async fn test_blocks_onion_domain() {
        let guard = EgressAllowlistGuard::new();
        let policy = Policy::default();

        let event = make_network_event("something.onion", 80);
        let result = guard.check(&event, &policy).await;
        assert!(result.is_denied());
    }

    #[tokio::test]
    async fn test_deny_list_takes_precedence() {
        let guard = EgressAllowlistGuard::new();
        let mut policy = Policy::default();
        policy.egress.allowed_domains.push("evil.com".to_string());
        policy.egress.denied_domains.push("evil.com".to_string());

        let event = make_network_event("evil.com", 443);
        let result = guard.check(&event, &policy).await;
        assert!(result.is_denied());
    }

    #[tokio::test]
    async fn test_blocks_localhost() {
        let guard = EgressAllowlistGuard::new();
        let policy = Policy::default();

        let event = make_network_event("127.0.0.1", 8080);
        let result = guard.check(&event, &policy).await;
        assert!(result.is_denied());
    }

    #[tokio::test]
    async fn test_blocks_private_ip_10() {
        let guard = EgressAllowlistGuard::new();
        let policy = Policy::default();

        let event = make_network_event("10.0.0.1", 443);
        let result = guard.check(&event, &policy).await;
        assert!(result.is_denied());
    }

    #[tokio::test]
    async fn test_blocks_private_ip_192() {
        let guard = EgressAllowlistGuard::new();
        let policy = Policy::default();

        let event = make_network_event("192.168.1.1", 443);
        let result = guard.check(&event, &policy).await;
        assert!(result.is_denied());
    }

    #[tokio::test]
    async fn test_blocks_private_ip_172() {
        let guard = EgressAllowlistGuard::new();
        let policy = Policy::default();

        let event = make_network_event("172.16.0.1", 443);
        let result = guard.check(&event, &policy).await;
        assert!(result.is_denied());
    }

    #[tokio::test]
    async fn test_allows_private_ip_when_disabled() {
        let guard = EgressAllowlistGuard::new();
        let mut policy = Policy::default();
        policy.egress.block_private_ips = false;
        policy.egress.allowed_cidrs.push("10.0.0.0/8".to_string());

        let event = make_network_event("10.0.0.1", 443);
        let result = guard.check(&event, &policy).await;
        assert!(result.is_allowed());
    }

    #[tokio::test]
    async fn test_allows_cidr_range() {
        let guard = EgressAllowlistGuard::new();
        let mut policy = Policy::default();
        policy.egress.block_private_ips = false;
        policy.egress.allowed_cidrs.push("10.0.0.0/8".to_string());

        let event = make_network_event("10.1.2.3", 443);
        let result = guard.check(&event, &policy).await;
        assert!(result.is_allowed());
    }

    #[tokio::test]
    async fn test_open_mode_allows_all() {
        let guard = EgressAllowlistGuard::new();
        let mut policy = Policy::default();
        policy.egress.mode = EgressMode::Open;

        let event = make_network_event("random-site.com", 443);
        let result = guard.check(&event, &policy).await;
        assert!(result.is_allowed());
    }

    #[tokio::test]
    async fn test_deny_all_mode_blocks_all() {
        let guard = EgressAllowlistGuard::new();
        let mut policy = Policy::default();
        policy.egress.mode = EgressMode::DenyAll;

        let event = make_network_event("api.github.com", 443);
        let result = guard.check(&event, &policy).await;
        assert!(result.is_denied());
    }

    #[tokio::test]
    async fn test_wildcard_domain_matching() {
        let guard = EgressAllowlistGuard::new();
        let mut policy = Policy::default();
        policy.egress.allowed_domains = vec!["*.example.com".to_string()];

        let event = make_network_event("api.example.com", 443);
        let result = guard.check(&event, &policy).await;
        assert!(result.is_allowed());

        let event2 = make_network_event("example.com", 443);
        let result2 = guard.check(&event2, &policy).await;
        assert!(result2.is_allowed());
    }

    #[tokio::test]
    async fn test_ignores_file_events() {
        let guard = EgressAllowlistGuard::new();
        let policy = Policy::default();

        let event = Event::file_read("/etc/passwd");
        let result = guard.check(&event, &policy).await;
        assert!(result.is_allowed());
    }
}
