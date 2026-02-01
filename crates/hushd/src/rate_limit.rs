//! Rate limiting middleware for hushd
//!
//! Uses a token bucket algorithm with per-IP rate limiting.
//! The /health endpoint is excluded from rate limiting.

use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;

use axum::{
    body::Body,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use governor::{
    clock::DefaultClock,
    middleware::NoOpMiddleware,
    state::InMemoryState,
    Quota, RateLimiter,
};

use crate::config::RateLimitConfig;

/// Type alias for our keyed rate limiter
pub type KeyedRateLimiter =
    RateLimiter<IpAddr, dashmap::DashMap<IpAddr, InMemoryState>, DefaultClock, NoOpMiddleware>;

/// Shared rate limiter state
#[derive(Clone)]
pub struct RateLimitState {
    limiter: Option<Arc<KeyedRateLimiter>>,
    config: RateLimitConfig,
}

impl RateLimitState {
    /// Create a new rate limit state from config
    pub fn new(config: &RateLimitConfig) -> Self {
        if !config.enabled {
            return Self {
                limiter: None,
                config: config.clone(),
            };
        }

        // Create quota: burst_size requests, refilling at requests_per_second
        let quota = Quota::per_second(
            NonZeroU32::new(config.requests_per_second).unwrap_or(NonZeroU32::new(100).unwrap()),
        )
        .allow_burst(NonZeroU32::new(config.burst_size).unwrap_or(NonZeroU32::new(50).unwrap()));

        let limiter = RateLimiter::keyed(quota);

        Self {
            limiter: Some(Arc::new(limiter)),
            config: config.clone(),
        }
    }

    /// Check if rate limiting is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled && self.limiter.is_some()
    }
}

/// Rate limiting middleware
///
/// Returns 429 Too Many Requests if the client exceeds their rate limit.
/// The /health endpoint is excluded from rate limiting.
pub async fn rate_limit_middleware(
    axum::extract::State(rate_limit): axum::extract::State<RateLimitState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    // Skip rate limiting if disabled
    if !rate_limit.is_enabled() {
        return next.run(req).await;
    }

    // Skip rate limiting for health endpoint
    if req.uri().path() == "/health" {
        return next.run(req).await;
    }

    // Extract client IP
    let client_ip = extract_client_ip(&req);

    // Check rate limit
    if let Some(ref limiter) = rate_limit.limiter {
        match limiter.check_key(&client_ip) {
            Ok(_) => {
                // Request allowed
                next.run(req).await
            }
            Err(_not_until) => {
                // Rate limit exceeded
                tracing::debug!(
                    client_ip = %client_ip,
                    "Rate limit exceeded"
                );
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    [("Retry-After", "1")],
                    "Rate limit exceeded. Please slow down.",
                )
                    .into_response()
            }
        }
    } else {
        next.run(req).await
    }
}

/// Extract client IP from request
///
/// Checks X-Forwarded-For header first, then falls back to connection info.
fn extract_client_ip(req: &Request<Body>) -> IpAddr {
    // Check X-Forwarded-For header (for proxied requests)
    if let Some(forwarded) = req
        .headers()
        .get("X-Forwarded-For")
        .and_then(|v| v.to_str().ok())
    {
        // Take the first IP in the chain
        if let Some(ip_str) = forwarded.split(',').next() {
            if let Ok(ip) = ip_str.trim().parse() {
                return ip;
            }
        }
    }

    // Check X-Real-IP header
    if let Some(real_ip) = req
        .headers()
        .get("X-Real-IP")
        .and_then(|v| v.to_str().ok())
    {
        if let Ok(ip) = real_ip.trim().parse() {
            return ip;
        }
    }

    // Fall back to a default IP (in production, you'd use ConnectInfo)
    // For now, use loopback as fallback
    IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_state_disabled() {
        let config = RateLimitConfig {
            enabled: false,
            requests_per_second: 100,
            burst_size: 50,
        };
        let state = RateLimitState::new(&config);
        assert!(!state.is_enabled());
        assert!(state.limiter.is_none());
    }

    #[test]
    fn test_rate_limit_state_enabled() {
        let config = RateLimitConfig {
            enabled: true,
            requests_per_second: 100,
            burst_size: 50,
        };
        let state = RateLimitState::new(&config);
        assert!(state.is_enabled());
        assert!(state.limiter.is_some());
    }

    #[test]
    fn test_rate_limiter_allows_requests_within_limit() {
        let config = RateLimitConfig {
            enabled: true,
            requests_per_second: 10,
            burst_size: 5,
        };
        let state = RateLimitState::new(&config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Should allow burst_size requests immediately
        for _ in 0..5 {
            assert!(state.limiter.as_ref().unwrap().check_key(&ip).is_ok());
        }
    }

    #[test]
    fn test_rate_limiter_blocks_after_burst() {
        let config = RateLimitConfig {
            enabled: true,
            requests_per_second: 10,
            burst_size: 3,
        };
        let state = RateLimitState::new(&config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Exhaust the burst
        for _ in 0..3 {
            assert!(state.limiter.as_ref().unwrap().check_key(&ip).is_ok());
        }

        // Next request should be blocked
        assert!(state.limiter.as_ref().unwrap().check_key(&ip).is_err());
    }

    #[test]
    fn test_rate_limiter_separate_ips() {
        let config = RateLimitConfig {
            enabled: true,
            requests_per_second: 10,
            burst_size: 2,
        };
        let state = RateLimitState::new(&config);
        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "192.168.1.2".parse().unwrap();

        // Exhaust burst for ip1
        for _ in 0..2 {
            assert!(state.limiter.as_ref().unwrap().check_key(&ip1).is_ok());
        }
        assert!(state.limiter.as_ref().unwrap().check_key(&ip1).is_err());

        // ip2 should still have full quota
        for _ in 0..2 {
            assert!(state.limiter.as_ref().unwrap().check_key(&ip2).is_ok());
        }
    }

    #[test]
    fn test_extract_client_ip_from_forwarded() {
        let req = Request::builder()
            .header("X-Forwarded-For", "203.0.113.195, 70.41.3.18, 150.172.238.178")
            .body(Body::empty())
            .unwrap();

        let ip = extract_client_ip(&req);
        assert_eq!(ip, "203.0.113.195".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_extract_client_ip_from_real_ip() {
        let req = Request::builder()
            .header("X-Real-IP", "203.0.113.195")
            .body(Body::empty())
            .unwrap();

        let ip = extract_client_ip(&req);
        assert_eq!(ip, "203.0.113.195".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_extract_client_ip_fallback() {
        let req = Request::builder().body(Body::empty()).unwrap();

        let ip = extract_client_ip(&req);
        assert_eq!(ip, "127.0.0.1".parse::<IpAddr>().unwrap());
    }
}
