//! Common test utilities for hushd integration tests

use std::net::TcpListener;
use std::process::{Child, Command};
use std::time::Duration;

/// Get the daemon URL from environment or use default
pub fn daemon_url() -> String {
    std::env::var("HUSHD_TEST_URL").unwrap_or_else(|_| "http://127.0.0.1:9876".to_string())
}

/// Find an available port for testing
pub fn find_available_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("Failed to bind to random port")
        .local_addr()
        .expect("Failed to get local address")
        .port()
}

/// Test daemon wrapper that manages lifecycle
pub struct TestDaemon {
    pub url: String,
    pub port: u16,
    process: Option<Child>,
}

impl TestDaemon {
    /// Spawn a new test daemon on an available port
    pub fn spawn() -> Self {
        let port = find_available_port();
        let url = format!("http://127.0.0.1:{}", port);

        // Build the daemon first (should already be built in CI)
        let daemon_path = std::env::var("HUSHD_BIN")
            .unwrap_or_else(|_| "target/debug/hushd".to_string());

        let process = Command::new(&daemon_path)
            .args(["start", "--bind", "127.0.0.1", "--port", &port.to_string()])
            .spawn()
            .expect("Failed to spawn daemon");

        let daemon = Self {
            url,
            port,
            process: Some(process),
        };

        // Wait for daemon to be ready
        daemon.wait_for_health(Duration::from_secs(10));

        daemon
    }

    /// Wait for the health endpoint to respond
    fn wait_for_health(&self, timeout: Duration) {
        let client = reqwest::blocking::Client::new();
        let start = std::time::Instant::now();

        while start.elapsed() < timeout {
            if let Ok(resp) = client.get(format!("{}/health", self.url)).send() {
                if resp.status().is_success() {
                    return;
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        panic!("Daemon failed to become healthy within {:?}", timeout);
    }

    /// Get HTTP client for making requests
    pub fn client(&self) -> reqwest::Client {
        reqwest::Client::new()
    }
}

impl Drop for TestDaemon {
    fn drop(&mut self) {
        if let Some(mut process) = self.process.take() {
            // Send SIGTERM on Unix, just kill on Windows
            #[cfg(unix)]
            {
                unsafe {
                    libc::kill(process.id() as i32, libc::SIGTERM);
                }
            }
            #[cfg(not(unix))]
            {
                let _ = process.kill();
            }
            let _ = process.wait();
        }
    }
}

/// Create a blocking reqwest client
pub fn blocking_client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::new()
}
