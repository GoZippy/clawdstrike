//! Hushd - Hushclaw daemon for runtime security enforcement
//!
//! This daemon provides:
//! - HTTP API for action checking
//! - WebSocket for real-time monitoring
//! - Receipt signing and attestation

use clap::Parser;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use hushclaw::{HushEngine, RuleSet};

#[derive(Parser)]
#[command(name = "hushd")]
#[command(about = "Hushclaw security daemon", long_about = None)]
struct Cli {
    /// Verbosity level
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Bind address
    #[arg(short, long, default_value = "127.0.0.1")]
    bind: String,

    /// Port
    #[arg(short, long, default_value = "9876")]
    port: u16,

    /// Ruleset to use
    #[arg(short, long, default_value = "default")]
    ruleset: String,

    /// Path to signing key
    #[arg(short, long)]
    key: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let log_level = match cli.verbose {
        0 => tracing::Level::INFO,
        1 => tracing::Level::DEBUG,
        _ => tracing::Level::TRACE,
    };

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_subscriber::filter::LevelFilter::from_level(log_level))
        .init();

    // Load ruleset
    let ruleset = RuleSet::by_name(&cli.ruleset)
        .ok_or_else(|| anyhow::anyhow!("Unknown ruleset: {}", cli.ruleset))?;

    tracing::info!(
        ruleset = ruleset.id,
        "Starting hushd with ruleset"
    );

    // Create engine
    let mut engine = HushEngine::with_policy(ruleset.policy);

    // Load signing key if provided
    if let Some(key_path) = cli.key {
        let key_hex = std::fs::read_to_string(&key_path)?.trim().to_string();
        let keypair = hush_core::Keypair::from_hex(&key_hex)?;
        engine = engine.with_keypair(keypair);
        tracing::info!("Loaded signing key from {}", key_path);
    } else {
        engine = engine.with_generated_keypair();
        tracing::warn!("Using generated ephemeral keypair (receipts won't be verifiable across restarts)");
    }

    // TODO: Implement HTTP server
    // For now, just print status and wait
    tracing::info!(
        bind = cli.bind,
        port = cli.port,
        "Hushd ready (HTTP server not yet implemented)"
    );

    // Keep the daemon running
    tokio::signal::ctrl_c().await?;
    tracing::info!("Shutting down");

    // Print final stats
    let stats = engine.stats().await;
    tracing::info!(
        actions = stats.action_count,
        violations = stats.violation_count,
        "Final session stats"
    );

    Ok(())
}
