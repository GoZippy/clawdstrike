//! Hush CLI - Command-line interface for hushclaw
//!
//! Commands:
//! - hush check <action> - Check an action against policy
//! - hush verify <receipt> - Verify a signed receipt
//! - hush keygen - Generate a signing keypair
//! - hush policy show - Show current policy
//! - hush policy validate <file> - Validate a policy file

use clap::{Parser, Subcommand};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use hush_core::{Keypair, SignedReceipt};
use hushclaw::{GuardContext, HushEngine, Policy, RuleSet};

#[derive(Parser)]
#[command(name = "hush")]
#[command(about = "Hushclaw security guard CLI", long_about = None)]
struct Cli {
    /// Verbosity level
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Check an action against policy
    Check {
        /// Action type (file, egress, mcp)
        #[arg(short, long)]
        action_type: String,

        /// Target (path, host, tool name)
        target: String,

        /// Ruleset to use
        #[arg(short, long, default_value = "default")]
        ruleset: String,
    },

    /// Verify a signed receipt
    Verify {
        /// Path to receipt JSON file
        receipt: String,

        /// Path to public key file
        #[arg(short, long)]
        pubkey: String,
    },

    /// Generate a signing keypair
    Keygen {
        /// Output path for private key
        #[arg(short, long, default_value = "hush.key")]
        output: String,
    },

    /// Policy commands
    Policy {
        #[command(subcommand)]
        command: PolicyCommands,
    },
}

#[derive(Subcommand)]
enum PolicyCommands {
    /// Show a ruleset's policy
    Show {
        /// Ruleset name
        #[arg(default_value = "default")]
        ruleset: String,
    },

    /// Validate a policy file
    Validate {
        /// Path to policy YAML file
        file: String,
    },

    /// List available rulesets
    List,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let log_level = match cli.verbose {
        0 => tracing::Level::WARN,
        1 => tracing::Level::INFO,
        2 => tracing::Level::DEBUG,
        _ => tracing::Level::TRACE,
    };

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_subscriber::filter::LevelFilter::from_level(
            log_level,
        ))
        .init();

    match cli.command {
        Commands::Check {
            action_type,
            target,
            ruleset,
        } => {
            let engine = HushEngine::from_ruleset(&ruleset)
                .map_err(|e| anyhow::anyhow!("Failed to load ruleset: {}", e))?;
            let context = GuardContext::new();

            let result = match action_type.as_str() {
                "file" => engine.check_file_access(&target, &context).await?,
                "egress" => {
                    let parts: Vec<&str> = target.split(':').collect();
                    let host = parts[0];
                    let port: u16 = parts.get(1).unwrap_or(&"443").parse()?;
                    engine.check_egress(host, port, &context).await?
                }
                "mcp" => {
                    let args = serde_json::json!({});
                    engine.check_mcp_tool(&target, &args, &context).await?
                }
                _ => anyhow::bail!("Unknown action type: {}", action_type),
            };

            if result.allowed {
                println!("ALLOWED: {}", result.message);
            } else {
                println!("BLOCKED [{:?}]: {}", result.severity, result.message);
                std::process::exit(1);
            }
        }

        Commands::Verify { receipt, pubkey } => {
            let receipt_json = std::fs::read_to_string(&receipt)?;
            let signed: SignedReceipt = serde_json::from_str(&receipt_json)?;

            let pubkey_hex = std::fs::read_to_string(&pubkey)?.trim().to_string();
            let public_key = hush_core::PublicKey::from_hex(&pubkey_hex)?;

            let keys = hush_core::receipt::PublicKeySet::new(public_key);
            let result = signed.verify(&keys);

            if result.valid {
                println!("VALID: Receipt signature verified");
                println!(
                    "  Verdict: {}",
                    if signed.receipt.verdict.passed {
                        "PASS"
                    } else {
                        "FAIL"
                    }
                );
            } else {
                println!("INVALID: {}", result.errors.join(", "));
                std::process::exit(1);
            }
        }

        Commands::Keygen { output } => {
            let keypair = Keypair::generate();
            let private_hex = keypair.to_hex();
            let public_hex = keypair.public_key().to_hex();

            std::fs::write(&output, &private_hex)?;
            std::fs::write(format!("{}.pub", output), &public_hex)?;

            println!("Generated keypair:");
            println!("  Private key: {}", output);
            println!("  Public key:  {}.pub", output);
            println!("  Public key (hex): {}", public_hex);
        }

        Commands::Policy { command } => match command {
            PolicyCommands::Show { ruleset } => {
                let rs = RuleSet::by_name(&ruleset)
                    .ok_or_else(|| anyhow::anyhow!("Unknown ruleset: {}", ruleset))?;
                let yaml = rs.policy.to_yaml()?;
                println!("# Ruleset: {} ({})", rs.name, rs.id);
                println!("# {}", rs.description);
                println!("{}", yaml);
            }

            PolicyCommands::Validate { file } => {
                let policy = Policy::from_yaml_file(&file)?;
                println!("Policy is valid:");
                println!("  Version: {}", policy.version);
                println!("  Name: {}", policy.name);
            }

            PolicyCommands::List => {
                println!("Available rulesets:");
                for name in ["default", "strict", "permissive"] {
                    let rs = RuleSet::by_name(name).unwrap();
                    println!("  {} - {}", rs.id, rs.description);
                }
            }
        },
    }

    Ok(())
}
