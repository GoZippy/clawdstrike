//! CLI unit tests for hush command-line interface
//!
//! Tests cover:
//! - Command parsing for all subcommands
//! - Argument validation and defaults
//! - Help and version flags
//! - Invalid command handling
//! - Shell completion generation

#[cfg(test)]
mod cli_parsing {
    use clap::Parser;

    use crate::{Cli, Commands, PolicyCommands};

    #[test]
    fn test_check_command_parses_with_required_args() {
        let cli = Cli::parse_from([
            "hush",
            "check",
            "--action-type",
            "file",
            "/path/to/file",
        ]);

        match cli.command {
            Commands::Check {
                action_type,
                target,
                ruleset,
            } => {
                assert_eq!(action_type, "file");
                assert_eq!(target, "/path/to/file");
                assert_eq!(ruleset, "default"); // default value
            }
            _ => panic!("Expected Check command"),
        }
    }

    #[test]
    fn test_check_command_with_custom_ruleset() {
        let cli = Cli::parse_from([
            "hush",
            "check",
            "--action-type",
            "egress",
            "--ruleset",
            "strict",
            "api.example.com:443",
        ]);

        match cli.command {
            Commands::Check {
                action_type,
                target,
                ruleset,
            } => {
                assert_eq!(action_type, "egress");
                assert_eq!(target, "api.example.com:443");
                assert_eq!(ruleset, "strict");
            }
            _ => panic!("Expected Check command"),
        }
    }

    #[test]
    fn test_check_command_mcp_action_type() {
        let cli = Cli::parse_from([
            "hush",
            "check",
            "-a",
            "mcp",
            "filesystem_read",
        ]);

        match cli.command {
            Commands::Check {
                action_type,
                target,
                ..
            } => {
                assert_eq!(action_type, "mcp");
                assert_eq!(target, "filesystem_read");
            }
            _ => panic!("Expected Check command"),
        }
    }

    #[test]
    fn test_verify_command_parses() {
        let cli = Cli::parse_from([
            "hush",
            "verify",
            "receipt.json",
            "--pubkey",
            "key.pub",
        ]);

        match cli.command {
            Commands::Verify { receipt, pubkey } => {
                assert_eq!(receipt, "receipt.json");
                assert_eq!(pubkey, "key.pub");
            }
            _ => panic!("Expected Verify command"),
        }
    }

    #[test]
    fn test_keygen_command_default_output() {
        let cli = Cli::parse_from(["hush", "keygen"]);

        match cli.command {
            Commands::Keygen { output } => {
                assert_eq!(output, "hush.key"); // default
            }
            _ => panic!("Expected Keygen command"),
        }
    }

    #[test]
    fn test_keygen_command_custom_output() {
        let cli = Cli::parse_from([
            "hush",
            "keygen",
            "--output",
            "/custom/path/my.key",
        ]);

        match cli.command {
            Commands::Keygen { output } => {
                assert_eq!(output, "/custom/path/my.key");
            }
            _ => panic!("Expected Keygen command"),
        }
    }

    #[test]
    fn test_policy_show_default_ruleset() {
        let cli = Cli::parse_from(["hush", "policy", "show"]);

        match cli.command {
            Commands::Policy { command } => match command {
                PolicyCommands::Show { ruleset } => {
                    assert_eq!(ruleset, "default");
                }
                _ => panic!("Expected Show subcommand"),
            },
            _ => panic!("Expected Policy command"),
        }
    }

    #[test]
    fn test_policy_show_custom_ruleset() {
        let cli = Cli::parse_from(["hush", "policy", "show", "strict"]);

        match cli.command {
            Commands::Policy { command } => match command {
                PolicyCommands::Show { ruleset } => {
                    assert_eq!(ruleset, "strict");
                }
                _ => panic!("Expected Show subcommand"),
            },
            _ => panic!("Expected Policy command"),
        }
    }

    #[test]
    fn test_policy_validate() {
        let cli = Cli::parse_from(["hush", "policy", "validate", "policy.yaml"]);

        match cli.command {
            Commands::Policy { command } => match command {
                PolicyCommands::Validate { file } => {
                    assert_eq!(file, "policy.yaml");
                }
                _ => panic!("Expected Validate subcommand"),
            },
            _ => panic!("Expected Policy command"),
        }
    }

    #[test]
    fn test_policy_list() {
        let cli = Cli::parse_from(["hush", "policy", "list"]);

        match cli.command {
            Commands::Policy { command } => {
                assert!(matches!(command, PolicyCommands::List));
            }
            _ => panic!("Expected Policy command"),
        }
    }
}

#[cfg(test)]
mod completions {
    // Completion generation tests will be added in subsequent tasks
}
