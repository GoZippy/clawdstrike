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

    use crate::{Cli, Commands, DaemonCommands, PolicyCommands};

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

    #[test]
    fn test_daemon_start_defaults() {
        let cli = Cli::parse_from(["hush", "daemon", "start"]);

        match cli.command {
            Commands::Daemon { command } => match command {
                DaemonCommands::Start { config, bind, port } => {
                    assert!(config.is_none());
                    assert_eq!(bind, "127.0.0.1");
                    assert_eq!(port, 9876);
                }
                _ => panic!("Expected Start subcommand"),
            },
            _ => panic!("Expected Daemon command"),
        }
    }

    #[test]
    fn test_daemon_start_with_options() {
        let cli = Cli::parse_from([
            "hush",
            "daemon",
            "start",
            "--config",
            "/etc/hush/config.yaml",
            "--bind",
            "0.0.0.0",
            "--port",
            "8080",
        ]);

        match cli.command {
            Commands::Daemon { command } => match command {
                DaemonCommands::Start { config, bind, port } => {
                    assert_eq!(config, Some("/etc/hush/config.yaml".to_string()));
                    assert_eq!(bind, "0.0.0.0");
                    assert_eq!(port, 8080);
                }
                _ => panic!("Expected Start subcommand"),
            },
            _ => panic!("Expected Daemon command"),
        }
    }

    #[test]
    fn test_daemon_status_default_url() {
        let cli = Cli::parse_from(["hush", "daemon", "status"]);

        match cli.command {
            Commands::Daemon { command } => match command {
                DaemonCommands::Status { url } => {
                    assert_eq!(url, "http://127.0.0.1:9876");
                }
                _ => panic!("Expected Status subcommand"),
            },
            _ => panic!("Expected Daemon command"),
        }
    }

    #[test]
    fn test_daemon_reload() {
        let cli = Cli::parse_from([
            "hush",
            "daemon",
            "reload",
            "http://localhost:9999",
        ]);

        match cli.command {
            Commands::Daemon { command } => match command {
                DaemonCommands::Reload { url } => {
                    assert_eq!(url, "http://localhost:9999");
                }
                _ => panic!("Expected Reload subcommand"),
            },
            _ => panic!("Expected Daemon command"),
        }
    }

    #[test]
    fn test_completions_bash() {
        let cli = Cli::parse_from(["hush", "completions", "bash"]);

        match cli.command {
            Commands::Completions { shell } => {
                assert_eq!(shell, clap_complete::Shell::Bash);
            }
            _ => panic!("Expected Completions command"),
        }
    }

    #[test]
    fn test_completions_zsh() {
        let cli = Cli::parse_from(["hush", "completions", "zsh"]);

        match cli.command {
            Commands::Completions { shell } => {
                assert_eq!(shell, clap_complete::Shell::Zsh);
            }
            _ => panic!("Expected Completions command"),
        }
    }

    #[test]
    fn test_completions_fish() {
        let cli = Cli::parse_from(["hush", "completions", "fish"]);

        match cli.command {
            Commands::Completions { shell } => {
                assert_eq!(shell, clap_complete::Shell::Fish);
            }
            _ => panic!("Expected Completions command"),
        }
    }

    #[test]
    fn test_version_flag() {
        let result = Cli::try_parse_from(["hush", "--version"]);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayVersion);
    }

    #[test]
    fn test_help_flag() {
        let result = Cli::try_parse_from(["hush", "--help"]);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
    }

    #[test]
    fn test_invalid_command_fails() {
        let result = Cli::try_parse_from(["hush", "nonexistent-command"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_verbose_flag_counts() {
        let cli = Cli::parse_from(["hush", "-vvv", "policy", "list"]);
        assert_eq!(cli.verbose, 3);
    }
}

#[cfg(test)]
mod completions {
    use clap::CommandFactory;
    use clap_complete::{generate, Shell};

    use crate::Cli;

    #[test]
    fn test_bash_completions_generated() {
        let mut cmd = Cli::command();
        let mut output = Vec::new();
        generate(Shell::Bash, &mut cmd, "hush", &mut output);

        let script = String::from_utf8(output).expect("valid UTF-8");
        assert!(script.contains("_hush"), "Should contain bash function");
        assert!(script.contains("check"), "Should contain check subcommand");
        assert!(script.contains("completions"), "Should contain completions subcommand");
    }

    #[test]
    fn test_zsh_completions_generated() {
        let mut cmd = Cli::command();
        let mut output = Vec::new();
        generate(Shell::Zsh, &mut cmd, "hush", &mut output);

        let script = String::from_utf8(output).expect("valid UTF-8");
        assert!(script.contains("#compdef hush"), "Should have zsh compdef header");
        assert!(script.contains("check"), "Should contain check subcommand");
    }

    #[test]
    fn test_fish_completions_generated() {
        let mut cmd = Cli::command();
        let mut output = Vec::new();
        generate(Shell::Fish, &mut cmd, "hush", &mut output);

        let script = String::from_utf8(output).expect("valid UTF-8");
        assert!(script.contains("complete -c hush"), "Should have fish complete command");
    }
}
