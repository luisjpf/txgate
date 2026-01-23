//! CLI integration tests for command-line argument parsing and execution flow.
//!
//! These tests verify that CLI arguments are correctly parsed and dispatched
//! to the appropriate command handlers.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::doc_markdown,
    clippy::uninlined_format_args,
    clippy::single_char_pattern
)]

use clap::Parser;
use sello::cli::{Cli, Commands, ConfigAction, EthereumCommands, OutputFormat};

/// Test parsing of various command combinations.
#[test]
fn test_cli_command_dispatch() {
    // Test init command
    let cli = Cli::try_parse_from(["sello", "init"]).expect("should parse");
    assert!(matches!(cli.command, Commands::Init { force: false }));

    // Test init with force
    let cli = Cli::try_parse_from(["sello", "init", "--force"]).expect("should parse");
    assert!(matches!(cli.command, Commands::Init { force: true }));

    // Test status command
    let cli = Cli::try_parse_from(["sello", "status"]).expect("should parse");
    assert!(matches!(cli.command, Commands::Status));

    // Test config command
    let cli = Cli::try_parse_from(["sello", "config"]).expect("should parse");
    assert!(matches!(cli.command, Commands::Config { action: None }));

    // Test serve command
    let cli = Cli::try_parse_from(["sello", "serve"]).expect("should parse");
    assert!(matches!(cli.command, Commands::Serve { foreground: false }));
}

/// Test Ethereum subcommand parsing.
#[test]
fn test_ethereum_subcommand_dispatch() {
    // Test address command
    let cli = Cli::try_parse_from(["sello", "ethereum", "address"]).expect("should parse");
    match cli.command {
        Commands::Ethereum {
            command: EthereumCommands::Address,
        } => {}
        _ => panic!("Expected Ethereum address command"),
    }

    // Test sign command with hex format
    let cli = Cli::try_parse_from(["sello", "ethereum", "sign", "0xabcd", "--format", "hex"])
        .expect("should parse");
    match cli.command {
        Commands::Ethereum {
            command:
                EthereumCommands::Sign {
                    transaction,
                    format,
                },
        } => {
            assert_eq!(transaction, "0xabcd");
            assert!(matches!(format, OutputFormat::Hex));
        }
        _ => panic!("Expected Ethereum sign command"),
    }

    // Test sign command with JSON format
    let cli = Cli::try_parse_from(["sello", "ethereum", "sign", "0x1234", "--format", "json"])
        .expect("should parse");
    match cli.command {
        Commands::Ethereum {
            command:
                EthereumCommands::Sign {
                    transaction,
                    format,
                },
        } => {
            assert_eq!(transaction, "0x1234");
            assert!(matches!(format, OutputFormat::Json));
        }
        _ => panic!("Expected Ethereum sign command with JSON"),
    }
}

/// Test verbose flag parsing.
#[test]
fn test_verbose_flag_parsing() {
    // No verbose flag
    let cli = Cli::try_parse_from(["sello", "status"]).expect("should parse");
    assert_eq!(cli.verbose, 0);

    // Single verbose
    let cli = Cli::try_parse_from(["sello", "-v", "status"]).expect("should parse");
    assert_eq!(cli.verbose, 1);

    // Double verbose
    let cli = Cli::try_parse_from(["sello", "-vv", "status"]).expect("should parse");
    assert_eq!(cli.verbose, 2);

    // Triple verbose
    let cli = Cli::try_parse_from(["sello", "-vvv", "status"]).expect("should parse");
    assert_eq!(cli.verbose, 3);

    // Verbose flag after command
    let cli = Cli::try_parse_from(["sello", "status", "-v"]).expect("should parse");
    assert_eq!(cli.verbose, 1);
}

/// Test config file option parsing.
#[test]
fn test_config_file_option() {
    // Long form
    let cli = Cli::try_parse_from(["sello", "--config", "/path/to/config.toml", "status"])
        .expect("should parse");
    assert_eq!(
        cli.config.as_deref().unwrap().to_str().unwrap(),
        "/path/to/config.toml"
    );

    // Short form
    let cli =
        Cli::try_parse_from(["sello", "-c", "/etc/sello.toml", "status"]).expect("should parse");
    assert_eq!(
        cli.config.as_deref().unwrap().to_str().unwrap(),
        "/etc/sello.toml"
    );

    // No config option
    let cli = Cli::try_parse_from(["sello", "status"]).expect("should parse");
    assert!(cli.config.is_none());
}

/// Test error cases for CLI parsing.
#[test]
fn test_cli_parsing_errors() {
    // No command
    let result = Cli::try_parse_from(["sello"]);
    assert!(result.is_err(), "Should fail when no command is provided");

    // Invalid command
    let result = Cli::try_parse_from(["sello", "invalid-command"]);
    assert!(result.is_err(), "Should fail for invalid command");

    // Missing required argument for sign
    let result = Cli::try_parse_from(["sello", "ethereum", "sign"]);
    assert!(result.is_err(), "Should fail when transaction is missing");

    // Invalid format for sign
    let result = Cli::try_parse_from(["sello", "ethereum", "sign", "0xabc", "--format", "xml"]);
    assert!(result.is_err(), "Should fail for invalid output format");
}

/// Test ConfigAction parsing.
#[test]
fn test_config_action_parsing() {
    // Config with edit action
    let cli = Cli::try_parse_from(["sello", "config", "edit"]).expect("should parse");
    match cli.command {
        Commands::Config {
            action: Some(ConfigAction::Edit),
        } => {}
        _ => panic!("Expected Config Edit command"),
    }

    // Config with path action
    let cli = Cli::try_parse_from(["sello", "config", "path"]).expect("should parse");
    match cli.command {
        Commands::Config {
            action: Some(ConfigAction::Path),
        } => {}
        _ => panic!("Expected Config Path command"),
    }

    // Config without action
    let cli = Cli::try_parse_from(["sello", "config"]).expect("should parse");
    match cli.command {
        Commands::Config { action: None } => {}
        _ => panic!("Expected Config command without action"),
    }
}

/// Test serve command options.
#[test]
fn test_serve_command_options() {
    // Serve without foreground
    let cli = Cli::try_parse_from(["sello", "serve"]).expect("should parse");
    match cli.command {
        Commands::Serve { foreground: false } => {}
        _ => panic!("Expected Serve command without foreground"),
    }

    // Serve with foreground (long form)
    let cli = Cli::try_parse_from(["sello", "serve", "--foreground"]).expect("should parse");
    match cli.command {
        Commands::Serve { foreground: true } => {}
        _ => panic!("Expected Serve command with foreground"),
    }

    // Serve with foreground (short form)
    let cli = Cli::try_parse_from(["sello", "serve", "-f"]).expect("should parse");
    match cli.command {
        Commands::Serve { foreground: true } => {}
        _ => panic!("Expected Serve command with foreground"),
    }
}

/// Test that CLI is Send and Sync.
#[test]
fn test_cli_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Cli>();
    assert_send_sync::<Commands>();
    assert_send_sync::<EthereumCommands>();
    assert_send_sync::<ConfigAction>();
    assert_send_sync::<OutputFormat>();
}

/// Test CLI Debug implementation.
#[test]
fn test_cli_debug() {
    let cli = Cli::try_parse_from(["sello", "-v", "status"]).expect("should parse");
    let debug_str = format!("{:?}", cli);

    assert!(debug_str.contains("verbose"));
    assert!(debug_str.contains("1"));
}

/// Test OutputFormat variants.
#[test]
fn test_output_format_variants() {
    // Test all variants
    let hex = OutputFormat::Hex;
    let json = OutputFormat::Json;

    assert_eq!(hex.to_string(), "hex");
    assert_eq!(json.to_string(), "json");

    // Test default
    let default = OutputFormat::default();
    assert!(matches!(default, OutputFormat::Hex));

    // Test Copy trait
    let format = OutputFormat::Json;
    let format_copy = format;
    assert!(matches!(format_copy, OutputFormat::Json));
}

/// Test combined options.
#[test]
fn test_combined_options() {
    // Verbose + config + command
    let cli = Cli::try_parse_from([
        "sello",
        "-vv",
        "--config",
        "/tmp/config.toml",
        "ethereum",
        "address",
    ])
    .expect("should parse");

    assert_eq!(cli.verbose, 2);
    assert!(cli.config.is_some());
    assert!(matches!(
        cli.command,
        Commands::Ethereum {
            command: EthereumCommands::Address
        }
    ));
}

/// Test that version information is available.
#[test]
fn test_version_info() {
    use clap::CommandFactory;

    let cmd = Cli::command();
    let version = cmd.get_version();
    assert!(version.is_some(), "Version should be available");

    // Test that --version flag works
    let result = Cli::try_parse_from(["sello", "--version"]);
    // This will fail because --version causes clap to exit, but we verify the flag exists
    assert!(result.is_err());
}

/// Test that help information is available.
#[test]
fn test_help_info() {
    use clap::CommandFactory;

    let cmd = Cli::command();

    // Test that all commands have help text
    for subcommand in cmd.get_subcommands() {
        let about = subcommand.get_about();
        assert!(
            about.is_some(),
            "Command '{}' should have help text",
            subcommand.get_name()
        );
    }
}
