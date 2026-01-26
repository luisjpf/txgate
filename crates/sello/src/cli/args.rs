//! # CLI Argument Definitions
//!
//! This module defines the command-line interface structure using clap derive macros.
//!
//! ## Main CLI Structure
//!
//! The CLI is structured as follows:
//!
//! - `sello init` - Initialize Sello configuration
//! - `sello status` - Display current status
//! - `sello config [edit|path]` - View or edit configuration
//! - `sello serve` - Start the signing server
//! - `sello ethereum address` - Display Ethereum address
//! - `sello ethereum sign <TX_HEX>` - Sign an Ethereum transaction
//!
//! ## Global Options
//!
//! - `-v, --verbose` - Increase verbosity level
//! - `-c, --config <PATH>` - Path to configuration file

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

/// Secure transaction signing daemon.
///
/// Sello provides a secure environment for signing blockchain transactions
/// with configurable policies and multi-chain support.
#[derive(Debug, Parser)]
#[command(name = "sello")]
#[command(author, version, about = "Secure transaction signing daemon")]
#[command(propagate_version = true)]
#[command(arg_required_else_help = true)]
pub struct Cli {
    /// Increase verbosity (-v, -vv, -vvv)
    ///
    /// Can be specified multiple times to increase verbosity level:
    /// - `-v` - Show info messages
    /// - `-vv` - Show debug messages
    /// - `-vvv` - Show trace messages
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,

    /// Path to config file
    ///
    /// If not specified, Sello will look for configuration in the default
    /// location (`~/.config/sello/config.toml` on Unix, or the appropriate
    /// platform-specific directory).
    #[arg(short, long, global = true, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// The command to execute
    #[command(subcommand)]
    pub command: Commands,
}

/// Available CLI commands.
#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Initialize Sello configuration and generate default key
    ///
    /// This command creates the necessary directories and configuration files,
    /// and optionally generates a default signing key.
    Init {
        /// Force re-initialization (overwrites existing config)
        ///
        /// Use this flag to reset the configuration to defaults.
        /// Warning: This will overwrite any existing configuration.
        #[arg(short, long)]
        force: bool,
    },

    /// Display current status
    ///
    /// Shows information about:
    /// - Server status (running/stopped)
    /// - Configured keys
    /// - Active policies
    /// - Recent signing activity
    Status,

    /// View or edit configuration
    ///
    /// Without a subcommand, displays the current configuration.
    /// Use `config edit` to open in your default editor.
    /// Use `config path` to show the configuration file location.
    Config {
        /// Configuration action to perform
        #[command(subcommand)]
        action: Option<ConfigAction>,
    },

    /// Start the signing server
    ///
    /// Starts the HTTP/gRPC server that listens for signing requests.
    /// By default, the server runs in the background as a daemon.
    Serve {
        /// Run in foreground (don't daemonize)
        ///
        /// Keep the server running in the current terminal instead
        /// of running as a background daemon.
        #[arg(short, long)]
        foreground: bool,
    },

    /// Ethereum-related commands
    ///
    /// Commands for interacting with the Ethereum blockchain,
    /// including address display and transaction signing.
    Ethereum {
        /// Ethereum command to execute
        #[command(subcommand)]
        command: EthereumCommands,
    },

    /// Bitcoin-related commands
    ///
    /// Commands for interacting with the Bitcoin blockchain,
    /// including address display and transaction signing.
    Bitcoin {
        /// Bitcoin command to execute
        #[command(subcommand)]
        command: BitcoinCommands,
    },

    /// Solana-related commands
    ///
    /// Commands for interacting with the Solana blockchain,
    /// including address display and transaction signing.
    /// Note: Solana uses ed25519 keys (stored as `default-ed25519.enc`).
    Solana {
        /// Solana command to execute
        #[command(subcommand)]
        command: SolanaCommands,
    },

    /// Key management commands
    ///
    /// Commands for managing cryptographic keys including
    /// listing, importing, exporting, and deleting keys.
    Key {
        /// Key command to execute
        #[command(subcommand)]
        command: KeyCommands,
    },
}

/// Configuration-related actions.
#[derive(Debug, Clone, Subcommand)]
pub enum ConfigAction {
    /// Open configuration in editor
    ///
    /// Opens the configuration file in the default editor
    /// (determined by `$EDITOR` or `$VISUAL` environment variable).
    Edit,

    /// Show configuration file path
    ///
    /// Displays the full path to the configuration file.
    /// Useful for scripting or manual editing.
    Path,
}

/// Ethereum-specific commands.
#[derive(Debug, Subcommand)]
pub enum EthereumCommands {
    /// Display Ethereum address for default key
    ///
    /// Shows the Ethereum address derived from the default signing key.
    /// This address can be used to receive funds or interact with contracts.
    Address,

    /// Sign an Ethereum transaction
    ///
    /// Signs a raw Ethereum transaction using the default key.
    /// The transaction should be provided as a hex-encoded RLP-encoded
    /// unsigned transaction.
    Sign {
        /// Raw transaction hex (with or without 0x prefix)
        ///
        /// The unsigned transaction in RLP-encoded hexadecimal format.
        /// The 0x prefix is optional.
        #[arg(value_name = "TX_HEX")]
        transaction: String,

        /// Output format
        ///
        /// Choose the format for the signed transaction output:
        /// - `hex` - Raw hexadecimal (default)
        /// - `json` - JSON with transaction details
        #[arg(short, long, default_value = "hex", value_name = "FORMAT")]
        format: OutputFormat,
    },
}

/// Bitcoin-specific commands.
#[derive(Debug, Subcommand)]
pub enum BitcoinCommands {
    /// Display Bitcoin address for default key
    ///
    /// Shows the Bitcoin address (P2WPKH/bech32 format) derived from the
    /// default signing key. This address starts with 'bc1q' on mainnet.
    Address,

    /// Sign a Bitcoin transaction
    ///
    /// Signs a raw Bitcoin transaction using the default key.
    /// The transaction should be provided as a hex-encoded raw transaction.
    Sign {
        /// Raw transaction hex (with or without 0x prefix)
        ///
        /// The unsigned transaction in hexadecimal format.
        /// The 0x prefix is optional.
        #[arg(value_name = "TX_HEX")]
        transaction: String,

        /// Output format
        ///
        /// Choose the format for the signed transaction output:
        /// - `hex` - Raw hexadecimal (default)
        /// - `json` - JSON with transaction details
        #[arg(short, long, default_value = "hex", value_name = "FORMAT")]
        format: OutputFormat,
    },
}

/// Solana-specific commands.
#[derive(Debug, Subcommand)]
pub enum SolanaCommands {
    /// Display Solana address for default ed25519 key
    ///
    /// Shows the Solana address (base58-encoded public key) derived from the
    /// default ed25519 signing key. Requires a `default-ed25519.enc` key file.
    Address,

    /// Sign a Solana transaction
    ///
    /// Signs a raw Solana transaction using the default ed25519 key.
    /// The transaction should be provided as a hex-encoded raw transaction.
    Sign {
        /// Raw transaction hex (with or without 0x prefix)
        ///
        /// The unsigned transaction in hexadecimal format.
        /// The 0x prefix is optional.
        #[arg(value_name = "TX_HEX")]
        transaction: String,

        /// Output format
        ///
        /// Choose the format for the signed transaction output:
        /// - `hex` - Raw hexadecimal (default)
        /// - `json` - JSON with transaction details
        #[arg(short, long, default_value = "hex", value_name = "FORMAT")]
        format: OutputFormat,
    },
}

/// Key management commands.
#[derive(Debug, Subcommand)]
pub enum KeyCommands {
    /// List all stored keys
    ///
    /// Shows a list of all keys stored in the key store.
    /// Use --verbose for additional details.
    List(KeyListArgs),

    /// Import a private key from hex
    ///
    /// Imports an existing private key from a hex string.
    /// The key will be encrypted with a passphrase before storage.
    Import(KeyImportArgs),

    /// Export a key as encrypted backup
    ///
    /// Exports a key as an encrypted backup file.
    /// Requires the current passphrase and a new passphrase for the export.
    Export(KeyExportArgs),

    /// Delete a stored key
    ///
    /// Permanently removes a key from storage.
    /// Requires confirmation unless --force is provided.
    Delete(KeyDeleteArgs),
}

/// Arguments for the key list command.
#[derive(Debug, Clone, Args)]
pub struct KeyListArgs {
    /// Show additional details (file names, sizes)
    ///
    /// Displays extra information about each key including
    /// the encrypted file name and size.
    #[arg(short = 'd', long = "details")]
    pub details: bool,
}

/// Arguments for the key import command.
///
/// Note: This type implements a custom `Debug` that redacts the secret key
/// to prevent accidental exposure in logs or error messages.
#[derive(Clone, Args)]
pub struct KeyImportArgs {
    /// Private key in hex format (with or without 0x prefix)
    ///
    /// The raw private key as a 32-byte hexadecimal string.
    /// The 0x prefix is optional.
    #[arg(value_name = "HEX")]
    pub key: String,

    /// Name for the imported key
    ///
    /// A unique identifier for this key. If not provided,
    /// you will be prompted to enter one.
    #[arg(short, long, value_name = "NAME")]
    pub name: Option<String>,

    /// Elliptic curve type for the key
    ///
    /// Specifies which curve the private key belongs to:
    /// - `secp256k1` (default) - For Bitcoin and Ethereum keys
    /// - `ed25519` - For Solana keys
    ///
    /// Ed25519 keys will be stored with a `-ed25519` suffix.
    #[arg(short = 'C', long, default_value = "secp256k1", value_name = "CURVE")]
    pub curve: CurveArg,
}

impl std::fmt::Debug for KeyImportArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyImportArgs")
            .field("key", &"[REDACTED]")
            .field("name", &self.name)
            .field("curve", &self.curve)
            .finish()
    }
}

/// Arguments for the key export command.
#[derive(Debug, Clone, Args)]
pub struct KeyExportArgs {
    /// Name of the key to export
    ///
    /// The identifier of the key to export from storage.
    #[arg(value_name = "NAME")]
    pub name: String,

    /// Output file path
    ///
    /// Where to save the encrypted backup file.
    /// If not provided, outputs to stdout.
    #[arg(short, long, value_name = "PATH")]
    pub output: Option<PathBuf>,

    /// Overwrite existing output file
    ///
    /// If the output file already exists, overwrite it.
    #[arg(long)]
    pub force: bool,
}

/// Arguments for the key delete command.
#[derive(Debug, Clone, Args)]
pub struct KeyDeleteArgs {
    /// Name of the key to delete
    ///
    /// The identifier of the key to remove from storage.
    #[arg(value_name = "NAME")]
    pub name: String,

    /// Skip confirmation prompt
    ///
    /// Delete the key without asking for confirmation.
    /// Required when deleting the "default" key.
    #[arg(long)]
    pub force: bool,
}

/// Curve type for key import.
///
/// Specifies which elliptic curve the private key belongs to.
/// This determines how the key is validated and stored.
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum CurveArg {
    /// secp256k1 curve (used by Bitcoin and Ethereum)
    ///
    /// The default curve type. Keys using this curve can be used
    /// to sign Bitcoin and Ethereum transactions.
    #[default]
    Secp256k1,

    /// Ed25519 curve (used by Solana)
    ///
    /// Keys using this curve can be used to sign Solana transactions.
    /// When importing an ed25519 key, it will be stored with a `-ed25519`
    /// suffix in the key name.
    Ed25519,
}

impl std::fmt::Display for CurveArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Secp256k1 => write!(f, "secp256k1"),
            Self::Ed25519 => write!(f, "ed25519"),
        }
    }
}

impl From<CurveArg> for sello_crypto::signer::CurveType {
    fn from(curve: CurveArg) -> Self {
        match curve {
            CurveArg::Secp256k1 => Self::Secp256k1,
            CurveArg::Ed25519 => Self::Ed25519,
        }
    }
}

/// Output format for command results.
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum OutputFormat {
    /// Hexadecimal output
    ///
    /// Raw hexadecimal string, suitable for direct use with other tools.
    #[default]
    Hex,

    /// JSON output with details
    ///
    /// Structured JSON output including transaction details,
    /// signature components, and metadata.
    Json,
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Hex => write!(f, "hex"),
            Self::Json => write!(f, "json"),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::similar_names,
        clippy::redundant_clone,
        clippy::manual_string_new,
        clippy::needless_raw_string_hashes,
        clippy::needless_collect,
        clippy::unreadable_literal,
        clippy::uninlined_format_args,
        clippy::doc_markdown,
        clippy::redundant_closure_for_method_calls,
        clippy::needless_pass_by_value
    )]

    use super::*;
    use clap::CommandFactory;

    /// Test that the CLI can be built without errors.
    #[test]
    fn test_cli_build() {
        Cli::command().debug_assert();
    }

    /// Test parsing of the init command.
    #[test]
    fn test_parse_init() {
        let cli = Cli::try_parse_from(["sello", "init"]);
        assert!(cli.is_ok(), "Failed to parse 'init': {:?}", cli.err());
        let cli = cli.expect("CLI should parse");
        assert!(matches!(cli.command, Commands::Init { force: false }));
    }

    /// Test parsing of the init command with force flag.
    #[test]
    fn test_parse_init_force() {
        let cli = Cli::try_parse_from(["sello", "init", "--force"]);
        assert!(
            cli.is_ok(),
            "Failed to parse 'init --force': {:?}",
            cli.err()
        );
        let cli = cli.expect("CLI should parse");
        assert!(matches!(cli.command, Commands::Init { force: true }));
    }

    /// Test parsing of the status command.
    #[test]
    fn test_parse_status() {
        let cli = Cli::try_parse_from(["sello", "status"]);
        assert!(cli.is_ok(), "Failed to parse 'status': {:?}", cli.err());
        let cli = cli.expect("CLI should parse");
        assert!(matches!(cli.command, Commands::Status));
    }

    /// Test parsing of the config command without subcommand.
    #[test]
    fn test_parse_config() {
        let cli = Cli::try_parse_from(["sello", "config"]);
        assert!(cli.is_ok(), "Failed to parse 'config': {:?}", cli.err());
        let cli = cli.expect("CLI should parse");
        assert!(matches!(cli.command, Commands::Config { action: None }));
    }

    /// Test parsing of the config edit command.
    #[test]
    fn test_parse_config_edit() {
        let cli = Cli::try_parse_from(["sello", "config", "edit"]);
        assert!(
            cli.is_ok(),
            "Failed to parse 'config edit': {:?}",
            cli.err()
        );
        let cli = cli.expect("CLI should parse");
        assert!(matches!(
            cli.command,
            Commands::Config {
                action: Some(ConfigAction::Edit)
            }
        ));
    }

    /// Test parsing of the config path command.
    #[test]
    fn test_parse_config_path() {
        let cli = Cli::try_parse_from(["sello", "config", "path"]);
        assert!(
            cli.is_ok(),
            "Failed to parse 'config path': {:?}",
            cli.err()
        );
        let cli = cli.expect("CLI should parse");
        assert!(matches!(
            cli.command,
            Commands::Config {
                action: Some(ConfigAction::Path)
            }
        ));
    }

    /// Test parsing of the serve command.
    #[test]
    fn test_parse_serve() {
        let cli = Cli::try_parse_from(["sello", "serve"]);
        assert!(cli.is_ok(), "Failed to parse 'serve': {:?}", cli.err());
        let cli = cli.expect("CLI should parse");
        assert!(matches!(cli.command, Commands::Serve { foreground: false }));
    }

    /// Test parsing of the serve command with foreground flag.
    #[test]
    fn test_parse_serve_foreground() {
        let cli = Cli::try_parse_from(["sello", "serve", "--foreground"]);
        assert!(
            cli.is_ok(),
            "Failed to parse 'serve --foreground': {:?}",
            cli.err()
        );
        let cli = cli.expect("CLI should parse");
        assert!(matches!(cli.command, Commands::Serve { foreground: true }));
    }

    /// Test parsing of the ethereum address command.
    #[test]
    fn test_parse_ethereum_address() {
        let cli = Cli::try_parse_from(["sello", "ethereum", "address"]);
        assert!(
            cli.is_ok(),
            "Failed to parse 'ethereum address': {:?}",
            cli.err()
        );
        let cli = cli.expect("CLI should parse");
        assert!(matches!(
            cli.command,
            Commands::Ethereum {
                command: EthereumCommands::Address
            }
        ));
    }

    /// Test parsing of the ethereum sign command.
    #[test]
    fn test_parse_ethereum_sign() {
        let cli = Cli::try_parse_from(["sello", "ethereum", "sign", "0xdeadbeef"]);
        assert!(
            cli.is_ok(),
            "Failed to parse 'ethereum sign': {:?}",
            cli.err()
        );
        let cli = cli.expect("CLI should parse");
        match cli.command {
            Commands::Ethereum {
                command:
                    EthereumCommands::Sign {
                        transaction,
                        format,
                    },
            } => {
                assert_eq!(transaction, "0xdeadbeef");
                assert!(matches!(format, OutputFormat::Hex));
            }
            _ => panic!("Expected Ethereum Sign command"),
        }
    }

    /// Test parsing of the ethereum sign command with JSON format.
    #[test]
    fn test_parse_ethereum_sign_json_format() {
        let cli = Cli::try_parse_from([
            "sello",
            "ethereum",
            "sign",
            "0xdeadbeef",
            "--format",
            "json",
        ]);
        assert!(
            cli.is_ok(),
            "Failed to parse 'ethereum sign --format json': {:?}",
            cli.err()
        );
        let cli = cli.expect("CLI should parse");
        match cli.command {
            Commands::Ethereum {
                command:
                    EthereumCommands::Sign {
                        transaction,
                        format,
                    },
            } => {
                assert_eq!(transaction, "0xdeadbeef");
                assert!(matches!(format, OutputFormat::Json));
            }
            _ => panic!("Expected Ethereum Sign command"),
        }
    }

    /// Test parsing of global verbose flag.
    #[test]
    fn test_parse_verbose_levels() {
        // Single -v
        let cli = Cli::try_parse_from(["sello", "-v", "status"]);
        assert!(cli.is_ok(), "Failed to parse '-v': {:?}", cli.err());
        let cli = cli.expect("CLI should parse");
        assert_eq!(cli.verbose, 1);

        // Double -vv
        let cli = Cli::try_parse_from(["sello", "-vv", "status"]);
        assert!(cli.is_ok(), "Failed to parse '-vv': {:?}", cli.err());
        let cli = cli.expect("CLI should parse");
        assert_eq!(cli.verbose, 2);

        // Triple -vvv
        let cli = Cli::try_parse_from(["sello", "-vvv", "status"]);
        assert!(cli.is_ok(), "Failed to parse '-vvv': {:?}", cli.err());
        let cli = cli.expect("CLI should parse");
        assert_eq!(cli.verbose, 3);
    }

    /// Test parsing of global config option.
    #[test]
    fn test_parse_config_option() {
        let cli = Cli::try_parse_from(["sello", "--config", "/path/to/config.toml", "status"]);
        assert!(cli.is_ok(), "Failed to parse '--config': {:?}", cli.err());
        let cli = cli.expect("CLI should parse");
        assert_eq!(cli.config, Some(PathBuf::from("/path/to/config.toml")));
    }

    /// Test parsing of short config option.
    #[test]
    fn test_parse_config_short_option() {
        let cli = Cli::try_parse_from(["sello", "-c", "/path/to/config.toml", "status"]);
        assert!(cli.is_ok(), "Failed to parse '-c': {:?}", cli.err());
        let cli = cli.expect("CLI should parse");
        assert_eq!(cli.config, Some(PathBuf::from("/path/to/config.toml")));
    }

    /// Test that help can be generated for the main command.
    #[test]
    fn test_help_generation() {
        let mut cmd = Cli::command();
        let help = cmd.render_help();
        let help_str = help.to_string();

        assert!(help_str.contains("Secure transaction signing daemon"));
        assert!(help_str.contains("--verbose"));
        assert!(help_str.contains("--config"));
        assert!(help_str.contains("init"));
        assert!(help_str.contains("status"));
        assert!(help_str.contains("config"));
        assert!(help_str.contains("serve"));
        assert!(help_str.contains("ethereum"));
        assert!(help_str.contains("key"));
    }

    /// Test that version information is available.
    #[test]
    fn test_version_info() {
        let cmd = Cli::command();
        let version = cmd.get_version();
        assert!(version.is_some(), "Version should be set");
    }

    /// Test that subcommand help can be generated.
    #[test]
    fn test_subcommand_help() {
        let cmd = Cli::command();
        let subcommands: Vec<_> = cmd.get_subcommands().collect();

        assert!(!subcommands.is_empty(), "Should have subcommands");

        // Check that each subcommand has help text
        for subcmd in subcommands {
            let name = subcmd.get_name();
            let about = subcmd.get_about();
            assert!(
                about.is_some(),
                "Subcommand '{}' should have about text",
                name
            );
        }
    }

    /// Test that global options work with subcommands.
    #[test]
    fn test_global_options_with_subcommands() {
        // Verbose after subcommand
        let cli = Cli::try_parse_from(["sello", "status", "-v"]);
        assert!(cli.is_ok(), "Failed to parse 'status -v': {:?}", cli.err());
        let cli = cli.expect("CLI should parse");
        assert_eq!(cli.verbose, 1);

        // Config with ethereum subcommand
        let cli = Cli::try_parse_from([
            "sello",
            "--config",
            "/etc/sello.toml",
            "ethereum",
            "address",
        ]);
        assert!(cli.is_ok());
        let cli = cli.expect("CLI should parse");
        assert_eq!(cli.config, Some(PathBuf::from("/etc/sello.toml")));
    }

    /// Test OutputFormat display implementation.
    #[test]
    fn test_output_format_display() {
        assert_eq!(OutputFormat::Hex.to_string(), "hex");
        assert_eq!(OutputFormat::Json.to_string(), "json");
    }

    /// Test that invalid commands produce errors.
    #[test]
    fn test_invalid_command() {
        let cli = Cli::try_parse_from(["sello", "invalid"]);
        assert!(cli.is_err(), "Should fail on invalid command");
    }

    /// Test that missing required arguments produce errors.
    #[test]
    fn test_missing_required_arg() {
        // ethereum sign requires a transaction argument
        let cli = Cli::try_parse_from(["sello", "ethereum", "sign"]);
        assert!(cli.is_err(), "Should fail when transaction is missing");
    }

    /// Test that no command shows help.
    #[test]
    fn test_no_command_shows_help() {
        // With arg_required_else_help, no command should produce an error
        let cli = Cli::try_parse_from(["sello"]);
        assert!(cli.is_err(), "Should require a command");
    }

    /// Test parsing of key list command.
    #[test]
    fn test_parse_key_list() {
        let cli = Cli::try_parse_from(["sello", "key", "list"]);
        assert!(cli.is_ok(), "Failed to parse 'key list': {:?}", cli.err());
        let cli = cli.expect("CLI should parse");
        match cli.command {
            Commands::Key {
                command: KeyCommands::List(args),
            } => {
                assert!(!args.details);
            }
            _ => panic!("Expected Key List command"),
        }
    }

    /// Test parsing of key list details command.
    #[test]
    fn test_parse_key_list_details() {
        let cli = Cli::try_parse_from(["sello", "key", "list", "--details"]);
        assert!(
            cli.is_ok(),
            "Failed to parse 'key list --details': {:?}",
            cli.err()
        );
        let cli = cli.expect("CLI should parse");
        match cli.command {
            Commands::Key {
                command: KeyCommands::List(args),
            } => {
                assert!(args.details);
            }
            _ => panic!("Expected Key List command"),
        }
    }

    /// Test parsing of key import command.
    #[test]
    fn test_parse_key_import() {
        let cli = Cli::try_parse_from(["sello", "key", "import", "0xdeadbeef"]);
        assert!(cli.is_ok(), "Failed to parse 'key import': {:?}", cli.err());
        let cli = cli.expect("CLI should parse");
        match cli.command {
            Commands::Key {
                command: KeyCommands::Import(args),
            } => {
                assert_eq!(args.key, "0xdeadbeef");
                assert!(args.name.is_none());
            }
            _ => panic!("Expected Key Import command"),
        }
    }

    /// Test parsing of key import command with name.
    #[test]
    fn test_parse_key_import_with_name() {
        let cli = Cli::try_parse_from(["sello", "key", "import", "0xdeadbeef", "--name", "my-key"]);
        assert!(
            cli.is_ok(),
            "Failed to parse 'key import --name': {:?}",
            cli.err()
        );
        let cli = cli.expect("CLI should parse");
        match cli.command {
            Commands::Key {
                command: KeyCommands::Import(args),
            } => {
                assert_eq!(args.key, "0xdeadbeef");
                assert_eq!(args.name, Some("my-key".to_string()));
            }
            _ => panic!("Expected Key Import command"),
        }
    }

    /// Test parsing of key export command.
    #[test]
    fn test_parse_key_export() {
        let cli = Cli::try_parse_from(["sello", "key", "export", "my-key"]);
        assert!(cli.is_ok(), "Failed to parse 'key export': {:?}", cli.err());
        let cli = cli.expect("CLI should parse");
        match cli.command {
            Commands::Key {
                command: KeyCommands::Export(args),
            } => {
                assert_eq!(args.name, "my-key");
                assert!(args.output.is_none());
                assert!(!args.force);
            }
            _ => panic!("Expected Key Export command"),
        }
    }

    /// Test parsing of key export command with output.
    #[test]
    fn test_parse_key_export_with_output() {
        let cli = Cli::try_parse_from([
            "sello",
            "key",
            "export",
            "my-key",
            "--output",
            "/tmp/backup.json",
        ]);
        assert!(
            cli.is_ok(),
            "Failed to parse 'key export --output': {:?}",
            cli.err()
        );
        let cli = cli.expect("CLI should parse");
        match cli.command {
            Commands::Key {
                command: KeyCommands::Export(args),
            } => {
                assert_eq!(args.name, "my-key");
                assert_eq!(args.output, Some(PathBuf::from("/tmp/backup.json")));
                assert!(!args.force);
            }
            _ => panic!("Expected Key Export command"),
        }
    }

    /// Test parsing of key export command with force.
    #[test]
    fn test_parse_key_export_with_force() {
        let cli = Cli::try_parse_from([
            "sello",
            "key",
            "export",
            "my-key",
            "--output",
            "/tmp/backup.json",
            "--force",
        ]);
        assert!(
            cli.is_ok(),
            "Failed to parse 'key export --force': {:?}",
            cli.err()
        );
        let cli = cli.expect("CLI should parse");
        match cli.command {
            Commands::Key {
                command: KeyCommands::Export(args),
            } => {
                assert!(args.force);
            }
            _ => panic!("Expected Key Export command"),
        }
    }

    /// Test parsing of key delete command.
    #[test]
    fn test_parse_key_delete() {
        let cli = Cli::try_parse_from(["sello", "key", "delete", "my-key"]);
        assert!(cli.is_ok(), "Failed to parse 'key delete': {:?}", cli.err());
        let cli = cli.expect("CLI should parse");
        match cli.command {
            Commands::Key {
                command: KeyCommands::Delete(args),
            } => {
                assert_eq!(args.name, "my-key");
                assert!(!args.force);
            }
            _ => panic!("Expected Key Delete command"),
        }
    }

    /// Test parsing of key delete command with force.
    #[test]
    fn test_parse_key_delete_with_force() {
        let cli = Cli::try_parse_from(["sello", "key", "delete", "my-key", "--force"]);
        assert!(
            cli.is_ok(),
            "Failed to parse 'key delete --force': {:?}",
            cli.err()
        );
        let cli = cli.expect("CLI should parse");
        match cli.command {
            Commands::Key {
                command: KeyCommands::Delete(args),
            } => {
                assert_eq!(args.name, "my-key");
                assert!(args.force);
            }
            _ => panic!("Expected Key Delete command"),
        }
    }

    /// Test that key subcommand requires subcommand.
    #[test]
    fn test_key_requires_subcommand() {
        let cli = Cli::try_parse_from(["sello", "key"]);
        assert!(cli.is_err(), "Should fail when key subcommand is missing");
    }

    /// Test CurveArg display implementation.
    #[test]
    fn test_curve_arg_display() {
        assert_eq!(CurveArg::Secp256k1.to_string(), "secp256k1");
        assert_eq!(CurveArg::Ed25519.to_string(), "ed25519");
    }

    /// Test CurveArg to CurveType conversion.
    #[test]
    fn test_curve_arg_to_curve_type_conversion() {
        use sello_crypto::signer::CurveType;

        let curve: CurveType = CurveArg::Secp256k1.into();
        assert_eq!(curve, CurveType::Secp256k1);

        let curve: CurveType = CurveArg::Ed25519.into();
        assert_eq!(curve, CurveType::Ed25519);
    }

    /// Test parsing of key import command with curve flag.
    #[test]
    fn test_parse_key_import_with_curve() {
        let cli =
            Cli::try_parse_from(["sello", "key", "import", "0xdeadbeef", "--curve", "ed25519"]);
        assert!(
            cli.is_ok(),
            "Failed to parse 'key import --curve': {:?}",
            cli.err()
        );
        let cli = cli.expect("CLI should parse");
        match cli.command {
            Commands::Key {
                command: KeyCommands::Import(args),
            } => {
                assert_eq!(args.key, "0xdeadbeef");
                assert!(matches!(args.curve, CurveArg::Ed25519));
            }
            _ => panic!("Expected Key Import command"),
        }
    }

    /// Test KeyImportArgs debug does not expose key.
    #[test]
    fn test_key_import_args_debug_redacts_key() {
        let args = KeyImportArgs {
            key: "0xsupersecretkey".to_string(),
            name: Some("my-key".to_string()),
            curve: CurveArg::Secp256k1,
        };
        let debug_str = format!("{:?}", args);
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("supersecretkey"));
        assert!(debug_str.contains("my-key"));
    }
}
