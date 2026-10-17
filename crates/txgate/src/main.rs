//! # `TxGate`
//!
//! Multi-chain transaction signing service with policy engine.
//!
//! ## Usage
//!
//! ```bash
//! # Initialize configuration
//! txgate init
//!
//! # Display current status
//! txgate status
//!
//! # Start the signing server
//! txgate serve --foreground
//!
//! # Display Ethereum address
//! txgate ethereum address
//!
//! # Sign an Ethereum transaction
//! txgate ethereum sign 0xdeadbeef
//!
//! # Display Bitcoin address
//! txgate bitcoin address
//!
//! # Sign a Bitcoin transaction
//! txgate bitcoin sign 0x...
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]

use clap::Parser;
use txgate::cli::commands::{
    AddressCommand, BitcoinAddressCommand, BitcoinSignCommand, BitcoinSignCommandError,
    ConfigCommand, DeleteCommand, ExportCommand, ImportCommand, InitCommand, InstallSkillCommand,
    ListCommand, ServeCommand, SignCommand, SignCommandError, SolanaAddressCommand,
    SolanaSignCommand, SolanaSignCommandError, StatusCommand,
};
use txgate::cli::{BitcoinCommands, Cli, Commands, EthereumCommands, KeyCommands, SolanaCommands};
use txgate::logging::{init_logging, verbosity_to_level, LogConfig, LogError, LogFormat, LogGuard};

/// Exit code for policy denied (sign command).
const EXIT_POLICY_DENIED: i32 = 1;

/// Exit code for other errors.
const EXIT_ERROR: i32 = 2;

/// Set up logging based on verbosity level.
///
/// # Arguments
///
/// * `verbose` - Verbosity level (0 = warn, 1 = info, 2 = debug, 3+ = trace)
///
/// # Errors
///
/// Returns [`LogError`] if logging initialization fails.
fn setup_logging(verbose: u8) -> Result<LogGuard, LogError> {
    let config = LogConfig {
        level: verbosity_to_level(verbose),
        format: LogFormat::Pretty,
        file_path: None,
        correlation_ids: true,
    };
    init_logging(&config)
}

/// Main entry point for the `TxGate` application.
fn main() {
    let cli = Cli::parse();

    // Set up logging based on verbosity level
    let _guard = match setup_logging(cli.verbose) {
        Ok(guard) => guard,
        Err(e) => {
            eprintln!("Failed to initialize logging: {e}");
            std::process::exit(EXIT_ERROR);
        }
    };

    // Dispatch to command handlers
    let result = match cli.command {
        Commands::Init {
            force,
            allow_env_passphrase,
        } => {
            let cmd = InitCommand::new(force, allow_env_passphrase);
            cmd.run().map_err(|e| e.to_string())
        }
        Commands::Status => {
            let cmd = StatusCommand::new();
            cmd.run().map_err(|e| e.to_string())
        }
        Commands::InstallSkill => {
            let cmd = InstallSkillCommand::new();
            cmd.run().map_err(|e| e.to_string())
        }
        Commands::Config { action } => {
            let cmd = ConfigCommand::new(action);
            cmd.run().map_err(|e| e.to_string())
        }
        Commands::Serve { foreground } => {
            let rt = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("Failed to create tokio runtime: {e}");
                    std::process::exit(EXIT_ERROR);
                }
            };
            let cmd = ServeCommand { foreground };
            rt.block_on(cmd.run()).map_err(|e| e.to_string())
        }
        Commands::Ethereum { command } => handle_ethereum(command),
        Commands::Bitcoin { command } => handle_bitcoin(command),
        Commands::Solana { command } => handle_solana(command),
        Commands::Key { command } => handle_key(command),
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(EXIT_ERROR);
    }
}

/// Handle Ethereum subcommands.
///
/// # Arguments
///
/// * `command` - The Ethereum subcommand to execute.
///
/// # Returns
///
/// `Ok(())` on success, or an error message string on failure.
///
/// # Exit Codes
///
/// This function may call `std::process::exit` directly for policy denial:
/// - Exit code 1: Policy denied (for sign command)
/// - Exit code 2: Other error
fn handle_ethereum(command: EthereumCommands) -> Result<(), String> {
    match command {
        EthereumCommands::Address => {
            let cmd = AddressCommand::new();
            cmd.run().map_err(|e| e.to_string())
        }
        EthereumCommands::Sign {
            transaction,
            format,
        } => {
            let cmd = SignCommand::new(transaction, format);
            match cmd.run() {
                Ok(()) => Ok(()),
                Err(SignCommandError::PolicyDenied { rule, reason }) => {
                    eprintln!("Policy denied: {rule} - {reason}");
                    std::process::exit(EXIT_POLICY_DENIED);
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(EXIT_ERROR);
                }
            }
        }
    }
}

/// Handle Bitcoin subcommands.
///
/// # Arguments
///
/// * `command` - The Bitcoin subcommand to execute.
///
/// # Returns
///
/// `Ok(())` on success, or an error message string on failure.
///
/// # Exit Codes
///
/// This function may call `std::process::exit` directly for policy denial:
/// - Exit code 1: Policy denied (for sign command)
/// - Exit code 2: Other error
fn handle_bitcoin(command: BitcoinCommands) -> Result<(), String> {
    match command {
        BitcoinCommands::Address => {
            let cmd = BitcoinAddressCommand::new();
            cmd.run().map_err(|e| e.to_string())
        }
        BitcoinCommands::Sign {
            transaction,
            format,
        } => {
            let cmd = BitcoinSignCommand::new(transaction, format);
            match cmd.run() {
                Ok(()) => Ok(()),
                Err(BitcoinSignCommandError::PolicyDenied { rule, reason }) => {
                    eprintln!("Policy denied: {rule} - {reason}");
                    std::process::exit(EXIT_POLICY_DENIED);
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(EXIT_ERROR);
                }
            }
        }
    }
}

/// Handle Solana subcommands.
///
/// # Arguments
///
/// * `command` - The Solana subcommand to execute.
///
/// # Returns
///
/// `Ok(())` on success, or an error message string on failure.
///
/// # Exit Codes
///
/// This function may call `std::process::exit` directly for policy denial:
/// - Exit code 1: Policy denied (for sign command)
/// - Exit code 2: Other error
fn handle_solana(command: SolanaCommands) -> Result<(), String> {
    match command {
        SolanaCommands::Address => {
            let cmd = SolanaAddressCommand::new();
            cmd.run().map_err(|e| e.to_string())
        }
        SolanaCommands::Sign {
            transaction,
            format,
        } => {
            let cmd = SolanaSignCommand::new(transaction, format);
            match cmd.run() {
                Ok(()) => Ok(()),
                Err(SolanaSignCommandError::PolicyDenied { rule, reason }) => {
                    eprintln!("Policy denied: {rule} - {reason}");
                    std::process::exit(EXIT_POLICY_DENIED);
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(EXIT_ERROR);
                }
            }
        }
    }
}

/// Handle Key management subcommands.
///
/// # Arguments
///
/// * `command` - The Key subcommand to execute.
///
/// # Returns
///
/// `Ok(())` on success, or an error message string on failure.
fn handle_key(command: KeyCommands) -> Result<(), String> {
    match command {
        KeyCommands::List(args) => {
            let cmd = ListCommand::new(args.details);
            cmd.run().map_err(|e| e.to_string())
        }
        KeyCommands::Import(args) => {
            let cmd = ImportCommand::new(args.key, args.name, args.curve);
            cmd.run().map_err(|e| e.to_string())
        }
        KeyCommands::Export(args) => {
            let cmd = ExportCommand::new(args.name, args.output, args.force);
            cmd.run().map_err(|e| e.to_string())
        }
        KeyCommands::Delete(args) => {
            let cmd = DeleteCommand::new(args.name, args.force);
            cmd.run().map_err(|e| e.to_string())
        }
    }
}
