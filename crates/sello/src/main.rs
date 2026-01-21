//! # Sello
//!
//! Multi-chain transaction signing service with policy engine.
//!
//! ## Usage
//!
//! ```bash
//! # Initialize configuration
//! sello init
//!
//! # Display current status
//! sello status
//!
//! # Start the signing server
//! sello serve --foreground
//!
//! # Display Ethereum address
//! sello ethereum address
//!
//! # Sign an Ethereum transaction
//! sello ethereum sign 0xdeadbeef
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]

use clap::Parser;
use sello::cli::commands::{
    AddressCommand, ConfigCommand, InitCommand, ServeCommand, SignCommand, SignCommandError,
    StatusCommand,
};
use sello::cli::{Cli, Commands, EthereumCommands};
use sello::logging::{init_logging, verbosity_to_level, LogConfig, LogError, LogFormat, LogGuard};

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

/// Main entry point for the Sello application.
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
        Commands::Init { force } => {
            let cmd = InitCommand::new(force);
            cmd.run().map_err(|e| e.to_string())
        }
        Commands::Status => {
            let cmd = StatusCommand::new();
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
