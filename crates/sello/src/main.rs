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

mod server;

use clap::Parser;
use sello::cli::{Cli, Commands, ConfigAction, EthereumCommands};

/// Main entry point for the Sello application.
fn main() {
    let cli = Cli::parse();

    // Set up logging based on verbosity level
    setup_logging(cli.verbose);

    // Handle the command
    match cli.command {
        Commands::Init { force } => {
            handle_init(force, cli.config.as_deref());
        }
        Commands::Status => {
            handle_status(cli.config.as_deref());
        }
        Commands::Config { action } => {
            handle_config(action.as_ref(), cli.config.as_deref());
        }
        Commands::Serve { foreground } => {
            handle_serve(foreground, cli.config.as_deref());
        }
        Commands::Ethereum { command } => {
            handle_ethereum(command, cli.config.as_deref());
        }
    }
}

/// Set up logging based on verbosity level.
///
/// # Arguments
///
/// * `_verbose` - Verbosity level (0 = default, 1 = info, 2 = debug, 3+ = trace)
///
/// # Note
///
/// This is a placeholder. The actual implementation will configure the tracing
/// subscriber based on the verbosity level.
const fn setup_logging(_verbose: u8) {
    // Placeholder for tracing subscriber setup
    // Will be implemented in a future task
}

/// Handle the init command.
fn handle_init(force: bool, config_path: Option<&std::path::Path>) {
    println!("Initializing Sello...");
    if force {
        println!("  Force mode: will overwrite existing configuration");
    }
    if let Some(path) = config_path {
        println!("  Config path: {}", path.display());
    }
    // TODO: Implement actual initialization logic
    println!("  [Not yet implemented]");
}

/// Handle the status command.
fn handle_status(config_path: Option<&std::path::Path>) {
    println!("Sello Status");
    println!("============");
    if let Some(path) = config_path {
        println!("Config: {}", path.display());
    }
    println!("Server: Not running");
    println!("Keys: None configured");
    // TODO: Implement actual status logic
    println!("\n[Status not yet implemented]");
}

/// Handle the config command.
fn handle_config(action: Option<&ConfigAction>, config_path: Option<&std::path::Path>) {
    match action {
        Some(ConfigAction::Edit) => {
            println!("Opening configuration in editor...");
            // TODO: Implement editor opening
            println!("[Not yet implemented]");
        }
        Some(ConfigAction::Path) => {
            if let Some(path) = config_path {
                println!("{}", path.display());
            } else {
                // TODO: Get default config path
                println!("~/.config/sello/config.toml");
            }
        }
        None => {
            println!("Current configuration:");
            if let Some(path) = config_path {
                println!("  Path: {}", path.display());
            }
            // TODO: Display actual configuration
            println!("  [Configuration display not yet implemented]");
        }
    }
}

/// Handle the serve command.
fn handle_serve(foreground: bool, config_path: Option<&std::path::Path>) {
    println!("Starting Sello server...");
    if foreground {
        println!("  Running in foreground mode");
    } else {
        println!("  Running as daemon");
    }
    if let Some(path) = config_path {
        println!("  Config: {}", path.display());
    }
    // TODO: Implement actual server startup
    println!("  [Server not yet implemented]");
}

/// Handle Ethereum commands.
fn handle_ethereum(command: EthereumCommands, config_path: Option<&std::path::Path>) {
    if let Some(path) = config_path {
        // Config path is available for key loading
        let _ = path;
    }

    match command {
        EthereumCommands::Address => {
            use sello::cli::commands::AddressCommand;

            let cmd = AddressCommand::new();
            if let Err(e) = cmd.run() {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        EthereumCommands::Sign {
            transaction,
            format,
        } => {
            use sello::cli::commands::SignCommand;

            let cmd = SignCommand::new(transaction, format);
            if let Err(e) = cmd.run() {
                eprintln!("Error: {e}");
                std::process::exit(e.exit_code());
            }
        }
    }
}
