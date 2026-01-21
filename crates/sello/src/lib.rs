//! # Sello Library
//!
//! Multi-chain transaction signing service with policy engine.
//!
//! This crate provides both a library interface and a binary for the Sello
//! transaction signing service. The library exports the CLI module for
//! programmatic access to argument parsing and command structures.
//!
//! ## Modules
//!
//! - [`cli`] - Command-line interface definitions and handlers
//!
//! ## Usage
//!
//! ```no_run
//! use clap::Parser;
//! use sello::cli::{Cli, Commands};
//!
//! let cli = Cli::parse();
//! println!("Verbose level: {}", cli.verbose);
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]

pub mod cli;
pub mod logging;

// Re-export key logging types for convenience
pub use logging::{
    init_logging, log_security_event, new_correlation_id, redact_sensitive, verbosity_to_level,
    LogConfig, LogError, LogFormat, LogGuard, LogLevel,
};
