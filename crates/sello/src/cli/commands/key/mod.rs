//! # Key Management Commands
//!
//! Commands for managing cryptographic keys in Sello.
//!
//! ## Available Commands
//!
//! - [`ListCommand`] - List all stored keys
//! - [`ImportCommand`] - Import a private key from hex
//! - [`ExportCommand`] - Export a key as encrypted backup
//! - [`DeleteCommand`] - Delete a key from storage
//!
//! ## Usage
//!
//! ```no_run
//! use sello::cli::commands::key::ListCommand;
//!
//! let cmd = ListCommand::new(false);
//! cmd.run().expect("list failed");
//! ```
//!
//! ```no_run
//! use sello::cli::commands::key::ImportCommand;
//! use sello::cli::args::CurveArg;
//!
//! let cmd = ImportCommand::new("0xabc123...".to_string(), Some("my-key".to_string()), CurveArg::Secp256k1);
//! cmd.run().expect("import failed");
//! ```

pub mod delete;
pub mod export;
pub mod import;
pub mod list;

// Re-export command types for convenience
pub use delete::{DeleteCommand, DeleteError};
pub use export::{ExportCommand, ExportError};
pub use import::{ImportCommand, ImportError};
pub use list::{ListCommand, ListError};
