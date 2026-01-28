//! # Key List Command
//!
//! Implementation of the `txgate key list` command that displays all stored keys.
//!
//! ## Output Format
//!
//! ```text
//! Keys:
//!   default
//!   trading-wallet
//!   cold-storage
//! ```
//!
//! With `--verbose`:
//!
//! ```text
//! Keys:
//!   NAME              FILE                  SIZE
//!   default           default.enc           77 B
//!   trading-wallet    trading-wallet.enc    77 B
//! ```
//!
//! ## Usage
//!
//! ```no_run
//! use txgate::cli::commands::key::ListCommand;
//!
//! let cmd = ListCommand::new(false);
//! cmd.run().expect("list failed");
//! ```

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use txgate_crypto::store::{FileKeyStore, KeyStore};

// ============================================================================
// Constants
// ============================================================================

/// Base directory name within the home directory.
const BASE_DIR_NAME: &str = ".txgate";

/// Keys subdirectory name.
const KEYS_DIR_NAME: &str = "keys";

// ============================================================================
// ListError
// ============================================================================

/// Errors that can occur during key listing.
#[derive(Debug, thiserror::Error)]
pub enum ListError {
    /// `TxGate` is not initialized.
    #[error("TxGate is not initialized. Run 'txgate init' first.")]
    NotInitialized,

    /// I/O error.
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// Could not determine home directory.
    #[error("Could not determine home directory")]
    NoHomeDirectory,

    /// Storage error.
    #[error("Storage error: {0}")]
    Store(String),
}

// ============================================================================
// ListCommand
// ============================================================================

/// Command to list all stored keys.
#[derive(Debug, Clone, Copy)]
pub struct ListCommand {
    /// Whether to show verbose output with file details.
    pub verbose: bool,
}

impl ListCommand {
    /// Create a new list command.
    #[must_use]
    pub const fn new(verbose: bool) -> Self {
        Self { verbose }
    }

    /// Execute the list command.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `TxGate` is not initialized
    /// - I/O or storage errors occur
    pub fn run(self) -> Result<(), ListError> {
        let base_dir = get_base_dir()?;
        self.run_with_base_dir(&base_dir)
    }

    /// Execute the list command with a custom base directory.
    ///
    /// This is useful for testing with temporary directories.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `TxGate` is not initialized
    /// - I/O or storage errors occur
    pub fn run_with_base_dir(self, base_dir: &Path) -> Result<(), ListError> {
        // Check if initialized
        let keys_dir = base_dir.join(KEYS_DIR_NAME);
        if !keys_dir.exists() {
            return Err(ListError::NotInitialized);
        }

        // Create key store and list keys
        let store = FileKeyStore::with_path(keys_dir.clone())
            .map_err(|e| ListError::Store(e.to_string()))?;

        let keys = store.list().map_err(|e| ListError::Store(e.to_string()))?;

        if keys.is_empty() {
            println!("No keys stored.");
            return Ok(());
        }

        if self.verbose {
            Self::print_verbose(&keys, &keys_dir)?;
        } else {
            Self::print_simple(&keys);
        }

        Ok(())
    }

    /// Print simple key list.
    fn print_simple(keys: &[String]) {
        println!("Keys:");
        for name in keys {
            println!("  {name}");
        }
    }

    /// Print verbose key list with file details.
    fn print_verbose(keys: &[String], keys_dir: &Path) -> Result<(), ListError> {
        println!("Keys:");
        println!("  {:<20} {:<25} {:>10}", "NAME", "FILE", "SIZE");

        for name in keys {
            let file_name = format!("{name}.enc");
            let file_path = keys_dir.join(&file_name);

            let size = match fs::metadata(&file_path) {
                Ok(metadata) => format_size(metadata.len()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => "(missing)".to_string(),
                Err(e) => return Err(ListError::Io(e)),
            };

            println!("  {name:<20} {file_name:<25} {size:>10}");
        }

        Ok(())
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Get the base directory for `TxGate`.
fn get_base_dir() -> Result<PathBuf, ListError> {
    dirs::home_dir()
        .map(|home| home.join(BASE_DIR_NAME))
        .ok_or(ListError::NoHomeDirectory)
}

/// Format a file size in human-readable form.
#[allow(clippy::cast_precision_loss)]
fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        let kb = bytes as f64 / 1024.0;
        format!("{kb:.1} KB")
    } else {
        let mb = bytes as f64 / (1024.0 * 1024.0);
        format!("{mb:.1} MB")
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use super::*;
    use std::fs;
    use tempfile::TempDir;
    use txgate_crypto::encryption::encrypt_key;
    use txgate_crypto::keys::SecretKey;

    /// Create a test environment with keys directory.
    fn setup_test_env() -> TempDir {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let keys_dir = temp_dir.path().join(KEYS_DIR_NAME);
        fs::create_dir_all(&keys_dir).expect("Failed to create keys dir");
        temp_dir
    }

    /// Store a test key in the given directory.
    fn store_test_key(keys_dir: &Path, name: &str, passphrase: &str) {
        let secret_key = SecretKey::generate();
        let encrypted = encrypt_key(&secret_key, passphrase).expect("Failed to encrypt");
        let file_path = keys_dir.join(format!("{name}.enc"));
        fs::write(file_path, encrypted.to_bytes()).expect("Failed to write key");
    }

    #[test]
    fn test_list_empty_store() {
        let temp_dir = setup_test_env();
        let cmd = ListCommand::new(false);
        let result = cmd.run_with_base_dir(temp_dir.path());
        assert!(result.is_ok());
    }

    #[test]
    fn test_list_with_keys() {
        let temp_dir = setup_test_env();
        let keys_dir = temp_dir.path().join(KEYS_DIR_NAME);

        // Store some test keys
        store_test_key(&keys_dir, "default", "password123");
        store_test_key(&keys_dir, "trading", "password456");

        let cmd = ListCommand::new(false);
        let result = cmd.run_with_base_dir(temp_dir.path());
        assert!(result.is_ok());
    }

    #[test]
    fn test_list_verbose() {
        let temp_dir = setup_test_env();
        let keys_dir = temp_dir.path().join(KEYS_DIR_NAME);

        store_test_key(&keys_dir, "my-key", "password");

        let cmd = ListCommand::new(true);
        let result = cmd.run_with_base_dir(temp_dir.path());
        assert!(result.is_ok());
    }

    #[test]
    fn test_list_not_initialized() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        // Don't create keys directory

        let cmd = ListCommand::new(false);
        let result = cmd.run_with_base_dir(temp_dir.path());
        assert!(matches!(result, Err(ListError::NotInitialized)));
    }

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(77), "77 B");
        assert_eq!(format_size(1023), "1023 B");
        assert_eq!(format_size(1024), "1.0 KB");
        assert_eq!(format_size(1536), "1.5 KB");
        assert_eq!(format_size(1_048_576), "1.0 MB");
    }
}
