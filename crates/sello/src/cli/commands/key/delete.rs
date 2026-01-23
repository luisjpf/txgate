//! # Key Delete Command
//!
//! Implementation of the `sello key delete` command that removes a stored key.
//!
//! ## Usage
//!
//! ```no_run
//! use sello::cli::commands::key::DeleteCommand;
//!
//! let cmd = DeleteCommand::new("my-key".to_string(), true);
//! cmd.run().expect("delete failed");
//! ```
//!
//! ## Security
//!
//! - Requires confirmation unless `--force` is provided
//! - Cannot delete "default" key without `--force`
//! - Deletion is permanent and cannot be undone
//! - Confirmation prompts require an interactive terminal (not piped input)
//! - Use `--force` flag when running in non-interactive contexts (scripts, CI)

use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};

use sello_crypto::store::{FileKeyStore, KeyStore};

// ============================================================================
// Constants
// ============================================================================

/// Base directory name within the home directory.
const BASE_DIR_NAME: &str = ".sello";

/// Keys subdirectory name.
const KEYS_DIR_NAME: &str = "keys";

/// Default key name that requires extra confirmation.
const DEFAULT_KEY_NAME: &str = "default";

// ============================================================================
// DeleteError
// ============================================================================

/// Errors that can occur during key deletion.
#[derive(Debug, thiserror::Error)]
pub enum DeleteError {
    /// Sello is not initialized.
    #[error("Sello is not initialized. Run 'sello init' first.")]
    NotInitialized,

    /// Key not found.
    #[error("Key '{0}' not found")]
    KeyNotFound(String),

    /// Cannot delete default key without --force.
    #[error("Cannot delete default key without --force flag")]
    DefaultKeyProtected,

    /// Deletion was cancelled by user.
    #[error("Deletion cancelled")]
    Cancelled,

    /// Cannot prompt for confirmation without a terminal.
    #[error("Cannot prompt for confirmation: stdin is not a terminal. Use --force to skip confirmation.")]
    NotTerminal,

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
// DeleteCommand
// ============================================================================

/// Command to delete a stored key.
#[derive(Debug, Clone)]
pub struct DeleteCommand {
    /// Name of the key to delete.
    pub name: String,

    /// Skip confirmation prompt.
    pub force: bool,
}

impl DeleteCommand {
    /// Create a new delete command.
    #[must_use]
    pub const fn new(name: String, force: bool) -> Self {
        Self { name, force }
    }

    /// Execute the delete command.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Sello is not initialized
    /// - The key does not exist
    /// - User cancels the deletion
    /// - I/O or storage errors occur
    pub fn run(&self) -> Result<(), DeleteError> {
        let base_dir = get_base_dir()?;
        self.run_with_base_dir(&base_dir)
    }

    /// Execute the delete command with a custom base directory.
    ///
    /// This is useful for testing with temporary directories.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Sello is not initialized
    /// - The key does not exist
    /// - Default key is being deleted without `--force`
    /// - User cancels the deletion
    /// - I/O or storage errors occur
    pub fn run_with_base_dir(&self, base_dir: &Path) -> Result<(), DeleteError> {
        // Check if initialized
        let keys_dir = base_dir.join(KEYS_DIR_NAME);
        if !keys_dir.exists() {
            return Err(DeleteError::NotInitialized);
        }

        // Create key store
        let key_store =
            FileKeyStore::with_path(keys_dir).map_err(|e| DeleteError::Store(e.to_string()))?;

        // Check if key exists
        if !key_store.exists(&self.name) {
            return Err(DeleteError::KeyNotFound(self.name.clone()));
        }

        // Check if trying to delete default key without force
        if self.name == DEFAULT_KEY_NAME && !self.force {
            return Err(DeleteError::DefaultKeyProtected);
        }

        // Confirm deletion if not forced
        if !self.force && !confirm_deletion(&self.name)? {
            return Err(DeleteError::Cancelled);
        }

        // Delete the key
        key_store
            .delete(&self.name)
            .map_err(|e| DeleteError::Store(e.to_string()))?;

        println!("Key '{}' deleted successfully.", self.name);

        Ok(())
    }

    /// Execute the delete command with a custom base directory, skipping interactive prompts.
    ///
    /// This is useful for testing where we want to force deletion without prompts.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Sello is not initialized
    /// - The key does not exist
    /// - I/O or storage errors occur
    #[cfg(test)]
    pub fn run_with_base_dir_forced(&self, base_dir: &Path) -> Result<(), DeleteError> {
        // Check if initialized
        let keys_dir = base_dir.join(KEYS_DIR_NAME);
        if !keys_dir.exists() {
            return Err(DeleteError::NotInitialized);
        }

        // Create key store
        let key_store =
            FileKeyStore::with_path(keys_dir).map_err(|e| DeleteError::Store(e.to_string()))?;

        // Check if key exists
        if !key_store.exists(&self.name) {
            return Err(DeleteError::KeyNotFound(self.name.clone()));
        }

        // Delete the key
        key_store
            .delete(&self.name)
            .map_err(|e| DeleteError::Store(e.to_string()))?;

        println!("Key '{}' deleted successfully.", self.name);

        Ok(())
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Get the base directory for Sello.
fn get_base_dir() -> Result<PathBuf, DeleteError> {
    dirs::home_dir()
        .map(|home| home.join(BASE_DIR_NAME))
        .ok_or(DeleteError::NoHomeDirectory)
}

/// Prompt user to confirm deletion.
fn confirm_deletion(name: &str) -> Result<bool, DeleteError> {
    // Ensure stdin is a terminal to prevent unexpected behavior when piped
    if !io::stdin().is_terminal() {
        return Err(DeleteError::NotTerminal);
    }

    print!("Are you sure you want to delete key '{name}'? This cannot be undone. [y/N] ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    let input = input.trim().to_lowercase();
    Ok(input == "y" || input == "yes")
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
    use sello_crypto::encryption::encrypt_key;
    use sello_crypto::keys::SecretKey;
    use std::fs;
    use tempfile::TempDir;

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
    fn test_delete_not_initialized() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        // Don't create keys directory

        let cmd = DeleteCommand::new("test".to_string(), true);
        let result = cmd.run_with_base_dir(temp_dir.path());
        assert!(matches!(result, Err(DeleteError::NotInitialized)));
    }

    #[test]
    fn test_delete_key_not_found() {
        let temp_dir = setup_test_env();

        let cmd = DeleteCommand::new("nonexistent".to_string(), true);
        let result = cmd.run_with_base_dir(temp_dir.path());
        assert!(matches!(result, Err(DeleteError::KeyNotFound(_))));
    }

    #[test]
    fn test_delete_success_with_force() {
        let temp_dir = setup_test_env();
        let keys_dir = temp_dir.path().join(KEYS_DIR_NAME);

        // Store a test key
        store_test_key(&keys_dir, "my-key", "password123");

        // Verify key exists
        let key_file = keys_dir.join("my-key.enc");
        assert!(key_file.exists());

        // Delete with force
        let cmd = DeleteCommand::new("my-key".to_string(), true);
        let result = cmd.run_with_base_dir(temp_dir.path());
        assert!(result.is_ok());

        // Verify key is deleted
        assert!(!key_file.exists());
    }

    #[test]
    fn test_delete_default_key_protected() {
        let temp_dir = setup_test_env();
        let keys_dir = temp_dir.path().join(KEYS_DIR_NAME);

        // Store a default key
        store_test_key(&keys_dir, "default", "password123");

        // Try to delete without force
        let cmd = DeleteCommand::new("default".to_string(), false);
        let result = cmd.run_with_base_dir(temp_dir.path());
        assert!(matches!(result, Err(DeleteError::DefaultKeyProtected)));

        // Key should still exist
        let key_file = keys_dir.join("default.enc");
        assert!(key_file.exists());
    }

    #[test]
    fn test_delete_default_key_with_force() {
        let temp_dir = setup_test_env();
        let keys_dir = temp_dir.path().join(KEYS_DIR_NAME);

        // Store a default key
        store_test_key(&keys_dir, "default", "password123");

        // Delete with force
        let cmd = DeleteCommand::new("default".to_string(), true);
        let result = cmd.run_with_base_dir(temp_dir.path());
        assert!(result.is_ok());

        // Key should be deleted
        let key_file = keys_dir.join("default.enc");
        assert!(!key_file.exists());
    }

    #[test]
    fn test_delete_using_forced_method() {
        let temp_dir = setup_test_env();
        let keys_dir = temp_dir.path().join(KEYS_DIR_NAME);

        // Store a test key
        store_test_key(&keys_dir, "test-key", "password123");

        // Delete using the forced method (no interactive prompt)
        let cmd = DeleteCommand::new("test-key".to_string(), false);
        let result = cmd.run_with_base_dir_forced(temp_dir.path());
        assert!(result.is_ok());

        // Key should be deleted
        let key_file = keys_dir.join("test-key.enc");
        assert!(!key_file.exists());
    }
}
