//! # Key Export Command
//!
//! Implementation of the `txgate key export` command that exports a key as an encrypted backup.
//!
//! ## Usage
//!
//! ```no_run
//! use txgate::cli::commands::key::ExportCommand;
//! use std::path::PathBuf;
//!
//! let cmd = ExportCommand::new("my-key".to_string(), Some(PathBuf::from("/tmp/backup.json")), false);
//! cmd.run().expect("export failed");
//! ```
//!
//! ## Output Format
//!
//! The exported key is stored as JSON with the encrypted key data:
//!
//! ```json
//! {
//!   "version": 1,
//!   "name": "my-key",
//!   "ethereum_address": "0x...",
//!   "encrypted_key": "base64-encoded-77-bytes"
//! }
//! ```
//!
//! ## Security
//!
//! - Requires the current passphrase to decrypt the key
//! - Requires a new passphrase for the export (with confirmation)
//! - Output file permissions are set to 0600
//! - Current passphrase can be provided via `TXGATE_PASSPHRASE` env var or interactive prompt
//! - Export passphrase can be provided via `TXGATE_EXPORT_PASSPHRASE` (falls back to `TXGATE_PASSPHRASE`, then interactive prompt)
//! - Wrong passphrase errors are detected reliably (not via string matching)

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use base64::Engine;
use serde::{Deserialize, Serialize};

use txgate_core::error::StoreError;
use txgate_crypto::encryption::encrypt_key;
use txgate_crypto::keypair::{KeyPair, Secp256k1KeyPair};
use txgate_crypto::store::{FileKeyStore, KeyStore};
use zeroize::Zeroizing;

use crate::cli::passphrase::{PassphraseError, MIN_PASSPHRASE_LENGTH};

// ============================================================================
// Constants
// ============================================================================

/// Base directory name within the home directory.
const BASE_DIR_NAME: &str = ".txgate";

/// Keys subdirectory name.
const KEYS_DIR_NAME: &str = "keys";

/// Current export format version.
const EXPORT_VERSION: u32 = 1;

// ============================================================================
// ExportedKey
// ============================================================================

/// Structure for the exported key JSON format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedKey {
    /// Export format version.
    pub version: u32,

    /// Key name.
    pub name: String,

    /// Ethereum address derived from the key.
    pub ethereum_address: String,

    /// Base64-encoded encrypted key data.
    pub encrypted_key: String,
}

// ============================================================================
// ExportError
// ============================================================================

/// Errors that can occur during key export.
#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    /// `TxGate` is not initialized.
    #[error("TxGate is not initialized. Run 'txgate init' first.")]
    NotInitialized,

    /// Key not found.
    #[error("Key '{0}' not found")]
    KeyNotFound(String),

    /// Wrong passphrase.
    #[error("Wrong passphrase")]
    WrongPassphrase,

    /// Passphrase input was cancelled.
    #[error("Passphrase input cancelled")]
    Cancelled,

    /// Failed to read passphrase from terminal.
    #[error("Failed to read passphrase from terminal: {0}")]
    TerminalError(String),

    /// Passphrase is too short.
    #[error("Passphrase must be at least {MIN_PASSPHRASE_LENGTH} characters")]
    PassphraseTooShort,

    /// Passphrases don't match.
    #[error("Passphrases do not match")]
    PassphraseMismatch,

    /// Output file already exists.
    #[error("Output file '{0}' already exists. Use --force to overwrite.")]
    FileExists(String),

    /// I/O error.
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// Could not determine home directory.
    #[error("Could not determine home directory")]
    NoHomeDirectory,

    /// Storage error.
    #[error("Storage error: {0}")]
    Store(String),

    /// Encryption error.
    #[error("Encryption error: {0}")]
    Encryption(String),

    /// Key derivation error.
    #[error("Key derivation error: {0}")]
    KeyDerivation(String),

    /// Serialization error.
    #[error("Serialization error: {0}")]
    Serialization(String),
}

// ============================================================================
// ExportCommand
// ============================================================================

/// Command to export a key as an encrypted backup.
#[derive(Debug, Clone)]
pub struct ExportCommand {
    /// Name of the key to export.
    pub name: String,

    /// Output file path (defaults to stdout).
    pub output: Option<PathBuf>,

    /// Overwrite existing output file.
    pub force: bool,
}

impl ExportCommand {
    /// Create a new export command.
    #[must_use]
    pub const fn new(name: String, output: Option<PathBuf>, force: bool) -> Self {
        Self {
            name,
            output,
            force,
        }
    }

    /// Execute the export command.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `TxGate` is not initialized
    /// - The key does not exist
    /// - The passphrase is incorrect
    /// - The output file already exists and `--force` was not specified
    /// - I/O, encryption, or storage errors occur
    pub fn run(&self) -> Result<(), ExportError> {
        let base_dir = get_base_dir()?;

        // Prompt for current passphrase
        let current_passphrase = read_current_passphrase()?;

        // Prompt for new passphrase
        let new_passphrase = read_new_passphrase_for_export()?;

        self.run_with_base_dir_and_passphrases(&base_dir, &current_passphrase, &new_passphrase)
    }

    /// Execute the export command with a custom base directory and passphrases.
    ///
    /// This is useful for testing.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `TxGate` is not initialized
    /// - The key does not exist
    /// - The passphrase is incorrect
    /// - The output file already exists and `--force` was not specified
    /// - I/O, encryption, or storage errors occur
    pub fn run_with_base_dir_and_passphrases(
        &self,
        base_dir: &Path,
        current_passphrase: &str,
        new_passphrase: &str,
    ) -> Result<(), ExportError> {
        // Check if initialized
        let keys_dir = base_dir.join(KEYS_DIR_NAME);
        if !keys_dir.exists() {
            return Err(ExportError::NotInitialized);
        }

        // Create key store
        let key_store =
            FileKeyStore::with_path(keys_dir).map_err(|e| ExportError::Store(e.to_string()))?;

        // Check if key exists
        if !key_store.exists(&self.name) {
            return Err(ExportError::KeyNotFound(self.name.clone()));
        }

        // Load and decrypt the key
        let secret_key = key_store
            .load(&self.name, current_passphrase)
            .map_err(|e| match e {
                StoreError::DecryptionFailed => ExportError::WrongPassphrase,
                other => ExportError::Store(other.to_string()),
            })?;

        // Get Ethereum address
        let keypair = Secp256k1KeyPair::from_secret_key(&secret_key)
            .map_err(|e| ExportError::KeyDerivation(e.to_string()))?;
        let eth_address = keypair.public_key().ethereum_address();
        let eth_address_hex = format!("0x{}", hex::encode(eth_address));

        // Re-encrypt with new passphrase
        let encrypted = encrypt_key(&secret_key, new_passphrase)
            .map_err(|e| ExportError::Encryption(e.to_string()))?;

        // Encode as base64
        let encrypted_base64 =
            base64::engine::general_purpose::STANDARD.encode(encrypted.to_bytes());

        // Create export structure
        let exported = ExportedKey {
            version: EXPORT_VERSION,
            name: self.name.clone(),
            ethereum_address: eth_address_hex.clone(),
            encrypted_key: encrypted_base64,
        };

        // Serialize to JSON
        let json = serde_json::to_string_pretty(&exported)
            .map_err(|e| ExportError::Serialization(e.to_string()))?;

        // Output
        if let Some(output_path) = &self.output {
            // Check if file exists
            if output_path.exists() && !self.force {
                return Err(ExportError::FileExists(output_path.display().to_string()));
            }

            // Write to file
            let mut file = File::create(output_path)?;
            file.write_all(json.as_bytes())?;
            file.write_all(b"\n")?;

            // Set file permissions (Unix only)
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let permissions = fs::Permissions::from_mode(0o600);
                fs::set_permissions(output_path, permissions)?;
            }

            println!("Key exported successfully!");
            println!();
            println!("  Name:     {}", self.name);
            println!("  Address:  {eth_address_hex}");
            println!("  Output:   {}", output_path.display());
        } else {
            // Output to stdout
            println!("{json}");
        }

        Ok(())
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Get the base directory for `TxGate`.
fn get_base_dir() -> Result<PathBuf, ExportError> {
    dirs::home_dir()
        .map(|home| home.join(BASE_DIR_NAME))
        .ok_or(ExportError::NoHomeDirectory)
}

/// Read the current passphrase (from env var or interactive prompt).
fn read_current_passphrase() -> Result<Zeroizing<String>, ExportError> {
    crate::cli::passphrase::read_passphrase().map_err(|e| match e {
        PassphraseError::Empty | PassphraseError::Cancelled => ExportError::Cancelled,
        PassphraseError::Io(io_err) => ExportError::Io(io_err),
        other => ExportError::TerminalError(other.to_string()),
    })
}

/// Read a new passphrase for export (from env var or interactive prompt with confirmation).
fn read_new_passphrase_for_export() -> Result<Zeroizing<String>, ExportError> {
    crate::cli::passphrase::read_new_export_passphrase().map_err(|e| match e {
        PassphraseError::Empty | PassphraseError::Cancelled => ExportError::Cancelled,
        PassphraseError::TooShort { .. } => ExportError::PassphraseTooShort,
        PassphraseError::Mismatch => ExportError::PassphraseMismatch,
        PassphraseError::Io(e) => ExportError::Io(e),
    })
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
    fn store_test_key(keys_dir: &Path, name: &str, passphrase: &str) -> SecretKey {
        let secret_key = SecretKey::generate();
        let encrypted = encrypt_key(&secret_key, passphrase).expect("Failed to encrypt");
        let file_path = keys_dir.join(format!("{name}.enc"));
        fs::write(file_path, encrypted.to_bytes()).expect("Failed to write key");
        secret_key
    }

    #[test]
    fn test_export_not_initialized() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        // Don't create keys directory

        let cmd = ExportCommand::new("test".to_string(), None, false);
        let result =
            cmd.run_with_base_dir_and_passphrases(temp_dir.path(), "password", "newpass123");
        assert!(matches!(result, Err(ExportError::NotInitialized)));
    }

    #[test]
    fn test_export_key_not_found() {
        let temp_dir = setup_test_env();

        let cmd = ExportCommand::new("nonexistent".to_string(), None, false);
        let result =
            cmd.run_with_base_dir_and_passphrases(temp_dir.path(), "password", "newpass123");
        assert!(matches!(result, Err(ExportError::KeyNotFound(_))));
    }

    #[test]
    fn test_export_wrong_passphrase() {
        let temp_dir = setup_test_env();
        let keys_dir = temp_dir.path().join(KEYS_DIR_NAME);

        // Store a test key with a known passphrase
        store_test_key(&keys_dir, "my-key", "correct-password");

        // Try to export with wrong passphrase
        let cmd = ExportCommand::new("my-key".to_string(), None, false);
        let result =
            cmd.run_with_base_dir_and_passphrases(temp_dir.path(), "wrong-password", "newpass123");
        assert!(matches!(result, Err(ExportError::WrongPassphrase)));
    }

    #[test]
    fn test_export_to_file_success() {
        let temp_dir = setup_test_env();
        let keys_dir = temp_dir.path().join(KEYS_DIR_NAME);

        // Store a test key
        store_test_key(&keys_dir, "my-key", "password123");

        // Export to file
        let output_path = temp_dir.path().join("exported.json");
        let cmd = ExportCommand::new("my-key".to_string(), Some(output_path.clone()), false);
        let result =
            cmd.run_with_base_dir_and_passphrases(temp_dir.path(), "password123", "newpass456");
        assert!(result.is_ok());

        // Verify file exists and contains valid JSON
        assert!(output_path.exists());
        let content = fs::read_to_string(&output_path).expect("Failed to read export");
        let exported: ExportedKey = serde_json::from_str(&content).expect("Invalid JSON");

        assert_eq!(exported.version, EXPORT_VERSION);
        assert_eq!(exported.name, "my-key");
        assert!(exported.ethereum_address.starts_with("0x"));
        assert!(!exported.encrypted_key.is_empty());
    }

    #[test]
    fn test_export_file_exists_without_force() {
        let temp_dir = setup_test_env();
        let keys_dir = temp_dir.path().join(KEYS_DIR_NAME);

        // Store a test key
        store_test_key(&keys_dir, "my-key", "password123");

        // Create existing output file
        let output_path = temp_dir.path().join("existing.json");
        fs::write(&output_path, "existing content").expect("Failed to create file");

        // Try to export without force
        let cmd = ExportCommand::new("my-key".to_string(), Some(output_path), false);
        let result =
            cmd.run_with_base_dir_and_passphrases(temp_dir.path(), "password123", "newpass456");
        assert!(matches!(result, Err(ExportError::FileExists(_))));
    }

    #[test]
    fn test_export_file_exists_with_force() {
        let temp_dir = setup_test_env();
        let keys_dir = temp_dir.path().join(KEYS_DIR_NAME);

        // Store a test key
        store_test_key(&keys_dir, "my-key", "password123");

        // Create existing output file
        let output_path = temp_dir.path().join("existing.json");
        fs::write(&output_path, "existing content").expect("Failed to create file");

        // Export with force
        let cmd = ExportCommand::new("my-key".to_string(), Some(output_path.clone()), true);
        let result =
            cmd.run_with_base_dir_and_passphrases(temp_dir.path(), "password123", "newpass456");
        assert!(result.is_ok());

        // Verify file was overwritten
        let content = fs::read_to_string(&output_path).expect("Failed to read export");
        assert!(content.contains("encrypted_key"));
    }

    #[test]
    fn test_export_to_stdout() {
        let temp_dir = setup_test_env();
        let keys_dir = temp_dir.path().join(KEYS_DIR_NAME);

        // Store a test key
        store_test_key(&keys_dir, "my-key", "password123");

        // Export to stdout (no output path)
        let cmd = ExportCommand::new("my-key".to_string(), None, false);
        let result =
            cmd.run_with_base_dir_and_passphrases(temp_dir.path(), "password123", "newpass456");
        assert!(result.is_ok());
    }

    #[test]
    fn test_exported_key_structure() {
        let exported = ExportedKey {
            version: 1,
            name: "test".to_string(),
            ethereum_address: "0x1234".to_string(),
            encrypted_key: "base64data".to_string(),
        };

        let json = serde_json::to_string(&exported).expect("Serialization failed");
        let deserialized: ExportedKey =
            serde_json::from_str(&json).expect("Deserialization failed");

        assert_eq!(deserialized.version, exported.version);
        assert_eq!(deserialized.name, exported.name);
        assert_eq!(deserialized.ethereum_address, exported.ethereum_address);
        assert_eq!(deserialized.encrypted_key, exported.encrypted_key);
    }
}
