//! # Key Import Command
//!
//! Implementation of the `sello key import` command that imports a private key from hex.
//!
//! ## Usage
//!
//! ```no_run
//! use sello::cli::commands::key::ImportCommand;
//! use sello::cli::args::CurveArg;
//!
//! // Import a secp256k1 key (for Ethereum/Bitcoin)
//! let cmd = ImportCommand::new("0xabc123...".to_string(), Some("my-key".to_string()), CurveArg::Secp256k1);
//! cmd.run().expect("import failed");
//!
//! // Import an ed25519 key (for Solana)
//! let cmd = ImportCommand::new("0xdef456...".to_string(), Some("my-key".to_string()), CurveArg::Ed25519);
//! cmd.run().expect("import failed");
//! // Key will be stored as "my-key-ed25519"
//! ```
//!
//! ## Security
//!
//! - Keys are validated as valid scalars for the specified curve before storage
//! - Keys are encrypted with a passphrase before storing
//! - Passphrase must be at least 8 characters and confirmed
//! - Intermediate key bytes are zeroized after use to prevent memory leaks
//! - `ImportCommand` implements a custom `Debug` trait that redacts the secret key
//! - Passphrase prompts require an interactive terminal (not piped input)

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use sello_crypto::keypair::{Ed25519KeyPair, KeyPair, Secp256k1KeyPair};
use sello_crypto::keys::SecretKey;
use sello_crypto::store::{FileKeyStore, KeyStore};
use zeroize::{Zeroize, Zeroizing};

use crate::cli::args::CurveArg;

// ============================================================================
// Constants
// ============================================================================

/// Base directory name within the home directory.
const BASE_DIR_NAME: &str = ".sello";

/// Keys subdirectory name.
const KEYS_DIR_NAME: &str = "keys";

/// Expected length of a private key in bytes.
const SECRET_KEY_LEN: usize = 32;

/// Minimum passphrase length.
const MIN_PASSPHRASE_LENGTH: usize = 8;

/// Maximum key name length.
const MAX_KEY_NAME_LENGTH: usize = 64;

/// Ed25519 key suffix.
const ED25519_KEY_SUFFIX: &str = "-ed25519";

// ============================================================================
// ImportError
// ============================================================================

/// Errors that can occur during key import.
#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    /// Sello is not initialized.
    #[error("Sello is not initialized. Run 'sello init' first.")]
    NotInitialized,

    /// Invalid hex format.
    #[error("Invalid hex format: {0}")]
    InvalidHex(String),

    /// Invalid key length.
    #[error("Invalid key length: expected 32 bytes, got {0}")]
    InvalidKeyLength(usize),

    /// Invalid private key (not a valid scalar for the specified curve).
    #[error("Invalid private key: {0}")]
    InvalidKey(String),

    /// Key with this name already exists.
    #[error("Key '{0}' already exists. Use a different name or delete the existing key first.")]
    KeyExists(String),

    /// No key name provided and prompting failed.
    #[error("Key name is required")]
    NameRequired,

    /// Passphrase input was cancelled (empty input).
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

    /// I/O error.
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// Could not determine home directory.
    #[error("Could not determine home directory")]
    NoHomeDirectory,

    /// Storage error.
    #[error("Storage error: {0}")]
    Store(String),

    /// Invalid key name.
    #[error("Invalid key name: {0}")]
    InvalidKeyName(String),
}

// ============================================================================
// ImportCommand
// ============================================================================

/// Command to import a private key from hex.
///
/// Note: This type implements a custom `Debug` that redacts the secret key
/// to prevent accidental exposure in logs or error messages.
///
/// # Security
///
/// The `key_hex` field uses `Zeroizing<String>` to ensure the private key
/// material is automatically zeroized when the command is dropped.
pub struct ImportCommand {
    /// The private key in hex format (with or without 0x prefix).
    /// Wrapped in `Zeroizing` to ensure secure cleanup on drop.
    pub key_hex: Zeroizing<String>,

    /// Optional name for the key.
    pub name: Option<String>,

    /// The elliptic curve type of the key.
    pub curve: CurveArg,
}

impl std::fmt::Debug for ImportCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportCommand")
            .field("key_hex", &"[REDACTED]")
            .field("name", &self.name)
            .field("curve", &self.curve)
            .finish()
    }
}

impl ImportCommand {
    /// Create a new import command.
    ///
    /// The `key_hex` is wrapped in `Zeroizing` to ensure the private key
    /// material is securely erased when the command is dropped.
    #[must_use]
    pub fn new(key_hex: String, name: Option<String>, curve: CurveArg) -> Self {
        Self {
            key_hex: Zeroizing::new(key_hex),
            name,
            curve,
        }
    }

    /// Execute the import command.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Sello is not initialized
    /// - The hex key is invalid or not a valid secp256k1 scalar
    /// - A key with the same name already exists
    /// - No key name was provided
    /// - I/O or storage errors occur
    pub fn run(&self) -> Result<(), ImportError> {
        let base_dir = get_base_dir()?;
        let passphrase = prompt_passphrase()?;
        self.run_with_base_dir_and_passphrase(&base_dir, &passphrase)
    }

    /// Execute the import command with a custom base directory and passphrase.
    ///
    /// This is useful for testing.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Sello is not initialized
    /// - The hex key is invalid or not a valid scalar for the specified curve
    /// - A key with the same name already exists
    /// - No key name was provided
    /// - I/O or storage errors occur
    pub fn run_with_base_dir_and_passphrase(
        &self,
        base_dir: &Path,
        passphrase: &str,
    ) -> Result<(), ImportError> {
        // Check if initialized
        let keys_dir = base_dir.join(KEYS_DIR_NAME);
        if !keys_dir.exists() {
            return Err(ImportError::NotInitialized);
        }

        // Parse and validate the hex key
        let mut key_bytes = parse_hex_key(&self.key_hex)?;

        // Create SecretKey and validate it
        let secret_key = SecretKey::new(key_bytes);

        // Zeroize the intermediate key bytes now that SecretKey has a copy
        key_bytes.zeroize();

        // Determine key name based on curve type
        let base_name = self.name.as_ref().ok_or(ImportError::NameRequired)?.clone();

        // Validate the key name for security
        validate_key_name(&base_name)?;

        let (name, address_display, curve_display) = match self.curve {
            CurveArg::Secp256k1 => {
                // Verify it's a valid secp256k1 key by trying to create a keypair
                let keypair = Secp256k1KeyPair::from_secret_key(&secret_key)
                    .map_err(|e| ImportError::InvalidKey(e.to_string()))?;

                // Get the Ethereum address for display
                let eth_address = keypair.public_key().ethereum_address();
                let address_hex = format!("0x{}", hex::encode(eth_address));

                (base_name, address_hex, "secp256k1 (Ethereum/Bitcoin)")
            }
            CurveArg::Ed25519 => {
                // Verify it's a valid ed25519 key by trying to create a keypair
                let keypair = Ed25519KeyPair::from_secret_key(&secret_key)
                    .map_err(|e| ImportError::InvalidKey(e.to_string()))?;

                // Get the Solana address for display
                let solana_address = keypair.public_key().solana_address();

                // For ed25519 keys, append -ed25519 to the name if not already present
                let name = if base_name.ends_with(ED25519_KEY_SUFFIX) {
                    base_name
                } else {
                    format!("{base_name}{ED25519_KEY_SUFFIX}")
                };

                (name, solana_address, "ed25519 (Solana)")
            }
        };

        // Create key store
        let key_store =
            FileKeyStore::with_path(keys_dir).map_err(|e| ImportError::Store(e.to_string()))?;

        // Check if key already exists
        if key_store.exists(&name) {
            return Err(ImportError::KeyExists(name));
        }

        // Store the key
        key_store
            .store(&name, &secret_key, passphrase)
            .map_err(|e| ImportError::Store(e.to_string()))?;

        println!("Key imported successfully!");
        println!();
        println!("  Name:     {name}");
        println!("  Curve:    {curve_display}");
        println!("  Address:  {address_display}");

        Ok(())
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Get the base directory for Sello.
fn get_base_dir() -> Result<PathBuf, ImportError> {
    dirs::home_dir()
        .map(|home| home.join(BASE_DIR_NAME))
        .ok_or(ImportError::NoHomeDirectory)
}

/// Validate a key name for security and filesystem safety.
///
/// Rejects names that:
/// - Are empty
/// - Exceed the maximum length
/// - Contain path traversal sequences (`..`, `/`, `\`)
/// - Contain null bytes
/// - Contain only whitespace
fn validate_key_name(name: &str) -> Result<(), ImportError> {
    // Check for empty or whitespace-only names
    if name.trim().is_empty() {
        return Err(ImportError::InvalidKeyName(
            "name cannot be empty or whitespace only".to_string(),
        ));
    }

    // Check length (account for potential suffix)
    if name.len() > MAX_KEY_NAME_LENGTH {
        return Err(ImportError::InvalidKeyName(format!(
            "name exceeds maximum length of {MAX_KEY_NAME_LENGTH} characters"
        )));
    }

    // Check for null bytes
    if name.contains('\0') {
        return Err(ImportError::InvalidKeyName(
            "name cannot contain null bytes".to_string(),
        ));
    }

    // Check for path traversal
    if name.contains("..") || name.contains('/') || name.contains('\\') {
        return Err(ImportError::InvalidKeyName(
            "name cannot contain path separators or '..'".to_string(),
        ));
    }

    Ok(())
}

/// Parse a hex string into a 32-byte key.
fn parse_hex_key(hex_str: &str) -> Result<[u8; SECRET_KEY_LEN], ImportError> {
    // Strip 0x prefix if present
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let hex_str = hex_str.strip_prefix("0X").unwrap_or(hex_str);

    // Decode hex
    let mut bytes =
        hex::decode(hex_str).map_err(|e| ImportError::InvalidHex(format!("invalid hex: {e}")))?;

    // Check length
    if bytes.len() != SECRET_KEY_LEN {
        let actual_len = bytes.len();
        bytes.zeroize();
        return Err(ImportError::InvalidKeyLength(actual_len));
    }

    // Convert to fixed-size array
    let mut key = [0u8; SECRET_KEY_LEN];
    key.copy_from_slice(&bytes);

    // Zeroize the intermediate Vec now that we've copied to the fixed-size array
    bytes.zeroize();

    // Check for all-zero key (invalid)
    if key.iter().all(|&b| b == 0) {
        key.zeroize();
        return Err(ImportError::InvalidKey(
            "key cannot be all zeros".to_string(),
        ));
    }

    Ok(key)
}

/// Prompt for a passphrase with confirmation.
fn prompt_passphrase() -> Result<String, ImportError> {
    print!("Enter passphrase to encrypt the key: ");
    io::stdout().flush()?;

    let passphrase =
        rpassword::read_password().map_err(|e| ImportError::TerminalError(e.to_string()))?;

    if passphrase.is_empty() {
        return Err(ImportError::Cancelled);
    }

    if passphrase.len() < MIN_PASSPHRASE_LENGTH {
        return Err(ImportError::PassphraseTooShort);
    }

    print!("Confirm passphrase: ");
    io::stdout().flush()?;

    let confirmation =
        rpassword::read_password().map_err(|e| ImportError::TerminalError(e.to_string()))?;

    if passphrase != confirmation {
        return Err(ImportError::PassphraseMismatch);
    }

    Ok(passphrase)
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

    /// Create a test environment with keys directory.
    fn setup_test_env() -> TempDir {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let keys_dir = temp_dir.path().join(KEYS_DIR_NAME);
        fs::create_dir_all(&keys_dir).expect("Failed to create keys dir");
        temp_dir
    }

    /// Generate a valid test key hex string.
    fn test_key_hex() -> String {
        // Valid secp256k1 private key (32 bytes)
        "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string()
    }

    #[test]
    fn test_parse_hex_key_valid() {
        let key = parse_hex_key(&test_key_hex());
        assert!(key.is_ok());
        assert_eq!(key.unwrap().len(), 32);
    }

    #[test]
    fn test_parse_hex_key_without_prefix() {
        let hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let key = parse_hex_key(hex);
        assert!(key.is_ok());
    }

    #[test]
    fn test_parse_hex_key_uppercase() {
        let hex = "0X0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
        let key = parse_hex_key(hex);
        assert!(key.is_ok());
    }

    #[test]
    fn test_parse_hex_key_invalid_hex() {
        let result = parse_hex_key("0xGGGG");
        assert!(matches!(result, Err(ImportError::InvalidHex(_))));
    }

    #[test]
    fn test_parse_hex_key_too_short() {
        let result = parse_hex_key("0x1234");
        assert!(matches!(result, Err(ImportError::InvalidKeyLength(2))));
    }

    #[test]
    fn test_parse_hex_key_too_long() {
        let hex = "0x".to_string() + &"ab".repeat(33);
        let result = parse_hex_key(&hex);
        assert!(matches!(result, Err(ImportError::InvalidKeyLength(33))));
    }

    #[test]
    fn test_parse_hex_key_all_zeros() {
        let hex = "0x".to_string() + &"00".repeat(32);
        let result = parse_hex_key(&hex);
        assert!(matches!(result, Err(ImportError::InvalidKey(_))));
    }

    #[test]
    fn test_import_not_initialized() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        // Don't create keys directory

        let cmd = ImportCommand::new(
            test_key_hex(),
            Some("test".to_string()),
            CurveArg::Secp256k1,
        );
        let result = cmd.run_with_base_dir_and_passphrase(temp_dir.path(), "password123");
        assert!(matches!(result, Err(ImportError::NotInitialized)));
    }

    #[test]
    fn test_import_success_secp256k1() {
        let temp_dir = setup_test_env();

        let cmd = ImportCommand::new(
            test_key_hex(),
            Some("my-key".to_string()),
            CurveArg::Secp256k1,
        );
        let result = cmd.run_with_base_dir_and_passphrase(temp_dir.path(), "password123");
        assert!(result.is_ok());

        // Verify the key file exists
        let key_file = temp_dir.path().join(KEYS_DIR_NAME).join("my-key.enc");
        assert!(key_file.exists());
    }

    #[test]
    fn test_import_success_ed25519() {
        let temp_dir = setup_test_env();

        let cmd = ImportCommand::new(
            test_key_hex(),
            Some("my-key".to_string()),
            CurveArg::Ed25519,
        );
        let result = cmd.run_with_base_dir_and_passphrase(temp_dir.path(), "password123");
        assert!(result.is_ok());

        // Verify the key file exists with -ed25519 suffix
        let key_file = temp_dir
            .path()
            .join(KEYS_DIR_NAME)
            .join("my-key-ed25519.enc");
        assert!(key_file.exists());
    }

    #[test]
    fn test_import_ed25519_already_has_suffix() {
        let temp_dir = setup_test_env();

        let cmd = ImportCommand::new(
            test_key_hex(),
            Some("my-key-ed25519".to_string()),
            CurveArg::Ed25519,
        );
        let result = cmd.run_with_base_dir_and_passphrase(temp_dir.path(), "password123");
        assert!(result.is_ok());

        // Verify the key file exists without doubling the suffix
        let key_file = temp_dir
            .path()
            .join(KEYS_DIR_NAME)
            .join("my-key-ed25519.enc");
        assert!(key_file.exists());
    }

    #[test]
    fn test_import_duplicate_name() {
        let temp_dir = setup_test_env();
        let _keys_dir = temp_dir.path().join(KEYS_DIR_NAME);

        // Import first key
        let cmd = ImportCommand::new(
            test_key_hex(),
            Some("my-key".to_string()),
            CurveArg::Secp256k1,
        );
        cmd.run_with_base_dir_and_passphrase(temp_dir.path(), "password123")
            .expect("First import failed");

        // Try to import with same name
        let cmd2 = ImportCommand::new(
            "0xfedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210".to_string(),
            Some("my-key".to_string()),
            CurveArg::Secp256k1,
        );
        let result = cmd2.run_with_base_dir_and_passphrase(temp_dir.path(), "password456");
        assert!(matches!(result, Err(ImportError::KeyExists(_))));
    }

    #[test]
    fn test_import_no_name() {
        let temp_dir = setup_test_env();

        let cmd = ImportCommand::new(test_key_hex(), None, CurveArg::Secp256k1);
        let result = cmd.run_with_base_dir_and_passphrase(temp_dir.path(), "password123");
        assert!(matches!(result, Err(ImportError::NameRequired)));
    }
}
