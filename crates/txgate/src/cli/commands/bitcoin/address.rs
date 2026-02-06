//! # Bitcoin Address Command
//!
//! Implementation of the `txgate bitcoin address` command that displays
//! the Bitcoin address derived from the default signing key.
//!
//! ## Usage
//!
//! ```no_run
//! use txgate::cli::commands::bitcoin::AddressCommand;
//!
//! let cmd = AddressCommand;
//! match cmd.run() {
//!     Ok(()) => println!("Address displayed successfully"),
//!     Err(e) => eprintln!("Error: {}", e),
//! }
//! ```
//!
//! ## Output
//!
//! The command outputs the Bitcoin address in P2WPKH (bech32) format:
//!
//! ```text
//! bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
//! ```

use std::io;
use std::path::{Path, PathBuf};

use txgate_core::error::StoreError;
use txgate_crypto::keypair::Secp256k1KeyPair;
use txgate_crypto::signer::{Chain, Secp256k1Signer, Signer};
use txgate_crypto::store::{FileKeyStore, KeyStore};
use zeroize::Zeroizing;

use crate::cli::passphrase::PassphraseError;

// ============================================================================
// Constants
// ============================================================================

/// Base directory name within the home directory.
const BASE_DIR_NAME: &str = ".txgate";

/// Keys subdirectory name.
const KEYS_DIR_NAME: &str = "keys";

/// Config file name.
const CONFIG_FILE_NAME: &str = "config.toml";

/// Default key name.
const DEFAULT_KEY_NAME: &str = "default";

// ============================================================================
// AddressError
// ============================================================================

/// Errors that can occur when displaying the Bitcoin address.
#[derive(Debug, thiserror::Error)]
pub enum AddressError {
    /// `TxGate` is not initialized.
    #[error("TxGate is not initialized. Run 'txgate init' first.")]
    NotInitialized,

    /// Default key not found.
    #[error("Default key not found. Run 'txgate init' to create one.")]
    KeyNotFound,

    /// Failed to load the key.
    #[error("Failed to load key: {0}")]
    KeyLoadError(String),

    /// Invalid passphrase (decryption failed).
    #[error("Invalid passphrase")]
    InvalidPassphrase,

    /// I/O error occurred.
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// Passphrase input was cancelled.
    #[error("Passphrase input cancelled")]
    Cancelled,

    /// Passphrase input failed (terminal error).
    #[error("Failed to read passphrase: {0}")]
    PassphraseInputFailed(String),

    /// Home directory could not be determined.
    #[error("Could not determine home directory")]
    NoHomeDirectory,
}

impl From<StoreError> for AddressError {
    fn from(err: StoreError) -> Self {
        match err {
            StoreError::KeyNotFound { .. } => Self::KeyNotFound,
            StoreError::DecryptionFailed => Self::InvalidPassphrase,
            StoreError::IoError(e) => Self::Io(e),
            other => Self::KeyLoadError(other.to_string()),
        }
    }
}

// ============================================================================
// AddressCommand
// ============================================================================

/// The `txgate bitcoin address` command handler.
///
/// This command displays the Bitcoin address derived from the default
/// signing key. The address is output in P2WPKH (bech32) format.
///
/// # Example
///
/// ```no_run
/// use txgate::cli::commands::bitcoin::AddressCommand;
///
/// let cmd = AddressCommand;
/// match cmd.run() {
///     Ok(()) => println!("Success"),
///     Err(e) => eprintln!("Error: {}", e),
/// }
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct AddressCommand;

impl AddressCommand {
    /// Create a new `AddressCommand`.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Run the address display command.
    ///
    /// This method:
    /// 1. Checks if `TxGate` is initialized
    /// 2. Checks if the default key exists
    /// 3. Prompts for the passphrase
    /// 4. Loads and decrypts the key
    /// 5. Derives and displays the Bitcoin address
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `TxGate` is not initialized
    /// - The default key does not exist
    /// - The passphrase input fails or is cancelled
    /// - The passphrase is incorrect
    /// - Key loading fails
    pub fn run(&self) -> Result<(), AddressError> {
        let base_dir = get_base_dir()?;
        self.run_with_base_dir(&base_dir)
    }

    /// Run the address display command with a custom base directory.
    ///
    /// This is primarily used for testing to avoid modifying the user's
    /// actual home directory.
    ///
    /// # Errors
    ///
    /// Same as [`run`](Self::run).
    pub fn run_with_base_dir(&self, base_dir: &Path) -> Result<(), AddressError> {
        // 1. Check if initialized
        if !is_initialized(base_dir) {
            return Err(AddressError::NotInitialized);
        }

        // 2. Check if default key exists
        let key_path = base_dir
            .join(KEYS_DIR_NAME)
            .join(format!("{DEFAULT_KEY_NAME}.enc"));
        if !key_path.exists() {
            return Err(AddressError::KeyNotFound);
        }

        // 3. Prompt for passphrase
        let passphrase = read_passphrase_for_address()?;

        // 4. Load and decrypt key
        let keys_dir = base_dir.join(KEYS_DIR_NAME);
        let store = FileKeyStore::with_path(keys_dir)?;
        let secret_key = store.load(DEFAULT_KEY_NAME, &passphrase)?;

        // 5. Create keypair and derive address
        let keypair = Secp256k1KeyPair::from_secret_key(&secret_key)
            .map_err(|e| AddressError::KeyLoadError(e.to_string()))?;

        let signer = Secp256k1Signer::new(keypair);
        let address = signer
            .address(Chain::Bitcoin)
            .map_err(|e| AddressError::KeyLoadError(e.to_string()))?;

        // 6. Display the address
        println!("{address}");

        Ok(())
    }

    /// Run the address display command with a provided passphrase.
    ///
    /// This is primarily used for testing to avoid interactive prompts.
    ///
    /// # Errors
    ///
    /// Same as [`run`](Self::run), except passphrase input errors.
    #[cfg(test)]
    pub fn run_with_passphrase(
        &self,
        base_dir: &Path,
        passphrase: &str,
    ) -> Result<String, AddressError> {
        // 1. Check if initialized
        if !is_initialized(base_dir) {
            return Err(AddressError::NotInitialized);
        }

        // 2. Check if default key exists
        let key_path = base_dir
            .join(KEYS_DIR_NAME)
            .join(format!("{DEFAULT_KEY_NAME}.enc"));
        if !key_path.exists() {
            return Err(AddressError::KeyNotFound);
        }

        // 3. Load and decrypt key
        let keys_dir = base_dir.join(KEYS_DIR_NAME);
        let store = FileKeyStore::with_path(keys_dir)?;
        let secret_key = store.load(DEFAULT_KEY_NAME, passphrase)?;

        // 4. Create keypair and derive address
        let keypair = Secp256k1KeyPair::from_secret_key(&secret_key)
            .map_err(|e| AddressError::KeyLoadError(e.to_string()))?;

        let signer = Secp256k1Signer::new(keypair);
        let address = signer
            .address(Chain::Bitcoin)
            .map_err(|e| AddressError::KeyLoadError(e.to_string()))?;

        Ok(address)
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Get the base directory for `TxGate` files (~/.txgate).
fn get_base_dir() -> Result<PathBuf, AddressError> {
    dirs::home_dir()
        .map(|home| home.join(BASE_DIR_NAME))
        .ok_or(AddressError::NoHomeDirectory)
}

/// Check if `TxGate` is initialized.
///
/// Returns true if the config file exists.
fn is_initialized(base_dir: &Path) -> bool {
    let config_path = base_dir.join(CONFIG_FILE_NAME);
    config_path.exists()
}

/// Read passphrase (from env var or interactive prompt).
fn read_passphrase_for_address() -> Result<Zeroizing<String>, AddressError> {
    crate::cli::passphrase::read_passphrase().map_err(|e| match e {
        PassphraseError::Empty | PassphraseError::Cancelled => AddressError::Cancelled,
        other => AddressError::KeyLoadError(other.to_string()),
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
    use std::fs;
    use tempfile::TempDir;
    use txgate_crypto::keys::SecretKey;

    /// Create a temporary directory for testing.
    fn create_test_dir() -> TempDir {
        TempDir::new().expect("failed to create temp dir")
    }

    /// Set up a test environment with an initialized `TxGate`.
    fn setup_initialized_env(temp_dir: &TempDir) -> (PathBuf, String) {
        let base_dir = temp_dir.path().to_path_buf();
        let keys_dir = base_dir.join(KEYS_DIR_NAME);
        let passphrase = "test-passphrase-123";

        // Create directory structure
        fs::create_dir_all(&keys_dir).expect("failed to create keys dir");

        // Create config file
        fs::write(base_dir.join(CONFIG_FILE_NAME), "[server]\nport = 3000\n")
            .expect("failed to write config");

        // Generate and store a key
        let secret_key = SecretKey::generate();
        let store = FileKeyStore::with_path(keys_dir).expect("failed to create key store");
        store
            .store(DEFAULT_KEY_NAME, &secret_key, passphrase)
            .expect("failed to store key");

        (base_dir, passphrase.to_string())
    }

    // ------------------------------------------------------------------------
    // Error Type Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_address_error_display() {
        assert_eq!(
            AddressError::NotInitialized.to_string(),
            "TxGate is not initialized. Run 'txgate init' first."
        );

        assert_eq!(
            AddressError::KeyNotFound.to_string(),
            "Default key not found. Run 'txgate init' to create one."
        );

        assert_eq!(
            AddressError::KeyLoadError("test error".to_string()).to_string(),
            "Failed to load key: test error"
        );

        assert_eq!(
            AddressError::InvalidPassphrase.to_string(),
            "Invalid passphrase"
        );

        assert_eq!(
            AddressError::Cancelled.to_string(),
            "Passphrase input cancelled"
        );

        assert_eq!(
            AddressError::NoHomeDirectory.to_string(),
            "Could not determine home directory"
        );
    }

    #[test]
    fn test_address_error_from_store_error() {
        let store_err = StoreError::KeyNotFound {
            name: "default".to_string(),
        };
        let addr_err: AddressError = store_err.into();
        assert!(matches!(addr_err, AddressError::KeyNotFound));

        let store_err = StoreError::DecryptionFailed;
        let addr_err: AddressError = store_err.into();
        assert!(matches!(addr_err, AddressError::InvalidPassphrase));

        let io_err = std::io::Error::other("test error");
        let store_err = StoreError::IoError(io_err);
        let addr_err: AddressError = store_err.into();
        assert!(matches!(addr_err, AddressError::Io(_)));

        let store_err = StoreError::InvalidFormat;
        let addr_err: AddressError = store_err.into();
        assert!(matches!(addr_err, AddressError::KeyLoadError(_)));
    }

    // ------------------------------------------------------------------------
    // Command Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_address_command_not_initialized() {
        let temp_dir = create_test_dir();
        let base_dir = temp_dir.path().to_path_buf();

        let cmd = AddressCommand::new();
        let result = cmd.run_with_base_dir(&base_dir);

        assert!(matches!(result, Err(AddressError::NotInitialized)));
    }

    #[test]
    fn test_address_command_key_not_found() {
        let temp_dir = create_test_dir();
        let base_dir = temp_dir.path().to_path_buf();

        // Create config but no key
        fs::create_dir_all(&base_dir).expect("failed to create dir");
        fs::write(base_dir.join(CONFIG_FILE_NAME), "[server]\nport = 3000\n")
            .expect("failed to write config");

        let cmd = AddressCommand::new();
        let result = cmd.run_with_base_dir(&base_dir);

        assert!(matches!(result, Err(AddressError::KeyNotFound)));
    }

    #[test]
    fn test_address_command_success() {
        let temp_dir = create_test_dir();
        let (base_dir, passphrase) = setup_initialized_env(&temp_dir);

        let cmd = AddressCommand::new();
        let result = cmd.run_with_passphrase(&base_dir, &passphrase);

        assert!(result.is_ok());
        let address = result.unwrap();

        // Verify P2WPKH bech32 address format
        assert!(
            address.starts_with("bc1q"),
            "Address should start with bc1q: {address}"
        );
        assert_eq!(
            address.len(),
            42,
            "P2WPKH address should be 42 characters: {address}"
        );
    }

    #[test]
    fn test_address_command_wrong_passphrase() {
        let temp_dir = create_test_dir();
        let (base_dir, _passphrase) = setup_initialized_env(&temp_dir);

        let cmd = AddressCommand::new();
        let result = cmd.run_with_passphrase(&base_dir, "wrong-passphrase");

        assert!(matches!(result, Err(AddressError::InvalidPassphrase)));
    }

    #[test]
    fn test_address_is_bech32() {
        let temp_dir = create_test_dir();
        let (base_dir, passphrase) = setup_initialized_env(&temp_dir);

        let cmd = AddressCommand::new();
        let result = cmd.run_with_passphrase(&base_dir, &passphrase);

        assert!(result.is_ok());
        let address = result.unwrap();

        // P2WPKH bech32 addresses:
        // - Start with bc1q for mainnet
        // - Are 42 characters long
        // - Use lowercase a-z and 0-9 (except 1, b, i, o)
        assert!(address.starts_with("bc1q"));
        assert_eq!(address.len(), 42);
        assert!(address
            .chars()
            .skip(4)
            .all(|c| { c.is_ascii_lowercase() || c.is_ascii_digit() }));
    }

    #[test]
    fn test_address_command_deterministic() {
        let temp_dir = create_test_dir();
        let (base_dir, passphrase) = setup_initialized_env(&temp_dir);

        let cmd = AddressCommand::new();

        // Get address twice
        let result1 = cmd.run_with_passphrase(&base_dir, &passphrase);
        let result2 = cmd.run_with_passphrase(&base_dir, &passphrase);

        assert!(result1.is_ok());
        assert!(result2.is_ok());

        // Same key should produce same address
        assert_eq!(result1.unwrap(), result2.unwrap());
    }

    // ------------------------------------------------------------------------
    // Thread Safety Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_address_command_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<AddressCommand>();
    }

    #[test]
    fn test_address_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<AddressError>();
    }

    // ------------------------------------------------------------------------
    // Helper Function Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_is_initialized_false_when_no_config() {
        let temp_dir = create_test_dir();
        let base_dir = temp_dir.path().to_path_buf();

        assert!(!is_initialized(&base_dir));
    }

    #[test]
    fn test_is_initialized_true_when_config_exists() {
        let temp_dir = create_test_dir();
        let base_dir = temp_dir.path().to_path_buf();

        fs::create_dir_all(&base_dir).expect("failed to create dir");
        fs::write(base_dir.join(CONFIG_FILE_NAME), "test").expect("failed to write config");

        assert!(is_initialized(&base_dir));
    }
}
