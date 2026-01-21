//! # Init Command
//!
//! Implementation of the `sello init` command that initializes the Sello
//! configuration directory, generates a default key, and creates the config file.
//!
//! ## Directory Structure
//!
//! The init command creates the following structure:
//!
//! ```text
//! ~/.sello/
//! ├── config.toml       (0600)
//! ├── keys/             (0700)
//! │   └── default.enc   (0600)
//! └── logs/             (0700)
//! ```
//!
//! ## Usage
//!
//! ```no_run
//! use sello::cli::commands::init::InitCommand;
//!
//! let cmd = InitCommand { force: false };
//! cmd.run().expect("initialization failed");
//! ```

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use sello_core::config::Config;
use sello_core::error::{ConfigError, StoreError};
use sello_crypto::keypair::{KeyPair, Secp256k1KeyPair};
use sello_crypto::keys::SecretKey;
use sello_crypto::store::{FileKeyStore, KeyStore};

// ============================================================================
// Constants
// ============================================================================

/// Minimum passphrase length in characters.
const MIN_PASSPHRASE_LENGTH: usize = 8;

/// Default key name for the generated key.
const DEFAULT_KEY_NAME: &str = "default";

/// Base directory name within the home directory.
const BASE_DIR_NAME: &str = ".sello";

/// Keys subdirectory name.
const KEYS_DIR_NAME: &str = "keys";

/// Logs subdirectory name.
const LOGS_DIR_NAME: &str = "logs";

/// Config file name.
const CONFIG_FILE_NAME: &str = "config.toml";

// ============================================================================
// InitError
// ============================================================================

/// Errors that can occur during initialization.
#[derive(Debug, thiserror::Error)]
pub enum InitError {
    /// Sello is already initialized and --force was not specified.
    #[error("Sello is already initialized. Use --force to reinitialize.")]
    AlreadyInitialized,

    /// Failed to create a directory.
    #[error("Failed to create directory: {0}")]
    DirectoryCreation(#[source] io::Error),

    /// The entered passphrases do not match.
    #[error("Passphrases do not match")]
    PassphraseMismatch,

    /// The passphrase is too short.
    #[error("Passphrase is too short (minimum {MIN_PASSPHRASE_LENGTH} characters)")]
    PassphraseTooShort,

    /// Failed to generate a key.
    #[error("Failed to generate key: {0}")]
    KeyGeneration(String),

    /// Failed to store the key.
    #[error("Failed to store key: {0}")]
    KeyStorage(#[source] StoreError),

    /// Failed to write the config file.
    #[error("Failed to write config: {0}")]
    ConfigWrite(#[source] ConfigError),

    /// General I/O error.
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// Home directory could not be determined.
    #[error("Could not determine home directory")]
    NoHomeDirectory,

    /// Passphrase input was cancelled or empty.
    #[error("Passphrase input cancelled")]
    PassphraseCancelled,
}

// ============================================================================
// InitCommand
// ============================================================================

/// The `sello init` command handler.
///
/// This command initializes the Sello configuration directory structure,
/// generates a default signing key, and creates the default config file.
///
/// # Example
///
/// ```no_run
/// use sello::cli::commands::init::InitCommand;
///
/// let cmd = InitCommand { force: false };
/// match cmd.run() {
///     Ok(()) => println!("Initialization complete"),
///     Err(e) => eprintln!("Error: {}", e),
/// }
/// ```
#[derive(Debug, Clone)]
pub struct InitCommand {
    /// Force re-initialization even if already initialized.
    pub force: bool,
}

impl InitCommand {
    /// Create a new `InitCommand`.
    #[must_use]
    pub const fn new(force: bool) -> Self {
        Self { force }
    }

    /// Run the initialization command.
    ///
    /// This method:
    /// 1. Checks if already initialized (unless --force)
    /// 2. Creates ~/.sello directory structure
    /// 3. Prompts for passphrase (with confirmation)
    /// 4. Generates secp256k1 keypair
    /// 5. Encrypts and stores key
    /// 6. Creates default config.toml
    /// 7. Sets file permissions
    /// 8. Displays success message with next steps
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Already initialized and --force not specified
    /// - Directory creation fails
    /// - Passphrases don't match or are too short
    /// - Key generation or storage fails
    /// - Config file write fails
    pub fn run(&self) -> Result<(), InitError> {
        let base_dir = get_base_dir()?;

        // 1. Check if already initialized (unless --force)
        if !self.force && is_initialized(&base_dir) {
            return Err(InitError::AlreadyInitialized);
        }

        // 2. Create ~/.sello directory structure
        create_directory_structure(&base_dir)?;

        // 3. Prompt for passphrase (with confirmation)
        let passphrase = prompt_passphrase()?;

        // 4. Generate secp256k1 keypair
        let secret_key = SecretKey::generate();
        let keypair = Secp256k1KeyPair::from_secret_key(&secret_key)
            .map_err(|e| InitError::KeyGeneration(e.to_string()))?;

        // Get the Ethereum address for display
        let eth_address = keypair.public_key().ethereum_address();
        let eth_address_hex = format!("0x{}", hex::encode(eth_address));

        // 5. Encrypt and store key
        let keys_dir = base_dir.join(KEYS_DIR_NAME);
        let key_store = FileKeyStore::with_path(keys_dir).map_err(InitError::KeyStorage)?;

        // If force is set and key exists, delete it first
        if self.force && key_store.exists(DEFAULT_KEY_NAME) {
            key_store
                .delete(DEFAULT_KEY_NAME)
                .map_err(InitError::KeyStorage)?;
        }

        key_store
            .store(DEFAULT_KEY_NAME, &secret_key, &passphrase)
            .map_err(InitError::KeyStorage)?;

        // 6. Create default config.toml
        write_default_config(&base_dir)?;

        // 7. Set file permissions (already done in create_directory_structure and FileKeyStore)

        // 8. Display success message with next steps
        print_success_message(&eth_address_hex);

        Ok(())
    }

    /// Run the initialization command with a custom base directory.
    ///
    /// This is primarily used for testing to avoid modifying the user's
    /// actual home directory.
    ///
    /// # Errors
    ///
    /// Same as [`run`](Self::run).
    #[cfg(test)]
    #[allow(clippy::needless_pass_by_value)]
    pub fn run_with_base_dir(&self, base_dir: PathBuf) -> Result<String, InitError> {
        // 1. Check if already initialized (unless --force)
        if !self.force && is_initialized(&base_dir) {
            return Err(InitError::AlreadyInitialized);
        }

        // 2. Create ~/.sello directory structure
        create_directory_structure(&base_dir)?;

        // Use a test passphrase instead of prompting
        let passphrase = "test-passphrase-123";

        // 4. Generate secp256k1 keypair
        let secret_key = SecretKey::generate();
        let keypair = Secp256k1KeyPair::from_secret_key(&secret_key)
            .map_err(|e| InitError::KeyGeneration(e.to_string()))?;

        // Get the Ethereum address for display
        let eth_address = keypair.public_key().ethereum_address();
        let eth_address_hex = format!("0x{}", hex::encode(eth_address));

        // 5. Encrypt and store key
        let keys_dir = base_dir.join(KEYS_DIR_NAME);
        let key_store = FileKeyStore::with_path(keys_dir).map_err(InitError::KeyStorage)?;

        // If force is set and key exists, delete it first
        if self.force && key_store.exists(DEFAULT_KEY_NAME) {
            key_store
                .delete(DEFAULT_KEY_NAME)
                .map_err(InitError::KeyStorage)?;
        }

        key_store
            .store(DEFAULT_KEY_NAME, &secret_key, passphrase)
            .map_err(InitError::KeyStorage)?;

        // 6. Create default config.toml
        write_default_config(&base_dir)?;

        Ok(eth_address_hex)
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Get the base directory for Sello files (~/.sello).
fn get_base_dir() -> Result<PathBuf, InitError> {
    dirs::home_dir()
        .map(|home| home.join(BASE_DIR_NAME))
        .ok_or(InitError::NoHomeDirectory)
}

/// Check if Sello is already initialized.
///
/// Returns true if both the config file and default key exist.
fn is_initialized(base_dir: &Path) -> bool {
    let config_path = base_dir.join(CONFIG_FILE_NAME);
    let keys_dir = base_dir.join(KEYS_DIR_NAME);
    let default_key_path = keys_dir.join(format!("{DEFAULT_KEY_NAME}.enc"));

    config_path.exists() && default_key_path.exists()
}

/// Create the directory structure for Sello.
fn create_directory_structure(base_dir: &Path) -> Result<(), InitError> {
    // Create base directory
    if !base_dir.exists() {
        fs::create_dir_all(base_dir).map_err(InitError::DirectoryCreation)?;
    }

    // Set base directory permissions to 0700
    #[cfg(unix)]
    {
        let mut perms = fs::metadata(base_dir)
            .map_err(InitError::DirectoryCreation)?
            .permissions();
        perms.set_mode(0o700);
        fs::set_permissions(base_dir, perms).map_err(InitError::DirectoryCreation)?;
    }

    // Create keys directory
    let keys_dir = base_dir.join(KEYS_DIR_NAME);
    if !keys_dir.exists() {
        fs::create_dir_all(&keys_dir).map_err(InitError::DirectoryCreation)?;
    }

    #[cfg(unix)]
    {
        let mut perms = fs::metadata(&keys_dir)
            .map_err(InitError::DirectoryCreation)?
            .permissions();
        perms.set_mode(0o700);
        fs::set_permissions(&keys_dir, perms).map_err(InitError::DirectoryCreation)?;
    }

    // Create logs directory
    let logs_dir = base_dir.join(LOGS_DIR_NAME);
    if !logs_dir.exists() {
        fs::create_dir_all(&logs_dir).map_err(InitError::DirectoryCreation)?;
    }

    #[cfg(unix)]
    {
        let mut perms = fs::metadata(&logs_dir)
            .map_err(InitError::DirectoryCreation)?
            .permissions();
        perms.set_mode(0o700);
        fs::set_permissions(&logs_dir, perms).map_err(InitError::DirectoryCreation)?;
    }

    Ok(())
}

/// Prompt for passphrase with confirmation.
///
/// Uses `rpassword` for secure hidden input.
fn prompt_passphrase() -> Result<String, InitError> {
    println!("Enter a passphrase to encrypt your key:");
    let passphrase = rpassword::read_password().map_err(|_| InitError::PassphraseCancelled)?;

    if passphrase.is_empty() {
        return Err(InitError::PassphraseCancelled);
    }

    if passphrase.len() < MIN_PASSPHRASE_LENGTH {
        return Err(InitError::PassphraseTooShort);
    }

    println!("Confirm your passphrase:");
    let confirmation = rpassword::read_password().map_err(|_| InitError::PassphraseCancelled)?;

    if passphrase != confirmation {
        return Err(InitError::PassphraseMismatch);
    }

    Ok(passphrase)
}

/// Validate a passphrase.
///
/// Checks that the passphrase meets minimum length requirements.
#[allow(dead_code, clippy::missing_const_for_fn)]
fn validate_passphrase(passphrase: &str) -> Result<(), InitError> {
    if passphrase.len() < MIN_PASSPHRASE_LENGTH {
        return Err(InitError::PassphraseTooShort);
    }
    Ok(())
}

/// Write the default configuration file.
fn write_default_config(base_dir: &Path) -> Result<(), InitError> {
    let config_path = base_dir.join(CONFIG_FILE_NAME);
    let default_toml = Config::default_toml();

    // Write to file
    let mut file = File::create(&config_path)?;
    file.write_all(default_toml.as_bytes())?;
    file.sync_all()?;

    // Set file permissions to 0600
    #[cfg(unix)]
    {
        let mut perms = fs::metadata(&config_path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&config_path, perms)?;
    }

    Ok(())
}

/// Print the success message with next steps.
fn print_success_message(eth_address: &str) {
    println!();
    println!("Sello initialized successfully!");
    println!();
    println!("Your Ethereum address: {eth_address}");
    println!();
    println!("Next steps:");
    println!("  1. Edit configuration: sello config edit");
    println!("  2. View status: sello status");
    println!("  3. Start server: sello serve");
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
    use tempfile::TempDir;

    /// Create a temporary directory for testing.
    fn create_test_dir() -> TempDir {
        TempDir::new().expect("failed to create temp dir")
    }

    // ------------------------------------------------------------------------
    // Directory Structure Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_create_directory_structure() {
        let temp_dir = create_test_dir();
        let base_dir = temp_dir.path().to_path_buf();

        create_directory_structure(&base_dir).expect("should create directories");

        // Check that directories exist
        assert!(base_dir.exists());
        assert!(base_dir.join(KEYS_DIR_NAME).exists());
        assert!(base_dir.join(LOGS_DIR_NAME).exists());
    }

    #[cfg(unix)]
    #[test]
    fn test_directory_permissions() {
        let temp_dir = create_test_dir();
        let base_dir = temp_dir.path().join("sello-test");

        create_directory_structure(&base_dir).expect("should create directories");

        // Check base directory permissions
        let base_perms = fs::metadata(&base_dir)
            .expect("should get metadata")
            .permissions()
            .mode();
        assert_eq!(base_perms & 0o777, 0o700);

        // Check keys directory permissions
        let keys_perms = fs::metadata(base_dir.join(KEYS_DIR_NAME))
            .expect("should get metadata")
            .permissions()
            .mode();
        assert_eq!(keys_perms & 0o777, 0o700);

        // Check logs directory permissions
        let logs_perms = fs::metadata(base_dir.join(LOGS_DIR_NAME))
            .expect("should get metadata")
            .permissions()
            .mode();
        assert_eq!(logs_perms & 0o777, 0o700);
    }

    // ------------------------------------------------------------------------
    // Initialization Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_is_initialized_false_when_empty() {
        let temp_dir = create_test_dir();
        let base_dir = temp_dir.path().to_path_buf();

        assert!(!is_initialized(&base_dir));
    }

    #[test]
    fn test_is_initialized_false_when_partial() {
        let temp_dir = create_test_dir();
        let base_dir = temp_dir.path().to_path_buf();

        // Create only config file, not the key
        fs::create_dir_all(&base_dir).expect("should create dir");
        fs::write(base_dir.join(CONFIG_FILE_NAME), "test").expect("should write config");

        assert!(!is_initialized(&base_dir));
    }

    #[test]
    fn test_is_initialized_true_when_complete() {
        let temp_dir = create_test_dir();
        let base_dir = temp_dir.path().to_path_buf();

        // Create config and key
        let keys_dir = base_dir.join(KEYS_DIR_NAME);
        fs::create_dir_all(&keys_dir).expect("should create dirs");
        fs::write(base_dir.join(CONFIG_FILE_NAME), "test").expect("should write config");
        fs::write(keys_dir.join("default.enc"), "key").expect("should write key");

        assert!(is_initialized(&base_dir));
    }

    // ------------------------------------------------------------------------
    // InitCommand Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_init_command_creates_structure() {
        let temp_dir = create_test_dir();
        let base_dir = temp_dir.path().join("sello-init-test");

        let cmd = InitCommand::new(false);
        let result = cmd.run_with_base_dir(base_dir.clone());

        assert!(result.is_ok());
        assert!(base_dir.exists());
        assert!(base_dir.join(KEYS_DIR_NAME).exists());
        assert!(base_dir.join(LOGS_DIR_NAME).exists());
        assert!(base_dir.join(CONFIG_FILE_NAME).exists());
        assert!(base_dir.join(KEYS_DIR_NAME).join("default.enc").exists());
    }

    #[test]
    fn test_init_command_returns_ethereum_address() {
        let temp_dir = create_test_dir();
        let base_dir = temp_dir.path().join("sello-addr-test");

        let cmd = InitCommand::new(false);
        let result = cmd.run_with_base_dir(base_dir);

        assert!(result.is_ok());
        let address = result.unwrap();
        assert!(address.starts_with("0x"));
        assert_eq!(address.len(), 42); // 0x + 40 hex chars
    }

    #[test]
    fn test_init_command_fails_if_already_initialized() {
        let temp_dir = create_test_dir();
        let base_dir = temp_dir.path().join("sello-already-init");

        let cmd = InitCommand::new(false);

        // First init should succeed
        let result1 = cmd.run_with_base_dir(base_dir.clone());
        assert!(result1.is_ok());

        // Second init without force should fail
        let result2 = cmd.run_with_base_dir(base_dir);
        assert!(matches!(result2, Err(InitError::AlreadyInitialized)));
    }

    #[test]
    fn test_init_command_force_overwrites() {
        let temp_dir = create_test_dir();
        let base_dir = temp_dir.path().join("sello-force-test");

        // First init
        let cmd1 = InitCommand::new(false);
        let result1 = cmd1.run_with_base_dir(base_dir.clone());
        assert!(result1.is_ok());
        let address1 = result1.unwrap();

        // Second init with force should succeed and generate new key
        let cmd2 = InitCommand::new(true);
        let result2 = cmd2.run_with_base_dir(base_dir);
        assert!(result2.is_ok());
        let address2 = result2.unwrap();

        // Addresses should be different (new key generated)
        assert_ne!(address1, address2);
    }

    // ------------------------------------------------------------------------
    // Config File Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_write_default_config() {
        let temp_dir = create_test_dir();
        let base_dir = temp_dir.path().to_path_buf();

        fs::create_dir_all(&base_dir).expect("should create dir");
        write_default_config(&base_dir).expect("should write config");

        let config_path = base_dir.join(CONFIG_FILE_NAME);
        assert!(config_path.exists());

        let content = fs::read_to_string(&config_path).expect("should read config");
        assert!(content.contains("[server]"));
        assert!(content.contains("[keys]"));
        assert!(content.contains("[policy]"));
    }

    #[cfg(unix)]
    #[test]
    fn test_config_file_permissions() {
        let temp_dir = create_test_dir();
        let base_dir = temp_dir.path().to_path_buf();

        fs::create_dir_all(&base_dir).expect("should create dir");
        write_default_config(&base_dir).expect("should write config");

        let config_path = base_dir.join(CONFIG_FILE_NAME);
        let perms = fs::metadata(&config_path)
            .expect("should get metadata")
            .permissions()
            .mode();
        assert_eq!(perms & 0o777, 0o600);
    }

    // ------------------------------------------------------------------------
    // Passphrase Validation Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_validate_passphrase_too_short() {
        let result = validate_passphrase("short");
        assert!(matches!(result, Err(InitError::PassphraseTooShort)));
    }

    #[test]
    fn test_validate_passphrase_min_length() {
        let result = validate_passphrase("12345678");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_passphrase_long() {
        let result = validate_passphrase("this-is-a-very-long-passphrase-for-testing");
        assert!(result.is_ok());
    }

    // ------------------------------------------------------------------------
    // Error Display Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_init_error_display() {
        assert_eq!(
            InitError::AlreadyInitialized.to_string(),
            "Sello is already initialized. Use --force to reinitialize."
        );

        assert_eq!(
            InitError::PassphraseMismatch.to_string(),
            "Passphrases do not match"
        );

        assert!(InitError::PassphraseTooShort
            .to_string()
            .contains("minimum"));

        assert_eq!(
            InitError::KeyGeneration("test error".to_string()).to_string(),
            "Failed to generate key: test error"
        );

        assert_eq!(
            InitError::NoHomeDirectory.to_string(),
            "Could not determine home directory"
        );
    }

    // ------------------------------------------------------------------------
    // Thread Safety Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_init_command_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<InitCommand>();
    }

    #[test]
    fn test_init_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<InitError>();
    }

    // ------------------------------------------------------------------------
    // Key Generation Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_key_is_stored_and_loadable() {
        let temp_dir = create_test_dir();
        let base_dir = temp_dir.path().join("sello-key-test");

        let cmd = InitCommand::new(false);
        cmd.run_with_base_dir(base_dir.clone())
            .expect("init should succeed");

        // Try to load the key with the test passphrase
        let keys_dir = base_dir.join(KEYS_DIR_NAME);
        let key_store = FileKeyStore::with_path(keys_dir).expect("should create key store");

        let loaded_key = key_store.load(DEFAULT_KEY_NAME, "test-passphrase-123");
        assert!(loaded_key.is_ok());
    }

    #[test]
    fn test_key_cannot_be_loaded_with_wrong_passphrase() {
        let temp_dir = create_test_dir();
        let base_dir = temp_dir.path().join("sello-wrong-pass-test");

        let cmd = InitCommand::new(false);
        cmd.run_with_base_dir(base_dir.clone())
            .expect("init should succeed");

        // Try to load with wrong passphrase
        let keys_dir = base_dir.join(KEYS_DIR_NAME);
        let key_store = FileKeyStore::with_path(keys_dir).expect("should create key store");

        let loaded_key = key_store.load(DEFAULT_KEY_NAME, "wrong-passphrase");
        assert!(loaded_key.is_err());
    }

    // ------------------------------------------------------------------------
    // Idempotency Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_directory_creation_is_idempotent() {
        let temp_dir = create_test_dir();
        let base_dir = temp_dir.path().join("sello-idempotent-test");

        // Create directories twice
        create_directory_structure(&base_dir).expect("first creation should succeed");
        create_directory_structure(&base_dir).expect("second creation should succeed");

        // Everything should still be in place
        assert!(base_dir.exists());
        assert!(base_dir.join(KEYS_DIR_NAME).exists());
        assert!(base_dir.join(LOGS_DIR_NAME).exists());
    }
}
