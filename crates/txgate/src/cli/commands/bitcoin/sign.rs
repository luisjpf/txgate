//! # Bitcoin Sign Command
//!
//! Implementation of the `txgate bitcoin sign` command that signs
//! Bitcoin transactions using the default signing key.
//!
//! ## Usage
//!
//! ```no_run
//! use txgate::cli::commands::bitcoin::SignCommand;
//! use txgate::cli::args::OutputFormat;
//!
//! let cmd = SignCommand::new("0x0100000001...", OutputFormat::Hex);
//! match cmd.run() {
//!     Ok(()) => println!("Transaction signed successfully"),
//!     Err(e) => eprintln!("Error: {}", e),
//! }
//! ```
//!
//! ## Output Formats
//!
//! ### Hex (default)
//!
//! ```text
//! 0x1234567890abcdef...
//! ```
//!
//! ### JSON
//!
//! ```json
//! {
//!   "transaction_hash": "0x...",
//!   "signature": "0x...",
//!   "signed_transaction": "0x...",
//!   "signer": "bc1q..."
//! }
//! ```
//!
//! ## Exit Codes
//!
//! - 0: Success
//! - 1: Policy denied
//! - 2: Other error

use std::io;
use std::path::{Path, PathBuf};

use txgate_chain::bitcoin::BitcoinParser;
use txgate_chain::Chain;
use txgate_core::config_loader::ConfigLoader;
use txgate_core::error::StoreError;
use txgate_core::types::{ParsedTx, PolicyResult};
use txgate_crypto::keypair::Secp256k1KeyPair;
use txgate_crypto::signer::{Chain as SignerChain, Secp256k1Signer, Signer};
use txgate_crypto::store::{FileKeyStore, KeyStore};
use txgate_policy::engine::{DefaultPolicyEngine, PolicyEngine};

use crate::cli::args::OutputFormat;
use crate::cli::commands::exit_codes::{EXIT_ERROR, EXIT_POLICY_DENIED};

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
// SignCommandError
// ============================================================================

/// Errors that can occur when signing a Bitcoin transaction.
#[derive(Debug, thiserror::Error)]
pub enum SignCommandError {
    /// `TxGate` is not initialized.
    #[error("TxGate is not initialized. Run 'txgate init' first.")]
    NotInitialized,

    /// Default key not found.
    #[error("Default key not found. Run 'txgate init' to create one.")]
    KeyNotFound,

    /// Invalid passphrase (decryption failed).
    #[error("Invalid passphrase")]
    InvalidPassphrase,

    /// Invalid transaction data.
    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),

    /// Policy denied the transaction.
    #[error("Policy denied: {rule} - {reason}")]
    PolicyDenied {
        /// The rule that denied the transaction.
        rule: String,
        /// The reason for denial.
        reason: String,
    },

    /// Signing failed.
    #[error("Signing failed: {0}")]
    SigningFailed(String),

    /// I/O error occurred.
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// Passphrase input was cancelled.
    #[error("Passphrase input cancelled")]
    Cancelled,

    /// Passphrase input failed.
    #[error("Failed to read passphrase: {0}")]
    PassphraseInputFailed(String),

    /// Home directory could not be determined.
    #[error("Could not determine home directory")]
    NoHomeDirectory,

    /// Configuration error.
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// Policy engine error.
    #[error("Policy error: {0}")]
    PolicyError(String),
}

impl SignCommandError {
    /// Returns the appropriate exit code for this error.
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        match self {
            Self::PolicyDenied { .. } => EXIT_POLICY_DENIED,
            _ => EXIT_ERROR,
        }
    }
}

impl From<StoreError> for SignCommandError {
    fn from(err: StoreError) -> Self {
        match err {
            StoreError::KeyNotFound { .. } => Self::KeyNotFound,
            StoreError::DecryptionFailed => Self::InvalidPassphrase,
            StoreError::IoError(e) => Self::Io(e),
            StoreError::EncryptionFailed => {
                Self::SigningFailed("Key encryption failed".to_string())
            }
            StoreError::KeyExists { name } => {
                Self::SigningFailed(format!("Key already exists: {name}"))
            }
            StoreError::InvalidFormat => Self::SigningFailed("Invalid key file format".to_string()),
            StoreError::PermissionDenied => {
                Self::SigningFailed("Permission denied accessing key file".to_string())
            }
        }
    }
}

// ============================================================================
// SignCommand
// ============================================================================

/// The `txgate bitcoin sign` command handler.
///
/// This command signs a Bitcoin transaction using the default signing key,
/// after checking that the transaction passes policy rules.
///
/// # Example
///
/// ```no_run
/// use txgate::cli::commands::bitcoin::SignCommand;
/// use txgate::cli::args::OutputFormat;
///
/// let cmd = SignCommand::new("0x0100000001...", OutputFormat::Hex);
/// match cmd.run() {
///     Ok(()) => println!("Success"),
///     Err(e) => {
///         eprintln!("Error: {}", e);
///         std::process::exit(e.exit_code());
///     }
/// }
/// ```
#[derive(Debug, Clone)]
pub struct SignCommand {
    /// The hex-encoded transaction data.
    pub transaction: String,
    /// The output format.
    pub format: OutputFormat,
}

impl SignCommand {
    /// Create a new `SignCommand`.
    #[must_use]
    pub fn new(transaction: impl Into<String>, format: OutputFormat) -> Self {
        Self {
            transaction: transaction.into(),
            format,
        }
    }

    /// Run the sign command.
    ///
    /// This method:
    /// 1. Decodes the hex transaction input
    /// 2. Loads the configuration
    /// 3. Prompts for the passphrase
    /// 4. Loads and decrypts the default key
    /// 5. Parses the transaction
    /// 6. Checks the policy
    /// 7. Signs the transaction if policy allows
    /// 8. Outputs the signature
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `TxGate` is not initialized
    /// - The transaction data is invalid hex
    /// - The default key does not exist
    /// - The passphrase input fails or is cancelled
    /// - The passphrase is incorrect
    /// - Policy denies the transaction
    /// - Signing fails
    pub fn run(&self) -> Result<(), SignCommandError> {
        let base_dir = get_base_dir()?;
        self.run_with_base_dir(&base_dir)
    }

    /// Run the sign command with a custom base directory.
    ///
    /// This is primarily used for testing to avoid modifying the user's
    /// actual home directory.
    ///
    /// # Errors
    ///
    /// Same as [`run`](Self::run).
    pub fn run_with_base_dir(&self, base_dir: &Path) -> Result<(), SignCommandError> {
        // 1. Check if initialized
        if !is_initialized(base_dir) {
            return Err(SignCommandError::NotInitialized);
        }

        // 2. Decode hex input
        let tx_bytes = decode_hex_input(&self.transaction)?;

        // 3. Check if default key exists
        let key_path = base_dir
            .join(KEYS_DIR_NAME)
            .join(format!("{DEFAULT_KEY_NAME}.enc"));
        if !key_path.exists() {
            return Err(SignCommandError::KeyNotFound);
        }

        // 4. Load configuration
        let config_loader = ConfigLoader::with_base_dir(base_dir.to_path_buf());
        let config = config_loader
            .load()
            .map_err(|e| SignCommandError::ConfigError(e.to_string()))?;

        // 5. Prompt for passphrase
        let passphrase = read_passphrase_for_sign()?;

        // 6. Load and decrypt key
        let keys_dir = base_dir.join(KEYS_DIR_NAME);
        let store = FileKeyStore::with_path(keys_dir)?;
        let secret_key = store.load(DEFAULT_KEY_NAME, &passphrase)?;

        // 7. Create keypair and signer
        let keypair = Secp256k1KeyPair::from_secret_key(&secret_key)
            .map_err(|e| SignCommandError::SigningFailed(e.to_string()))?;

        let signer = Secp256k1Signer::new(keypair);
        let signer_address = signer
            .address(SignerChain::Bitcoin)
            .map_err(|e| SignCommandError::SigningFailed(e.to_string()))?;

        // 8. Parse the transaction
        let parser = BitcoinParser::mainnet();
        let parsed_tx = parser
            .parse(&tx_bytes)
            .map_err(|e| SignCommandError::InvalidTransaction(e.to_string()))?;

        // 9. Create policy engine and check policy
        let policy_engine = DefaultPolicyEngine::new(config.policy)
            .map_err(|e| SignCommandError::PolicyError(e.to_string()))?;

        let policy_result = policy_engine
            .check(&parsed_tx)
            .map_err(|e| SignCommandError::PolicyError(e.to_string()))?;

        // 10. Handle policy result
        // Note: PolicyResult is marked #[non_exhaustive], so we need a catch-all
        match policy_result {
            PolicyResult::Allowed => {
                // Continue with signing
            }
            PolicyResult::Denied { rule, reason } => {
                return Err(SignCommandError::PolicyDenied { rule, reason });
            }
            _ => {
                return Err(SignCommandError::PolicyError(format!(
                    "Unexpected policy result: {policy_result:?}"
                )));
            }
        }

        // 11. Sign the transaction hash
        let signature = signer
            .sign(&parsed_tx.hash)
            .map_err(|e| SignCommandError::SigningFailed(e.to_string()))?;

        // 12. Output the result
        match self.format {
            OutputFormat::Hex => {
                let output = format_hex_output(&signature);
                println!("{output}");
            }
            OutputFormat::Json => {
                let output =
                    format_json_output(&parsed_tx, &signature, &tx_bytes, &signer_address)?;
                println!("{output}");
            }
        }

        Ok(())
    }

    /// Run the sign command with a provided passphrase (for testing).
    ///
    /// # Errors
    ///
    /// Same as [`run`](Self::run), except passphrase input errors.
    #[cfg(test)]
    pub fn run_with_passphrase(
        &self,
        base_dir: &Path,
        passphrase: &str,
    ) -> Result<SignOutput, SignCommandError> {
        // 1. Check if initialized
        if !is_initialized(base_dir) {
            return Err(SignCommandError::NotInitialized);
        }

        // 2. Decode hex input
        let tx_bytes = decode_hex_input(&self.transaction)?;

        // 3. Check if default key exists
        let key_path = base_dir
            .join(KEYS_DIR_NAME)
            .join(format!("{DEFAULT_KEY_NAME}.enc"));
        if !key_path.exists() {
            return Err(SignCommandError::KeyNotFound);
        }

        // 4. Load configuration
        let config_loader = ConfigLoader::with_base_dir(base_dir.to_path_buf());
        let config = config_loader
            .load()
            .map_err(|e| SignCommandError::ConfigError(e.to_string()))?;

        // 5. Load and decrypt key
        let keys_dir = base_dir.join(KEYS_DIR_NAME);
        let store = FileKeyStore::with_path(keys_dir)?;
        let secret_key = store.load(DEFAULT_KEY_NAME, passphrase)?;

        // 6. Create keypair and signer
        let keypair = Secp256k1KeyPair::from_secret_key(&secret_key)
            .map_err(|e| SignCommandError::SigningFailed(e.to_string()))?;

        let signer = Secp256k1Signer::new(keypair);
        let signer_address = signer
            .address(SignerChain::Bitcoin)
            .map_err(|e| SignCommandError::SigningFailed(e.to_string()))?;

        // 7. Parse the transaction
        let parser = BitcoinParser::mainnet();
        let parsed_tx = parser
            .parse(&tx_bytes)
            .map_err(|e| SignCommandError::InvalidTransaction(e.to_string()))?;

        // 8. Create policy engine and check policy
        let policy_config = config.policy;
        let policy_engine = DefaultPolicyEngine::new(policy_config)
            .map_err(|e| SignCommandError::PolicyError(e.to_string()))?;

        let policy_result = policy_engine
            .check(&parsed_tx)
            .map_err(|e| SignCommandError::PolicyError(e.to_string()))?;

        // 9. Handle policy result
        // Note: PolicyResult is marked #[non_exhaustive], so we need a catch-all
        match policy_result {
            PolicyResult::Allowed => {
                // Continue with signing
            }
            PolicyResult::Denied { rule, reason } => {
                return Err(SignCommandError::PolicyDenied { rule, reason });
            }
            _ => {
                return Err(SignCommandError::PolicyError(format!(
                    "Unexpected policy result: {policy_result:?}"
                )));
            }
        }

        // 10. Sign the transaction hash
        let signature = signer
            .sign(&parsed_tx.hash)
            .map_err(|e| SignCommandError::SigningFailed(e.to_string()))?;

        Ok(SignOutput {
            transaction_hash: format_hex_output(&parsed_tx.hash),
            signature: format_hex_output(&signature),
            signed_transaction: format_hex_output(&tx_bytes),
            signer: signer_address,
        })
    }
}

// ============================================================================
// SignOutput
// ============================================================================

/// Output from a successful signing operation.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SignOutput {
    /// The transaction hash.
    pub transaction_hash: String,
    /// The signature in hex format.
    pub signature: String,
    /// The signed transaction in hex format.
    pub signed_transaction: String,
    /// The signer address.
    pub signer: String,
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Get the base directory for `TxGate` files (~/.txgate).
fn get_base_dir() -> Result<PathBuf, SignCommandError> {
    dirs::home_dir()
        .map(|home| home.join(BASE_DIR_NAME))
        .ok_or(SignCommandError::NoHomeDirectory)
}

/// Check if `TxGate` is initialized.
///
/// Returns true if the config file exists.
fn is_initialized(base_dir: &Path) -> bool {
    let config_path = base_dir.join(CONFIG_FILE_NAME);
    config_path.exists()
}

/// Read passphrase (from env var or interactive prompt).
fn read_passphrase_for_sign() -> Result<String, SignCommandError> {
    crate::cli::passphrase::read_passphrase().map_err(|e| match e {
        crate::cli::passphrase::PassphraseError::Cancelled => SignCommandError::Cancelled,
        other => SignCommandError::PassphraseInputFailed(other.to_string()),
    })
}

/// Decode hex-encoded input.
///
/// Accepts input with or without `0x` prefix.
///
/// # Errors
///
/// Returns an error if the input is not valid hex.
pub fn decode_hex_input(input: &str) -> Result<Vec<u8>, SignCommandError> {
    let hex_str = input.strip_prefix("0x").unwrap_or(input);

    if hex_str.is_empty() {
        return Err(SignCommandError::InvalidTransaction(
            "empty transaction data".to_string(),
        ));
    }

    hex::decode(hex_str).map_err(|e| SignCommandError::InvalidTransaction(e.to_string()))
}

/// Format bytes as hex output with `0x` prefix.
#[must_use]
pub fn format_hex_output(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// Format JSON output for a signed transaction.
fn format_json_output(
    parsed_tx: &ParsedTx,
    signature: &[u8],
    tx_bytes: &[u8],
    signer_address: &str,
) -> Result<String, SignCommandError> {
    let output = SignOutput {
        transaction_hash: format_hex_output(&parsed_tx.hash),
        signature: format_hex_output(signature),
        signed_transaction: format_hex_output(tx_bytes),
        signer: signer_address.to_string(),
    };

    serde_json::to_string_pretty(&output)
        .map_err(|e| SignCommandError::SigningFailed(format!("JSON serialization failed: {e}")))
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
    use txgate_core::types::ParsedTx;
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

        // Create config file with default policy
        let config_content = r#"
[server]
socket_path = "~/.txgate/txgate.sock"
timeout_secs = 30

[keys]
directory = "~/.txgate/keys"
default_key = "default"

[policy]
whitelist_enabled = false
whitelist = []
blacklist = []
"#;
        fs::write(base_dir.join(CONFIG_FILE_NAME), config_content).expect("failed to write config");

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
    fn test_sign_command_error_display() {
        assert_eq!(
            SignCommandError::NotInitialized.to_string(),
            "TxGate is not initialized. Run 'txgate init' first."
        );

        assert_eq!(
            SignCommandError::KeyNotFound.to_string(),
            "Default key not found. Run 'txgate init' to create one."
        );

        assert_eq!(
            SignCommandError::InvalidPassphrase.to_string(),
            "Invalid passphrase"
        );

        assert_eq!(
            SignCommandError::InvalidTransaction("bad hex".to_string()).to_string(),
            "Invalid transaction: bad hex"
        );

        assert_eq!(
            SignCommandError::PolicyDenied {
                rule: "blacklist".to_string(),
                reason: "address is blacklisted".to_string()
            }
            .to_string(),
            "Policy denied: blacklist - address is blacklisted"
        );

        assert_eq!(
            SignCommandError::SigningFailed("key error".to_string()).to_string(),
            "Signing failed: key error"
        );

        assert_eq!(
            SignCommandError::Cancelled.to_string(),
            "Passphrase input cancelled"
        );

        assert_eq!(
            SignCommandError::NoHomeDirectory.to_string(),
            "Could not determine home directory"
        );
    }

    #[test]
    fn test_sign_command_error_exit_codes() {
        assert_eq!(SignCommandError::NotInitialized.exit_code(), EXIT_ERROR);
        assert_eq!(SignCommandError::KeyNotFound.exit_code(), EXIT_ERROR);
        assert_eq!(SignCommandError::InvalidPassphrase.exit_code(), EXIT_ERROR);
        assert_eq!(
            SignCommandError::InvalidTransaction("test".to_string()).exit_code(),
            EXIT_ERROR
        );
        assert_eq!(
            SignCommandError::PolicyDenied {
                rule: "test".to_string(),
                reason: "test".to_string()
            }
            .exit_code(),
            EXIT_POLICY_DENIED
        );
        assert_eq!(
            SignCommandError::SigningFailed("test".to_string()).exit_code(),
            EXIT_ERROR
        );
        assert_eq!(SignCommandError::Cancelled.exit_code(), EXIT_ERROR);
        assert_eq!(SignCommandError::NoHomeDirectory.exit_code(), EXIT_ERROR);
    }

    #[test]
    fn test_sign_command_error_from_store_error() {
        let store_err = StoreError::KeyNotFound {
            name: "default".to_string(),
        };
        let sign_err: SignCommandError = store_err.into();
        assert!(matches!(sign_err, SignCommandError::KeyNotFound));

        let store_err = StoreError::DecryptionFailed;
        let sign_err: SignCommandError = store_err.into();
        assert!(matches!(sign_err, SignCommandError::InvalidPassphrase));

        let io_err = std::io::Error::other("test error");
        let store_err = StoreError::IoError(io_err);
        let sign_err: SignCommandError = store_err.into();
        assert!(matches!(sign_err, SignCommandError::Io(_)));

        let store_err = StoreError::InvalidFormat;
        let sign_err: SignCommandError = store_err.into();
        assert!(matches!(sign_err, SignCommandError::SigningFailed(_)));

        let store_err = StoreError::EncryptionFailed;
        let sign_err: SignCommandError = store_err.into();
        assert!(matches!(sign_err, SignCommandError::SigningFailed(_)));

        let store_err = StoreError::KeyExists {
            name: "test".to_string(),
        };
        let sign_err: SignCommandError = store_err.into();
        assert!(matches!(sign_err, SignCommandError::SigningFailed(_)));

        let store_err = StoreError::PermissionDenied;
        let sign_err: SignCommandError = store_err.into();
        assert!(matches!(sign_err, SignCommandError::SigningFailed(_)));
    }

    #[test]
    fn test_passphrase_input_failed_error_display() {
        let err = SignCommandError::PassphraseInputFailed("test error".to_string());
        assert_eq!(err.to_string(), "Failed to read passphrase: test error");
        assert_eq!(err.exit_code(), EXIT_ERROR);
    }

    #[test]
    fn test_policy_error_display() {
        let err = SignCommandError::PolicyError("test policy error".to_string());
        assert_eq!(err.to_string(), "Policy error: test policy error");
        assert_eq!(err.exit_code(), EXIT_ERROR);
    }

    #[test]
    fn test_config_error_display() {
        let err = SignCommandError::ConfigError("config parse error".to_string());
        assert_eq!(err.to_string(), "Configuration error: config parse error");
        assert_eq!(err.exit_code(), EXIT_ERROR);
    }

    #[test]
    fn test_io_error_display() {
        let io_err = io::Error::other("test io error");
        let err: SignCommandError = io_err.into();
        assert!(err.to_string().contains("IO error"));
        assert_eq!(err.exit_code(), EXIT_ERROR);
    }

    #[test]
    fn test_format_json_output() {
        use std::collections::HashMap;
        let parsed_tx = ParsedTx {
            chain: "bitcoin".to_string(),
            hash: [0x12; 32],
            tx_type: txgate_core::types::TxType::Transfer,
            recipient: Some("bc1qtest".to_string()),
            amount: None,
            token: None,
            token_address: None,
            nonce: None,
            chain_id: None,
            metadata: HashMap::new(),
        };
        let signature = vec![0xab, 0xcd];
        let tx_bytes = vec![0xde, 0xad];
        let signer_address = "bc1qsigner";

        let result = format_json_output(&parsed_tx, &signature, &tx_bytes, signer_address);
        assert!(result.is_ok());
        let json = result.unwrap();
        assert!(json.contains("transaction_hash"));
        assert!(json.contains("0xabcd"));
        assert!(json.contains("bc1qsigner"));
    }

    #[test]
    fn test_sign_output_debug() {
        let output = SignOutput {
            transaction_hash: "0x1234".to_string(),
            signature: "0x5678".to_string(),
            signed_transaction: "0x9abc".to_string(),
            signer: "bc1qtest".to_string(),
        };
        let debug_str = format!("{:?}", output);
        assert!(debug_str.contains("SignOutput"));
        assert!(debug_str.contains("transaction_hash"));
    }

    #[test]
    fn test_sign_output_clone() {
        let output = SignOutput {
            transaction_hash: "0x1234".to_string(),
            signature: "0x5678".to_string(),
            signed_transaction: "0x9abc".to_string(),
            signer: "bc1qtest".to_string(),
        };
        let cloned = output.clone();
        assert_eq!(cloned.transaction_hash, output.transaction_hash);
        assert_eq!(cloned.signature, output.signature);
    }

    // ------------------------------------------------------------------------
    // Hex Decoding Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_decode_hex_input_with_prefix() {
        let result = decode_hex_input("0xdeadbeef");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_decode_hex_input_without_prefix() {
        let result = decode_hex_input("deadbeef");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_decode_hex_input_empty() {
        let result = decode_hex_input("");
        assert!(matches!(
            result,
            Err(SignCommandError::InvalidTransaction(_))
        ));
    }

    #[test]
    fn test_decode_hex_input_empty_with_prefix() {
        let result = decode_hex_input("0x");
        assert!(matches!(
            result,
            Err(SignCommandError::InvalidTransaction(_))
        ));
    }

    #[test]
    fn test_decode_hex_input_invalid() {
        let result = decode_hex_input("0xgg");
        assert!(matches!(
            result,
            Err(SignCommandError::InvalidTransaction(_))
        ));
    }

    // ------------------------------------------------------------------------
    // Output Formatting Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_format_hex_output() {
        let bytes = vec![0xde, 0xad, 0xbe, 0xef];
        assert_eq!(format_hex_output(&bytes), "0xdeadbeef");
    }

    #[test]
    fn test_format_hex_output_empty() {
        let bytes: Vec<u8> = vec![];
        assert_eq!(format_hex_output(&bytes), "0x");
    }

    // ------------------------------------------------------------------------
    // Command Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_sign_command_not_initialized() {
        let temp_dir = create_test_dir();
        let base_dir = temp_dir.path().to_path_buf();

        let cmd = SignCommand::new("0xdeadbeef", OutputFormat::Hex);
        let result = cmd.run_with_base_dir(&base_dir);

        assert!(matches!(result, Err(SignCommandError::NotInitialized)));
    }

    #[test]
    fn test_sign_command_key_not_found() {
        let temp_dir = create_test_dir();
        let base_dir = temp_dir.path().to_path_buf();

        // Create config but no key
        fs::create_dir_all(&base_dir).expect("failed to create dir");
        let config_content = r#"
[server]
socket_path = "~/.txgate/txgate.sock"
timeout_secs = 30

[keys]
directory = "~/.txgate/keys"
default_key = "default"

[policy]
whitelist_enabled = false
"#;
        fs::write(base_dir.join(CONFIG_FILE_NAME), config_content).expect("failed to write config");

        let cmd = SignCommand::new("0xdeadbeef", OutputFormat::Hex);
        let result = cmd.run_with_base_dir(&base_dir);

        assert!(matches!(result, Err(SignCommandError::KeyNotFound)));
    }

    #[test]
    fn test_sign_command_invalid_hex() {
        let temp_dir = create_test_dir();
        let (base_dir, passphrase) = setup_initialized_env(&temp_dir);

        let cmd = SignCommand::new("0xnotvalidhex", OutputFormat::Hex);
        let result = cmd.run_with_passphrase(&base_dir, &passphrase);

        assert!(matches!(
            result,
            Err(SignCommandError::InvalidTransaction(_))
        ));
    }

    #[test]
    fn test_sign_command_wrong_passphrase() {
        let temp_dir = create_test_dir();
        let (base_dir, _passphrase) = setup_initialized_env(&temp_dir);

        let cmd = SignCommand::new("0xdeadbeef", OutputFormat::Hex);
        let result = cmd.run_with_passphrase(&base_dir, "wrong-passphrase");

        assert!(matches!(result, Err(SignCommandError::InvalidPassphrase)));
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

    // ------------------------------------------------------------------------
    // Thread Safety Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_sign_command_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SignCommand>();
    }

    #[test]
    fn test_sign_command_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SignCommandError>();
    }

    // ------------------------------------------------------------------------
    // SignOutput Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_sign_output_serialization() {
        let output = SignOutput {
            transaction_hash: "0x1234".to_string(),
            signature: "0x5678".to_string(),
            signed_transaction: "0x9abc".to_string(),
            signer: "bc1qtest".to_string(),
        };

        let json = serde_json::to_string(&output).expect("serialization should succeed");
        assert!(json.contains("transaction_hash"));
        assert!(json.contains("signature"));
        assert!(json.contains("signed_transaction"));
        assert!(json.contains("signer"));
    }

    #[test]
    fn test_sign_command_debug() {
        let cmd = SignCommand::new("0x1234", OutputFormat::Hex);
        let debug_str = format!("{:?}", cmd);
        assert!(debug_str.contains("SignCommand"));
        assert!(debug_str.contains("transaction"));
    }

    #[test]
    fn test_sign_command_clone() {
        let cmd = SignCommand::new("0x1234", OutputFormat::Json);
        let cloned = cmd.clone();
        assert_eq!(cmd.transaction, cloned.transaction);
        assert!(matches!(cloned.format, OutputFormat::Json));
    }

    // ------------------------------------------------------------------------
    // Config Error Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_sign_command_invalid_config() {
        let temp_dir = create_test_dir();
        let base_dir = temp_dir.path().to_path_buf();
        let keys_dir = base_dir.join(KEYS_DIR_NAME);

        // Create directory structure
        fs::create_dir_all(&keys_dir).expect("failed to create keys dir");

        // Create INVALID config file (missing required fields)
        let invalid_config = "this is not valid toml [[[";
        fs::write(base_dir.join(CONFIG_FILE_NAME), invalid_config).expect("failed to write config");

        // Store a key
        let secret_key = SecretKey::generate();
        let store = FileKeyStore::with_path(keys_dir).expect("failed to create key store");
        store
            .store(DEFAULT_KEY_NAME, &secret_key, "test-passphrase")
            .expect("failed to store key");

        let cmd = SignCommand::new("0xdeadbeef", OutputFormat::Hex);
        let result = cmd.run_with_base_dir(&base_dir);

        // Should fail with ConfigError because config is invalid TOML
        assert!(matches!(result, Err(SignCommandError::ConfigError(_))));
    }

    // ------------------------------------------------------------------------
    // Invalid Transaction Parsing Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_sign_command_invalid_bitcoin_transaction() {
        let temp_dir = create_test_dir();
        let (base_dir, passphrase) = setup_initialized_env(&temp_dir);

        // Use valid hex that decodes but isn't a valid Bitcoin transaction
        // (just 32 random bytes)
        let invalid_tx_hex = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

        let cmd = SignCommand::new(invalid_tx_hex, OutputFormat::Hex);
        let result = cmd.run_with_passphrase(&base_dir, &passphrase);

        // Should fail with InvalidTransaction because the bytes aren't a valid Bitcoin tx
        assert!(
            matches!(result, Err(SignCommandError::InvalidTransaction(_))),
            "Expected InvalidTransaction, got: {:?}",
            result
        );
    }

    // ------------------------------------------------------------------------
    // JSON Output Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_sign_command_json_output_format() {
        let temp_dir = create_test_dir();
        let (base_dir, passphrase) = setup_initialized_env(&temp_dir);

        // Use a valid Bitcoin transaction hex
        let valid_tx_hex = "0100000001000000000000000000000000000000000000000000000000\
            0000000000000000ffffffff0704ffff001d0104ffffffff0100f2052a\
            0100000043410496b538e853519c726a2c91e61ec11600ae1390813a62\
            7c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166\
            bf621e73a82cbf2342c858eeac00000000";

        let cmd = SignCommand::new(valid_tx_hex, OutputFormat::Json);
        let result = cmd.run_with_passphrase(&base_dir, &passphrase);

        // Should succeed with JSON output
        assert!(result.is_ok(), "Expected success, got: {:?}", result.err());

        let output = result.unwrap();
        assert!(!output.signature.is_empty());
        assert!(!output.transaction_hash.is_empty());
        assert!(!output.signer.is_empty());
        assert!(output.signer.starts_with("bc1")); // Bitcoin bech32 address
    }

    #[test]
    fn test_sign_command_hex_output_format() {
        let temp_dir = create_test_dir();
        let (base_dir, passphrase) = setup_initialized_env(&temp_dir);

        // Use a valid Bitcoin transaction hex
        let valid_tx_hex = "0100000001000000000000000000000000000000000000000000000000\
            0000000000000000ffffffff0704ffff001d0104ffffffff0100f2052a\
            0100000043410496b538e853519c726a2c91e61ec11600ae1390813a62\
            7c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166\
            bf621e73a82cbf2342c858eeac00000000";

        let cmd = SignCommand::new(valid_tx_hex, OutputFormat::Hex);
        let result = cmd.run_with_passphrase(&base_dir, &passphrase);

        // Should succeed with hex output
        assert!(result.is_ok(), "Expected success, got: {:?}", result.err());

        let output = result.unwrap();
        assert!(output.signature.starts_with("0x"));
        assert!(output.transaction_hash.starts_with("0x"));
    }

    // ------------------------------------------------------------------------
    // End-to-end Flow Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_sign_command_full_signing_flow() {
        let temp_dir = create_test_dir();
        let (base_dir, passphrase) = setup_initialized_env(&temp_dir);

        // Use a valid Bitcoin transaction hex
        let valid_tx_hex = "0100000001000000000000000000000000000000000000000000000000\
            0000000000000000ffffffff0704ffff001d0104ffffffff0100f2052a\
            0100000043410496b538e853519c726a2c91e61ec11600ae1390813a62\
            7c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166\
            bf621e73a82cbf2342c858eeac00000000";

        let cmd = SignCommand::new(valid_tx_hex, OutputFormat::Json);
        let result = cmd.run_with_passphrase(&base_dir, &passphrase);

        assert!(result.is_ok(), "Failed: {:?}", result.err());

        let output = result.unwrap();

        // Verify output structure
        assert!(output.transaction_hash.starts_with("0x"));
        assert!(output.signature.starts_with("0x"));
        assert!(output.signed_transaction.starts_with("0x"));
        assert!(output.signer.starts_with("bc1")); // Bitcoin address
    }
}
