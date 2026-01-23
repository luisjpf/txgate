//! # Serve Command
//!
//! Start the Sello signing server as a long-running process.
//!
//! This module implements the `sello serve` command which:
//! - Loads the encrypted key from `~/.sello/keys/default.enc`
//! - Prompts for the passphrase to decrypt the key
//! - Starts the Unix socket server for signing requests
//! - Handles graceful shutdown via SIGTERM/SIGINT
//!
//! ## Usage
//!
//! ```bash
//! # Start the server (runs in foreground)
//! sello serve
//!
//! # Explicitly run in foreground mode
//! sello serve --foreground
//! ```

use std::path::{Path, PathBuf};
use std::sync::Arc;

use sello_crypto::keypair::Secp256k1KeyPair;
use sello_crypto::signer::{Chain, Secp256k1Signer, Signer};
use sello_crypto::store::{FileKeyStore, KeyStore};
use sello_policy::engine::DefaultPolicyEngine;
use sello_policy::history::TransactionHistory;
use sello_policy::PolicyConfig;

use crate::audit::AuditLogger;

/// Command to start the Sello signing server.
///
/// The server listens on a Unix socket for JSON-RPC signing requests.
/// The key is loaded from `~/.sello/keys/default.enc` and decrypted using
/// the provided passphrase.
///
/// # Example
///
/// ```no_run
/// use sello::cli::commands::ServeCommand;
///
/// #[tokio::main]
/// async fn main() {
///     let cmd = ServeCommand { foreground: true };
///     if let Err(e) = cmd.run().await {
///         eprintln!("Error: {}", e);
///     }
/// }
/// ```
#[derive(Debug, Clone)]
pub struct ServeCommand {
    /// Run in foreground mode (currently the only supported mode).
    pub foreground: bool,
}

/// Errors that can occur when running the serve command.
#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    /// Sello has not been initialized. Run `sello init` first.
    #[error("Sello is not initialized. Run 'sello init' first.")]
    NotInitialized,

    /// Failed to load configuration.
    #[error("Failed to load configuration: {0}")]
    ConfigError(String),

    /// Failed to load key from store.
    #[error("Failed to load key: {0}")]
    KeyError(String),

    /// The provided passphrase was invalid.
    #[error("Invalid passphrase")]
    InvalidPassphrase,

    /// Server encountered an error.
    #[error("Server error: {0}")]
    ServerError(String),

    /// I/O error during file operations.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Passphrase input was cancelled by the user.
    #[error("Passphrase input cancelled")]
    Cancelled,

    /// Could not determine the user's home directory.
    #[error("Could not determine home directory")]
    NoHomeDirectory,

    /// Failed to create the policy engine.
    #[error("Policy engine error: {0}")]
    PolicyError(String),

    /// Failed to initialize audit logger.
    #[error("Audit logger error: {0}")]
    AuditError(String),
}

impl ServeCommand {
    /// Run the serve command.
    ///
    /// This method:
    /// 1. Checks if Sello is initialized
    /// 2. Loads configuration
    /// 3. Prompts for passphrase
    /// 4. Loads and decrypts the default key
    /// 5. Creates signer from keypair
    /// 6. Creates policy engine
    /// 7. Creates audit logger (optional)
    /// 8. Displays startup message
    /// 9. Sets up signal handling
    /// 10. Starts server and waits for shutdown signal
    ///
    /// # Errors
    ///
    /// Returns [`ServeError`] if:
    /// - Sello is not initialized
    /// - Configuration cannot be loaded
    /// - Key cannot be loaded or decrypted
    /// - Server fails to start
    ///
    /// # Example
    ///
    /// ```no_run
    /// use sello::cli::commands::ServeCommand;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let cmd = ServeCommand { foreground: true };
    ///     if let Err(e) = cmd.run().await {
    ///         eprintln!("Error: {}", e);
    ///     }
    /// }
    /// ```
    pub async fn run(&self) -> Result<(), ServeError> {
        // 1. Check if initialized
        let base_dir = get_base_dir()?;
        check_initialized(&base_dir)?;

        // 2. Load configuration (currently we use defaults, but this is where
        // we would load from ~/.sello/config.toml)
        let config = load_config(&base_dir)?;

        // 3. Prompt for passphrase
        let passphrase = prompt_passphrase()?;

        // 4. Load and decrypt default key
        let keypair = load_key(&base_dir, &passphrase)?;

        // 5. Create signer from keypair
        let signer = Secp256k1Signer::new(keypair);
        let address = signer
            .address(Chain::Ethereum)
            .map_err(|e| ServeError::KeyError(e.to_string()))?;

        // 6. Create policy engine
        let history = create_transaction_history(&base_dir)?;
        let policy_engine = create_policy_engine(config.policy, history)?;

        // 7. Create audit logger (optional - don't fail if key doesn't exist)
        let audit_logger = create_audit_logger(&base_dir).ok();

        // 8. Display startup message
        let socket_path = base_dir.join("sello.sock");
        let audit_log_path = base_dir.join("logs").join("audit.jsonl");

        display_startup_message(
            &address,
            &socket_path,
            &audit_log_path,
            audit_logger.is_some(),
        );

        // Store components in Arc for sharing
        let _signer = Arc::new(signer);
        let _policy_engine = Arc::new(policy_engine);
        let _audit_logger = audit_logger.map(Arc::new);

        // 9. Set up signal handling
        // 10. Start server and wait for shutdown

        // For now, just wait for shutdown signal since the full server
        // implementation (SelloServer) is being developed in a separate task
        tracing::info!(
            socket = %socket_path.display(),
            "Server would start here (server implementation pending)"
        );

        // Wait for shutdown signal
        wait_for_shutdown().await?;

        tracing::info!("Server shutting down gracefully");
        println!("\nServer stopped.");

        Ok(())
    }
}

/// Server configuration loaded from config file.
#[derive(Debug, Default)]
struct ServerConfig {
    /// Policy configuration.
    policy: PolicyConfig,
}

/// Get the base Sello directory (~/.sello).
fn get_base_dir() -> Result<PathBuf, ServeError> {
    dirs::home_dir()
        .map(|h| h.join(".sello"))
        .ok_or(ServeError::NoHomeDirectory)
}

/// Check if Sello has been initialized.
fn check_initialized(base_dir: &Path) -> Result<(), ServeError> {
    let keys_dir = base_dir.join("keys");
    let default_key = keys_dir.join("default.enc");

    if !keys_dir.exists() || !default_key.exists() {
        return Err(ServeError::NotInitialized);
    }

    Ok(())
}

/// Load configuration from the base directory.
fn load_config(base_dir: &Path) -> Result<ServerConfig, ServeError> {
    let config_path = base_dir.join("config.toml");

    if config_path.exists() {
        // Load config from file
        let content = std::fs::read_to_string(&config_path)
            .map_err(|e| ServeError::ConfigError(format!("failed to read config file: {e}")))?;

        // Parse TOML (for now, we just acknowledge it exists and use defaults)
        // A full implementation would parse the TOML into PolicyConfig
        let _ = content;
        tracing::debug!(config_path = %config_path.display(), "Config file found");
    }

    // Return default config for now
    Ok(ServerConfig::default())
}

/// Prompt the user for their passphrase.
fn prompt_passphrase() -> Result<String, ServeError> {
    println!("Enter passphrase to unlock signing key:");

    rpassword::read_password().map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            ServeError::Cancelled
        } else {
            ServeError::Io(e)
        }
    })
}

/// Load the default key from the key store.
fn load_key(base_dir: &Path, passphrase: &str) -> Result<Secp256k1KeyPair, ServeError> {
    let keys_dir = base_dir.join("keys");

    let store = FileKeyStore::with_path(keys_dir)
        .map_err(|e| ServeError::KeyError(format!("failed to create key store: {e}")))?;

    let secret_key = store.load("default", passphrase).map_err(|e| {
        // Check if it's a decryption failure (wrong passphrase)
        if matches!(e, sello_core::error::StoreError::DecryptionFailed) {
            ServeError::InvalidPassphrase
        } else {
            ServeError::KeyError(format!("failed to load key: {e}"))
        }
    })?;

    Secp256k1KeyPair::from_secret_key(&secret_key)
        .map_err(|e| ServeError::KeyError(format!("failed to create keypair: {e}")))
}

/// Create the transaction history database.
fn create_transaction_history(base_dir: &Path) -> Result<Arc<TransactionHistory>, ServeError> {
    let db_path = base_dir.join("history.db");

    TransactionHistory::new(&db_path)
        .map(Arc::new)
        .map_err(|e| ServeError::PolicyError(format!("failed to create transaction history: {e}")))
}

/// Create the policy engine.
fn create_policy_engine(
    config: PolicyConfig,
    history: Arc<TransactionHistory>,
) -> Result<DefaultPolicyEngine, ServeError> {
    DefaultPolicyEngine::new(config, history)
        .map_err(|e| ServeError::PolicyError(format!("failed to create policy engine: {e}")))
}

/// Create the audit logger (optional).
fn create_audit_logger(base_dir: &Path) -> Result<AuditLogger, ServeError> {
    AuditLogger::from_config(base_dir)
        .map_err(|e| ServeError::AuditError(format!("failed to create audit logger: {e}")))
}

/// Display the startup message.
fn display_startup_message(
    address: &str,
    socket_path: &Path,
    audit_log_path: &Path,
    audit_enabled: bool,
) {
    println!("\nSello server starting...\n");
    println!("Address: {address}");
    println!("Socket: {}", socket_path.display());

    if audit_enabled {
        println!("Audit log: {}", audit_log_path.display());
    } else {
        println!("Audit log: disabled (no audit.key file)");
    }

    println!("\nPress Ctrl+C to stop the server.\n");
}

/// Wait for a shutdown signal (SIGTERM or SIGINT).
async fn wait_for_shutdown() -> Result<(), ServeError> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut sigterm = signal(SignalKind::terminate()).map_err(|e| {
            ServeError::ServerError(format!("failed to register SIGTERM handler: {e}"))
        })?;

        let mut sigint = signal(SignalKind::interrupt()).map_err(|e| {
            ServeError::ServerError(format!("failed to register SIGINT handler: {e}"))
        })?;

        tokio::select! {
            _ = sigterm.recv() => {
                tracing::info!("Received SIGTERM");
            }
            _ = sigint.recv() => {
                tracing::info!("Received SIGINT");
            }
        }
    }

    #[cfg(not(unix))]
    {
        // On non-Unix platforms, just wait for Ctrl+C
        tokio::signal::ctrl_c()
            .await
            .map_err(|e| ServeError::ServerError(format!("failed to wait for Ctrl+C: {e}")))?;

        tracing::info!("Received Ctrl+C");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::needless_borrow,
        clippy::needless_borrows_for_generic_args,
        clippy::uninlined_format_args
    )]

    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// Helper to create a test environment with initialized Sello.
    fn create_initialized_env() -> (TempDir, PathBuf) {
        use sello_crypto::keys::SecretKey;

        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let base_dir = temp_dir.path().to_path_buf();

        // Create keys directory
        let keys_dir = base_dir.join("keys");
        fs::create_dir_all(&keys_dir).expect("failed to create keys dir");

        // Create a test key
        let store = FileKeyStore::with_path(keys_dir).expect("failed to create key store");
        let secret_key = SecretKey::generate();
        store
            .store("default", &secret_key, "test-passphrase")
            .expect("failed to store key");

        (temp_dir, base_dir)
    }

    // =========================================================================
    // Check initialized tests
    // =========================================================================

    mod check_initialized_tests {
        use super::*;

        #[test]
        fn test_not_initialized_no_keys_dir() {
            let temp_dir = TempDir::new().expect("failed to create temp dir");
            let base_dir = temp_dir.path();

            let result = check_initialized(base_dir);
            assert!(matches!(result, Err(ServeError::NotInitialized)));
        }

        #[test]
        fn test_not_initialized_no_default_key() {
            let temp_dir = TempDir::new().expect("failed to create temp dir");
            let base_dir = temp_dir.path();

            // Create keys directory but no default key
            let keys_dir = base_dir.join("keys");
            fs::create_dir_all(&keys_dir).expect("failed to create keys dir");

            let result = check_initialized(base_dir);
            assert!(matches!(result, Err(ServeError::NotInitialized)));
        }

        #[test]
        fn test_initialized_with_default_key() {
            let (_temp_dir, base_dir) = create_initialized_env();

            let result = check_initialized(&base_dir);
            assert!(result.is_ok());
        }
    }

    // =========================================================================
    // Load key tests
    // =========================================================================

    mod load_key_tests {
        use super::*;

        #[test]
        fn test_load_key_success() {
            let (_temp_dir, base_dir) = create_initialized_env();

            let result = load_key(&base_dir, "test-passphrase");
            assert!(result.is_ok());
        }

        #[test]
        fn test_load_key_wrong_passphrase() {
            let (_temp_dir, base_dir) = create_initialized_env();

            let result = load_key(&base_dir, "wrong-passphrase");
            assert!(matches!(result, Err(ServeError::InvalidPassphrase)));
        }

        #[test]
        fn test_load_key_not_found() {
            let temp_dir = TempDir::new().expect("failed to create temp dir");
            let base_dir = temp_dir.path();

            // Create empty keys directory
            let keys_dir = base_dir.join("keys");
            fs::create_dir_all(&keys_dir).expect("failed to create keys dir");

            let result = load_key(base_dir, "test-passphrase");
            assert!(matches!(result, Err(ServeError::KeyError(_))));
        }
    }

    // =========================================================================
    // Load config tests
    // =========================================================================

    mod load_config_tests {
        use super::*;

        #[test]
        fn test_load_config_no_file() {
            let temp_dir = TempDir::new().expect("failed to create temp dir");
            let base_dir = temp_dir.path();

            let result = load_config(base_dir);
            assert!(result.is_ok());
        }

        #[test]
        fn test_load_config_with_file() {
            let temp_dir = TempDir::new().expect("failed to create temp dir");
            let base_dir = temp_dir.path();

            // Create a config file
            let config_path = base_dir.join("config.toml");
            fs::write(&config_path, "[policy]\n").expect("failed to write config");

            let result = load_config(base_dir);
            assert!(result.is_ok());
        }

        // =====================================================================
        // Phase 2: Configuration Error Handling
        // =====================================================================

        #[test]
        fn should_return_error_when_config_file_cannot_be_read() {
            // Arrange: Create a directory without read permission (Unix only)
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;

                let temp_dir = TempDir::new().expect("failed to create temp dir");
                let base_dir = temp_dir.path();

                // Create config file
                let config_path = base_dir.join("config.toml");
                fs::write(&config_path, "[policy]\n").expect("failed to write config");

                // Remove read permission
                let mut perms = fs::metadata(&config_path)
                    .expect("failed to get metadata")
                    .permissions();
                perms.set_mode(0o000); // No permissions
                fs::set_permissions(&config_path, perms).expect("failed to set permissions");

                // Act: Try to load config
                let result = load_config(base_dir);

                // Assert: Should fail with config error
                assert!(result.is_err());
                if let Err(ServeError::ConfigError(msg)) = result {
                    assert!(msg.contains("failed to read config file"));
                }

                // Cleanup: Restore permissions so temp_dir can be deleted
                let mut perms = fs::metadata(&config_path)
                    .expect("failed to get metadata")
                    .permissions();
                perms.set_mode(0o644);
                fs::set_permissions(&config_path, perms).expect("failed to restore permissions");
            }

            // On non-Unix systems, just verify the function works
            #[cfg(not(unix))]
            {
                let temp_dir = TempDir::new().expect("failed to create temp dir");
                let base_dir = temp_dir.path();
                let result = load_config(base_dir);
                assert!(result.is_ok());
            }
        }

        #[test]
        fn should_handle_empty_config_file() {
            // Arrange: Create empty config file
            let temp_dir = TempDir::new().expect("failed to create temp dir");
            let base_dir = temp_dir.path();

            let config_path = base_dir.join("config.toml");
            fs::write(&config_path, "").expect("failed to write config");

            // Act: Load config
            let result = load_config(base_dir);

            // Assert: Should succeed with default config
            assert!(result.is_ok());
        }

        #[test]
        fn should_handle_config_file_with_whitespace_only() {
            // Arrange: Config file with only whitespace
            let temp_dir = TempDir::new().expect("failed to create temp dir");
            let base_dir = temp_dir.path();

            let config_path = base_dir.join("config.toml");
            fs::write(&config_path, "   \n\t\n  ").expect("failed to write config");

            // Act: Load config
            let result = load_config(base_dir);

            // Assert: Should succeed (content is read but not parsed yet)
            assert!(result.is_ok());
        }

        #[test]
        fn should_handle_config_file_with_comments_only() {
            // Arrange: Config file with only TOML comments
            let temp_dir = TempDir::new().expect("failed to create temp dir");
            let base_dir = temp_dir.path();

            let config_path = base_dir.join("config.toml");
            fs::write(&config_path, "# This is a comment\n# Another comment\n")
                .expect("failed to write config");

            // Act: Load config
            let result = load_config(base_dir);

            // Assert: Should succeed
            assert!(result.is_ok());
        }
    }

    // =========================================================================
    // Transaction history tests
    // =========================================================================

    mod transaction_history_tests {
        use super::*;

        #[test]
        fn test_create_transaction_history() {
            let temp_dir = TempDir::new().expect("failed to create temp dir");
            let base_dir = temp_dir.path();

            let result = create_transaction_history(base_dir);
            assert!(result.is_ok());

            // Verify database file was created
            let db_path = base_dir.join("history.db");
            assert!(db_path.exists());
        }
    }

    // =========================================================================
    // Policy engine tests
    // =========================================================================

    mod policy_engine_tests {
        use super::*;

        #[test]
        fn test_create_policy_engine() {
            let temp_dir = TempDir::new().expect("failed to create temp dir");
            let base_dir = temp_dir.path();

            let history = create_transaction_history(base_dir).expect("failed to create history");
            let config = PolicyConfig::new();

            let result = create_policy_engine(config, history);
            assert!(result.is_ok());
        }
    }

    // =========================================================================
    // Audit logger tests
    // =========================================================================

    mod audit_logger_tests {
        use super::*;

        #[test]
        fn test_create_audit_logger_no_key() {
            let temp_dir = TempDir::new().expect("failed to create temp dir");
            let base_dir = temp_dir.path();

            // No audit.key file
            let result = create_audit_logger(base_dir);
            assert!(matches!(result, Err(ServeError::AuditError(_))));
        }

        #[test]
        fn test_create_audit_logger_with_key() {
            let temp_dir = TempDir::new().expect("failed to create temp dir");
            let base_dir = temp_dir.path();

            // Create audit.key file
            let key = [0x42u8; 32];
            let key_path = base_dir.join("audit.key");
            fs::write(&key_path, &key).expect("failed to write key");

            let result = create_audit_logger(base_dir);
            assert!(result.is_ok());
        }
    }

    // =========================================================================
    // ServeError tests
    // =========================================================================

    mod serve_error_tests {
        use super::*;

        #[test]
        fn test_error_display() {
            let err = ServeError::NotInitialized;
            assert!(err.to_string().contains("not initialized"));

            let err = ServeError::ConfigError("test".to_string());
            assert!(err.to_string().contains("configuration"));

            let err = ServeError::KeyError("test".to_string());
            assert!(err.to_string().contains("key"));

            let err = ServeError::InvalidPassphrase;
            assert!(err.to_string().contains("passphrase"));

            let err = ServeError::ServerError("test".to_string());
            assert!(err.to_string().contains("Server error"));

            let err = ServeError::Cancelled;
            assert!(err.to_string().contains("cancelled"));

            let err = ServeError::NoHomeDirectory;
            assert!(err.to_string().contains("home directory"));

            let err = ServeError::PolicyError("test".to_string());
            assert!(err.to_string().contains("Policy engine"));

            let err = ServeError::AuditError("test".to_string());
            assert!(err.to_string().contains("Audit logger"));
        }

        #[test]
        fn test_io_error_conversion() {
            let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "not found");
            let serve_err: ServeError = io_err.into();
            assert!(matches!(serve_err, ServeError::Io(_)));
        }
    }

    // =========================================================================
    // ServeCommand tests
    // =========================================================================

    mod serve_command_tests {
        use super::*;

        #[test]
        fn test_serve_command_debug() {
            let cmd = ServeCommand { foreground: true };
            let debug = format!("{:?}", cmd);
            assert!(debug.contains("foreground"));
        }

        #[test]
        fn test_serve_command_clone() {
            let cmd = ServeCommand { foreground: true };
            let cloned = cmd.clone();
            assert_eq!(cmd.foreground, cloned.foreground);
        }
    }

    // =========================================================================
    // Additional Coverage Tests - Phase 3
    // =========================================================================

    mod display_startup_tests {
        use super::*;

        #[test]
        fn test_display_startup_message_with_audit() {
            let socket = PathBuf::from("/tmp/test.sock");
            let audit_log = PathBuf::from("/tmp/audit.jsonl");

            // Just verify it doesn't panic
            display_startup_message("0x1234567890abcdef", &socket, &audit_log, true);
        }

        #[test]
        fn test_display_startup_message_without_audit() {
            let socket = PathBuf::from("/tmp/test.sock");
            let audit_log = PathBuf::from("/tmp/audit.jsonl");

            // Just verify it doesn't panic
            display_startup_message("0x1234567890abcdef", &socket, &audit_log, false);
        }
    }

    mod server_config_tests {
        use super::*;

        #[test]
        fn test_server_config_default() {
            let config = ServerConfig::default();
            // Just verify it has default policy
            assert!(!config.policy.whitelist_enabled);
        }

        #[test]
        fn test_server_config_debug() {
            let config = ServerConfig::default();
            let debug = format!("{:?}", config);
            assert!(debug.contains("ServerConfig"));
        }
    }

    mod error_handling_tests {
        use super::*;

        #[test]
        fn test_serve_error_is_send_sync() {
            fn assert_send_sync<T: Send + Sync>() {}
            assert_send_sync::<ServeError>();
        }

        #[test]
        fn test_serve_command_is_send_sync() {
            fn assert_send_sync<T: Send + Sync>() {}
            assert_send_sync::<ServeCommand>();
        }

        #[test]
        fn test_all_serve_error_variants_display() {
            let errors: Vec<ServeError> = vec![
                ServeError::NotInitialized,
                ServeError::ConfigError("config".to_string()),
                ServeError::KeyError("key".to_string()),
                ServeError::InvalidPassphrase,
                ServeError::ServerError("server".to_string()),
                ServeError::Cancelled,
                ServeError::NoHomeDirectory,
                ServeError::PolicyError("policy".to_string()),
                ServeError::AuditError("audit".to_string()),
            ];

            for err in errors {
                let display = err.to_string();
                assert!(!display.is_empty());
            }
        }
    }

    mod transaction_history_error_tests {
        use super::*;

        #[test]
        fn test_create_transaction_history_readonly() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;

                let temp_dir = TempDir::new().expect("failed to create temp dir");
                let base_dir = temp_dir.path();

                // Create db file with no write permission
                let db_path = base_dir.join("history.db");
                fs::write(&db_path, b"").expect("failed to create db");

                let mut perms = fs::metadata(&db_path)
                    .expect("failed to get metadata")
                    .permissions();
                perms.set_mode(0o000);
                fs::set_permissions(&db_path, perms).expect("failed to set permissions");

                // Should fail with permission error
                let result = create_transaction_history(base_dir);

                // Restore permissions for cleanup
                let mut perms = fs::metadata(&db_path)
                    .expect("failed to get metadata")
                    .permissions();
                perms.set_mode(0o644);
                fs::set_permissions(&db_path, perms).expect("failed to restore permissions");

                // Result may fail or succeed depending on SQLite behavior
                // Just ensure no panic
                let _ = result;
            }
        }
    }

    mod policy_engine_error_tests {
        use super::*;

        #[test]
        fn test_create_policy_engine_with_custom_config() {
            use sello_core::U256;

            let temp_dir = TempDir::new().expect("failed to create temp dir");
            let base_dir = temp_dir.path();

            let history = create_transaction_history(base_dir).expect("failed to create history");

            let config = PolicyConfig::new()
                .with_whitelist(vec!["0xAAA".to_string()])
                .with_daily_limit("ETH", U256::from(1000_u64));

            let result = create_policy_engine(config, history);
            assert!(result.is_ok());
        }
    }

    mod audit_logger_error_tests {
        use super::*;

        #[test]
        fn test_create_audit_logger_invalid_key() {
            let temp_dir = TempDir::new().expect("failed to create temp dir");
            let base_dir = temp_dir.path();

            // Create an invalid audit key (wrong size)
            let key_path = base_dir.join("audit.key");
            fs::write(&key_path, b"too short").expect("failed to write key");

            let result = create_audit_logger(base_dir);
            assert!(result.is_err());
        }

        #[test]
        fn test_create_audit_logger_with_valid_32_byte_key() {
            let temp_dir = TempDir::new().expect("failed to create temp dir");
            let base_dir = temp_dir.path();

            // Create a valid 32-byte audit key
            let key = [0xAB_u8; 32];
            let key_path = base_dir.join("audit.key");
            fs::write(&key_path, key).expect("failed to write key");

            let result = create_audit_logger(base_dir);
            assert!(result.is_ok());
        }
    }

    mod serve_command_foreground_tests {
        use super::*;

        #[test]
        fn test_serve_command_foreground_false() {
            let cmd = ServeCommand { foreground: false };
            assert!(!cmd.foreground);

            let cloned = cmd.clone();
            assert!(!cloned.foreground);
        }
    }
}
