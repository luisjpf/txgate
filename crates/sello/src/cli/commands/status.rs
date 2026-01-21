//! # Status Command
//!
//! Implementation of the `sello status` command that displays current status
//! including key count, chains supported, policy summary, and transaction statistics.
//!
//! ## Output Format
//!
//! ```text
//! Sello Status
//! ============
//!
//! Installation:
//!   Base directory: ~/.sello
//!   Initialized: Yes
//!
//! Keys:
//!   Total keys: 1
//!   Default key: default
//!
//! Supported Chains:
//!   - Ethereum (secp256k1)
//!
//! Policy:
//!   Whitelist enabled: No
//!   Whitelist addresses: 0
//!   Blacklist addresses: 2
//!   Transaction limits: 3 tokens
//!   Daily limits: 2 tokens
//!
//! Server:
//!   Socket path: ~/.sello/sello.sock
//!   Status: Not running
//! ```
//!
//! ## Usage
//!
//! ```no_run
//! use sello::cli::commands::status::StatusCommand;
//!
//! let cmd = StatusCommand;
//! cmd.run().expect("status command failed");
//! ```

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use sello_core::config::{Config, PolicyConfig};
use sello_core::config_loader::{expand_path, ConfigLoader};
use sello_core::error::ConfigError;

// ============================================================================
// Constants
// ============================================================================

/// Base directory name within the home directory.
const BASE_DIR_NAME: &str = ".sello";

/// Keys subdirectory name.
const KEYS_DIR_NAME: &str = "keys";

/// Config file name.
const CONFIG_FILE_NAME: &str = "config.toml";

// ============================================================================
// StatusError
// ============================================================================

/// Errors that can occur during status display.
#[derive(Debug, thiserror::Error)]
pub enum StatusError {
    /// Sello is not initialized.
    #[error("Sello is not initialized. Run 'sello init' first.")]
    NotInitialized,

    /// Failed to load configuration.
    #[error("Failed to load configuration: {0}")]
    ConfigError(#[source] ConfigError),

    /// I/O error.
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// History error.
    #[error("History error: {0}")]
    History(String),
}

impl From<ConfigError> for StatusError {
    fn from(err: ConfigError) -> Self {
        Self::ConfigError(err)
    }
}

// ============================================================================
// PolicySummary
// ============================================================================

/// Summary of policy configuration for display.
#[derive(Debug, Clone, Default)]
pub struct PolicySummary {
    /// Whether whitelist mode is enabled.
    pub whitelist_enabled: bool,
    /// Number of addresses in the whitelist.
    pub whitelist_count: usize,
    /// Number of addresses in the blacklist.
    pub blacklist_count: usize,
    /// Number of tokens with transaction limits.
    pub tx_limit_count: usize,
    /// Number of tokens with daily limits.
    pub daily_limit_count: usize,
}

// ============================================================================
// StatusCommand
// ============================================================================

/// The `sello status` command handler.
///
/// This command displays current Sello status including:
/// - Installation status and base directory
/// - Key count and default key
/// - Supported chains
/// - Policy summary
/// - Server status
///
/// # Example
///
/// ```no_run
/// use sello::cli::commands::status::StatusCommand;
///
/// let cmd = StatusCommand;
/// match cmd.run() {
///     Ok(()) => println!("Status displayed"),
///     Err(e) => eprintln!("Error: {}", e),
/// }
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct StatusCommand;

impl StatusCommand {
    /// Create a new `StatusCommand`.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Run the status command.
    ///
    /// This method:
    /// 1. Checks if Sello is initialized
    /// 2. Loads configuration
    /// 3. Counts keys in ~/.sello/keys/
    /// 4. Gets policy summary
    /// 5. Checks server status
    /// 6. Displays formatted output
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Sello is not initialized
    /// - Configuration cannot be loaded
    /// - Key directory cannot be read
    pub fn run(&self) -> Result<(), StatusError> {
        let base_dir = get_base_dir()?;

        // 1. Check if initialized
        if !is_initialized(&base_dir) {
            return Err(StatusError::NotInitialized);
        }

        // 2. Load configuration
        let loader = ConfigLoader::with_base_dir(base_dir.clone());
        let config = loader.load()?;

        // 3. Count keys
        let keys_dir = base_dir.join(KEYS_DIR_NAME);
        let key_count = count_keys(&keys_dir)?;
        let key_names = list_key_names(&keys_dir)?;

        // 4. Get policy summary
        let policy_summary = get_policy_summary(&config.policy);

        // 5. Check server status
        let socket_path_str = &config.server.socket_path;
        let socket_path =
            expand_path(socket_path_str).unwrap_or_else(|_| PathBuf::from(socket_path_str));
        let server_running = check_server_running(&socket_path);

        // 6. Display formatted output
        print_status(
            &base_dir,
            &config,
            key_count,
            &key_names,
            &policy_summary,
            &socket_path,
            server_running,
        );

        Ok(())
    }

    /// Run the status command with a custom base directory.
    ///
    /// This is primarily used for testing to avoid modifying the user's
    /// actual home directory.
    ///
    /// # Errors
    ///
    /// Same as [`run`](Self::run).
    #[cfg(test)]
    pub fn run_with_base_dir(&self, base_dir: PathBuf) -> Result<StatusOutput, StatusError> {
        // 1. Check if initialized
        if !is_initialized(&base_dir) {
            return Err(StatusError::NotInitialized);
        }

        // 2. Load configuration
        let loader = ConfigLoader::with_base_dir(base_dir.clone());
        let config = loader.load()?;

        // 3. Count keys
        let keys_dir = base_dir.join(KEYS_DIR_NAME);
        let key_count = count_keys(&keys_dir)?;
        let key_names = list_key_names(&keys_dir)?;

        // 4. Get policy summary
        let policy_summary = get_policy_summary(&config.policy);

        // 5. Check server status
        let socket_path_str = &config.server.socket_path;
        let socket_path =
            expand_path(socket_path_str).unwrap_or_else(|_| PathBuf::from(socket_path_str));
        let server_running = check_server_running(&socket_path);

        Ok(StatusOutput {
            base_dir,
            initialized: true,
            key_count,
            key_names,
            default_key: config.keys.default_key.clone(),
            policy_summary,
            socket_path,
            server_running,
        })
    }
}

// ============================================================================
// StatusOutput (for testing)
// ============================================================================

/// Status output structure for testing.
#[cfg(test)]
#[derive(Debug)]
pub struct StatusOutput {
    /// Base directory path.
    pub base_dir: PathBuf,
    /// Whether Sello is initialized.
    pub initialized: bool,
    /// Number of keys in the key store.
    pub key_count: usize,
    /// List of key names.
    pub key_names: Vec<String>,
    /// Default key name.
    pub default_key: String,
    /// Policy summary.
    pub policy_summary: PolicySummary,
    /// Socket path for the server.
    pub socket_path: PathBuf,
    /// Whether the server is running.
    pub server_running: bool,
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Get the base directory for Sello files (~/.sello).
fn get_base_dir() -> Result<PathBuf, StatusError> {
    dirs::home_dir()
        .map(|home| home.join(BASE_DIR_NAME))
        .ok_or_else(|| StatusError::ConfigError(ConfigError::no_home_directory()))
}

/// Check if Sello is initialized.
///
/// Returns true if both the config file and keys directory exist.
fn is_initialized(base_dir: &Path) -> bool {
    let config_path = base_dir.join(CONFIG_FILE_NAME);
    let keys_dir = base_dir.join(KEYS_DIR_NAME);

    config_path.exists() && keys_dir.exists()
}

/// Count the number of keys in the keys directory.
///
/// Only counts files with `.enc` extension and excludes hidden files.
///
/// # Errors
///
/// Returns an error if the directory cannot be read.
pub fn count_keys(keys_dir: &Path) -> Result<usize, io::Error> {
    if !keys_dir.exists() {
        return Ok(0);
    }

    let count = fs::read_dir(keys_dir)?
        .filter_map(Result::ok)
        .filter(|entry| {
            let path = entry.path();
            path.extension().is_some_and(|ext| ext == "enc")
                && path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .is_some_and(|name| !name.starts_with('.'))
        })
        .count();

    Ok(count)
}

/// List the names of keys in the keys directory.
///
/// Returns a sorted list of key names (without `.enc` extension).
fn list_key_names(keys_dir: &Path) -> Result<Vec<String>, io::Error> {
    if !keys_dir.exists() {
        return Ok(Vec::new());
    }

    let mut names: Vec<String> = fs::read_dir(keys_dir)?
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "enc") {
                path.file_stem()
                    .and_then(|s| s.to_str())
                    .filter(|name| !name.starts_with('.'))
                    .map(String::from)
            } else {
                None
            }
        })
        .collect();

    names.sort();
    Ok(names)
}

/// Get a summary of the policy configuration.
#[must_use]
pub fn get_policy_summary(policy: &PolicyConfig) -> PolicySummary {
    PolicySummary {
        whitelist_enabled: policy.whitelist_enabled,
        whitelist_count: policy.whitelist.len(),
        blacklist_count: policy.blacklist.len(),
        tx_limit_count: policy.transaction_limits.len(),
        daily_limit_count: policy.daily_limits.len(),
    }
}

/// Check if the server is running by checking socket file existence.
///
/// This is a simple check that only verifies the socket file exists.
/// A more robust check would attempt to connect to the socket.
#[must_use]
pub fn check_server_running(socket_path: &Path) -> bool {
    socket_path.exists()
}

/// Format a human-readable display path.
///
/// Replaces home directory with ~ for cleaner display.
fn format_display_path(path: &Path) -> String {
    if let Some(home) = dirs::home_dir() {
        if let Ok(relative) = path.strip_prefix(&home) {
            return format!("~/{}", relative.display());
        }
    }
    path.display().to_string()
}

/// Print the status output.
#[allow(clippy::too_many_arguments)]
fn print_status(
    base_dir: &Path,
    config: &Config,
    key_count: usize,
    key_names: &[String],
    policy_summary: &PolicySummary,
    socket_path: &Path,
    server_running: bool,
) {
    println!("Sello Status");
    println!("============");
    println!();

    // Installation section
    println!("Installation:");
    println!("  Base directory: {}", format_display_path(base_dir));
    println!("  Initialized: Yes");
    println!();

    // Keys section
    println!("Keys:");
    println!("  Total keys: {key_count}");
    println!("  Default key: {}", config.keys.default_key);
    if !key_names.is_empty() {
        let has_default = key_names.contains(&config.keys.default_key);
        if !has_default && key_count > 0 {
            println!(
                "  Warning: Default key '{}' not found",
                config.keys.default_key
            );
        }
        // Show first few keys if there are many
        if key_names.len() <= 5 {
            for name in key_names {
                let marker = if name == &config.keys.default_key {
                    " (default)"
                } else {
                    ""
                };
                println!("    - {name}{marker}");
            }
        } else {
            for name in key_names.iter().take(3) {
                let marker = if name == &config.keys.default_key {
                    " (default)"
                } else {
                    ""
                };
                println!("    - {name}{marker}");
            }
            println!("    ... and {} more", key_names.len() - 3);
        }
    }
    println!();

    // Supported Chains section
    println!("Supported Chains:");
    println!("  - Ethereum (secp256k1)");
    println!();

    // Policy section
    println!("Policy:");
    println!(
        "  Whitelist enabled: {}",
        if policy_summary.whitelist_enabled {
            "Yes"
        } else {
            "No"
        }
    );
    println!("  Whitelist addresses: {}", policy_summary.whitelist_count);
    println!("  Blacklist addresses: {}", policy_summary.blacklist_count);
    println!(
        "  Transaction limits: {} tokens",
        policy_summary.tx_limit_count
    );
    println!(
        "  Daily limits: {} tokens",
        policy_summary.daily_limit_count
    );
    println!();

    // Server section
    println!("Server:");
    println!("  Socket path: {}", format_display_path(socket_path));
    println!(
        "  Status: {}",
        if server_running {
            "Running"
        } else {
            "Not running"
        }
    );
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
    use std::fs::{self, File};
    use tempfile::TempDir;

    /// Create a temporary directory for testing.
    fn create_test_dir() -> TempDir {
        TempDir::new().expect("failed to create temp dir")
    }

    /// Create an initialized Sello directory structure.
    fn create_initialized_sello(base_dir: &Path) {
        // Create directories
        fs::create_dir_all(base_dir.join(KEYS_DIR_NAME)).expect("failed to create keys dir");

        // Create default config
        let config_path = base_dir.join(CONFIG_FILE_NAME);
        let default_config = Config::default_toml();
        fs::write(&config_path, default_config).expect("failed to write config");

        // Create a default key file (mock)
        let key_path = base_dir.join(KEYS_DIR_NAME).join("default.enc");
        fs::write(&key_path, b"mock encrypted key").expect("failed to write key");
    }

    // ------------------------------------------------------------------------
    // Helper Function Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_count_keys_empty_directory() {
        let temp_dir = create_test_dir();
        let keys_dir = temp_dir.path().join("keys");
        fs::create_dir_all(&keys_dir).expect("failed to create dir");

        let count = count_keys(&keys_dir).expect("count should succeed");
        assert_eq!(count, 0);
    }

    #[test]
    fn test_count_keys_with_keys() {
        let temp_dir = create_test_dir();
        let keys_dir = temp_dir.path().join("keys");
        fs::create_dir_all(&keys_dir).expect("failed to create dir");

        // Create some key files
        fs::write(keys_dir.join("key1.enc"), b"data").expect("write should succeed");
        fs::write(keys_dir.join("key2.enc"), b"data").expect("write should succeed");
        fs::write(keys_dir.join("key3.enc"), b"data").expect("write should succeed");

        let count = count_keys(&keys_dir).expect("count should succeed");
        assert_eq!(count, 3);
    }

    #[test]
    fn test_count_keys_ignores_hidden_files() {
        let temp_dir = create_test_dir();
        let keys_dir = temp_dir.path().join("keys");
        fs::create_dir_all(&keys_dir).expect("failed to create dir");

        // Create regular and hidden key files
        fs::write(keys_dir.join("visible.enc"), b"data").expect("write should succeed");
        fs::write(keys_dir.join(".hidden.enc"), b"data").expect("write should succeed");

        let count = count_keys(&keys_dir).expect("count should succeed");
        assert_eq!(count, 1);
    }

    #[test]
    fn test_count_keys_ignores_non_enc_files() {
        let temp_dir = create_test_dir();
        let keys_dir = temp_dir.path().join("keys");
        fs::create_dir_all(&keys_dir).expect("failed to create dir");

        // Create .enc and other files
        fs::write(keys_dir.join("key.enc"), b"data").expect("write should succeed");
        fs::write(keys_dir.join("readme.txt"), b"data").expect("write should succeed");
        fs::write(keys_dir.join("backup.bak"), b"data").expect("write should succeed");

        let count = count_keys(&keys_dir).expect("count should succeed");
        assert_eq!(count, 1);
    }

    #[test]
    fn test_count_keys_nonexistent_directory() {
        let temp_dir = create_test_dir();
        let keys_dir = temp_dir.path().join("nonexistent");

        let count = count_keys(&keys_dir).expect("count should succeed");
        assert_eq!(count, 0);
    }

    #[test]
    fn test_list_key_names() {
        let temp_dir = create_test_dir();
        let keys_dir = temp_dir.path().join("keys");
        fs::create_dir_all(&keys_dir).expect("failed to create dir");

        // Create key files in non-alphabetical order
        fs::write(keys_dir.join("zebra.enc"), b"data").expect("write should succeed");
        fs::write(keys_dir.join("apple.enc"), b"data").expect("write should succeed");
        fs::write(keys_dir.join("mango.enc"), b"data").expect("write should succeed");

        let names = list_key_names(&keys_dir).expect("list should succeed");
        assert_eq!(names, vec!["apple", "mango", "zebra"]);
    }

    #[test]
    fn test_get_policy_summary_default() {
        let policy = PolicyConfig::default();
        let summary = get_policy_summary(&policy);

        assert!(!summary.whitelist_enabled);
        assert_eq!(summary.whitelist_count, 0);
        assert_eq!(summary.blacklist_count, 0);
        assert_eq!(summary.tx_limit_count, 0);
        assert_eq!(summary.daily_limit_count, 0);
    }

    #[test]
    fn test_get_policy_summary_with_values() {
        use sello_core::U256;

        let policy = PolicyConfig::new()
            .with_whitelist(vec!["0xAAA".to_string(), "0xBBB".to_string()])
            .with_blacklist(vec!["0xCCC".to_string()])
            .with_transaction_limit("ETH", U256::from(1_u64))
            .with_daily_limit("ETH", U256::from(10_u64))
            .with_daily_limit("USDC", U256::from(100_u64));

        let summary = get_policy_summary(&policy);

        assert!(summary.whitelist_enabled);
        assert_eq!(summary.whitelist_count, 2);
        assert_eq!(summary.blacklist_count, 1);
        assert_eq!(summary.tx_limit_count, 1);
        assert_eq!(summary.daily_limit_count, 2);
    }

    #[test]
    fn test_check_server_running_not_running() {
        let temp_dir = create_test_dir();
        let socket_path = temp_dir.path().join("sello.sock");

        assert!(!check_server_running(&socket_path));
    }

    #[test]
    fn test_check_server_running_socket_exists() {
        let temp_dir = create_test_dir();
        let socket_path = temp_dir.path().join("sello.sock");

        // Create a file to simulate socket existence
        File::create(&socket_path).expect("failed to create file");

        assert!(check_server_running(&socket_path));
    }

    #[test]
    fn test_is_initialized_false_when_empty() {
        let temp_dir = create_test_dir();
        assert!(!is_initialized(temp_dir.path()));
    }

    #[test]
    fn test_is_initialized_false_without_config() {
        let temp_dir = create_test_dir();
        let base_dir = temp_dir.path();

        // Create only keys directory
        fs::create_dir_all(base_dir.join(KEYS_DIR_NAME)).expect("failed to create dir");

        assert!(!is_initialized(base_dir));
    }

    #[test]
    fn test_is_initialized_false_without_keys() {
        let temp_dir = create_test_dir();
        let base_dir = temp_dir.path();

        // Create only config file
        fs::write(base_dir.join(CONFIG_FILE_NAME), "test").expect("failed to write");

        assert!(!is_initialized(base_dir));
    }

    #[test]
    fn test_is_initialized_true_when_complete() {
        let temp_dir = create_test_dir();
        let base_dir = temp_dir.path();

        create_initialized_sello(base_dir);

        assert!(is_initialized(base_dir));
    }

    // ------------------------------------------------------------------------
    // StatusCommand Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_status_command_not_initialized() {
        let temp_dir = create_test_dir();
        let cmd = StatusCommand::new();

        let result = cmd.run_with_base_dir(temp_dir.path().to_path_buf());

        assert!(result.is_err());
        assert!(matches!(result, Err(StatusError::NotInitialized)));
    }

    #[test]
    fn test_status_command_initialized() {
        let temp_dir = create_test_dir();
        let base_dir = temp_dir.path().to_path_buf();

        create_initialized_sello(&base_dir);

        let cmd = StatusCommand::new();
        let result = cmd.run_with_base_dir(base_dir.clone());

        assert!(result.is_ok());
        let output = result.expect("should succeed");

        assert!(output.initialized);
        assert_eq!(output.key_count, 1);
        assert_eq!(output.key_names, vec!["default"]);
        assert_eq!(output.default_key, "default");
        assert!(!output.server_running);
    }

    #[test]
    fn test_status_command_multiple_keys() {
        let temp_dir = create_test_dir();
        let base_dir = temp_dir.path().to_path_buf();

        create_initialized_sello(&base_dir);

        // Add more keys
        let keys_dir = base_dir.join(KEYS_DIR_NAME);
        fs::write(keys_dir.join("hot-wallet.enc"), b"data").expect("write should succeed");
        fs::write(keys_dir.join("cold-storage.enc"), b"data").expect("write should succeed");

        let cmd = StatusCommand::new();
        let result = cmd.run_with_base_dir(base_dir);

        assert!(result.is_ok());
        let output = result.expect("should succeed");

        assert_eq!(output.key_count, 3);
        assert_eq!(
            output.key_names,
            vec!["cold-storage", "default", "hot-wallet"]
        );
    }

    #[test]
    fn test_status_command_with_policy() {
        let temp_dir = create_test_dir();
        let base_dir = temp_dir.path().to_path_buf();

        // Create base structure
        fs::create_dir_all(base_dir.join(KEYS_DIR_NAME)).expect("failed to create keys dir");
        fs::write(base_dir.join(KEYS_DIR_NAME).join("default.enc"), b"data")
            .expect("failed to write key");

        // Create config with policy
        let config_content = r#"
[server]
socket_path = "~/.sello/sello.sock"
timeout_secs = 30

[keys]
directory = "~/.sello/keys"
default_key = "default"

[policy]
whitelist_enabled = true
whitelist = ["0xAAA", "0xBBB"]
blacklist = ["0xCCC"]

[policy.transaction_limits]
ETH = "1000000000000000000"

[policy.daily_limits]
ETH = "10000000000000000000"
USDC = "10000000000"
"#;
        fs::write(base_dir.join(CONFIG_FILE_NAME), config_content).expect("failed to write config");

        let cmd = StatusCommand::new();
        let result = cmd.run_with_base_dir(base_dir);

        assert!(result.is_ok());
        let output = result.expect("should succeed");

        assert!(output.policy_summary.whitelist_enabled);
        assert_eq!(output.policy_summary.whitelist_count, 2);
        assert_eq!(output.policy_summary.blacklist_count, 1);
        assert_eq!(output.policy_summary.tx_limit_count, 1);
        assert_eq!(output.policy_summary.daily_limit_count, 2);
    }

    // ------------------------------------------------------------------------
    // Error Display Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_status_error_display() {
        assert_eq!(
            StatusError::NotInitialized.to_string(),
            "Sello is not initialized. Run 'sello init' first."
        );

        let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "access denied");
        let status_err = StatusError::Io(io_err);
        assert!(status_err.to_string().contains("IO error"));

        let history_err = StatusError::History("database error".to_string());
        assert_eq!(history_err.to_string(), "History error: database error");
    }

    #[test]
    fn test_status_error_from_config_error() {
        let config_err = ConfigError::file_not_found("/path/to/config.toml");
        let status_err: StatusError = config_err.into();

        assert!(matches!(status_err, StatusError::ConfigError(_)));
        assert!(status_err
            .to_string()
            .contains("Failed to load configuration"));
    }

    // ------------------------------------------------------------------------
    // Thread Safety Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_status_command_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<StatusCommand>();
    }

    #[test]
    fn test_status_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<StatusError>();
    }

    #[test]
    fn test_policy_summary_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<PolicySummary>();
    }

    // ------------------------------------------------------------------------
    // Display Path Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_format_display_path_with_home() {
        if let Some(home) = dirs::home_dir() {
            let path = home.join("test").join("path");
            let display = format_display_path(&path);
            assert!(display.starts_with("~/"));
            assert!(display.contains("test"));
            assert!(display.contains("path"));
        }
    }

    #[test]
    fn test_format_display_path_without_home() {
        let path = Path::new("/etc/sello/config.toml");
        let display = format_display_path(path);
        assert_eq!(display, "/etc/sello/config.toml");
    }
}
