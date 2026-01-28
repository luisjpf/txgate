//! Configuration types for the `TxGate` signing service.
//!
//! This module provides the configuration structures for defining the behavior
//! of the `TxGate` daemon, including server settings, key storage configuration,
//! and policy rules.
//!
//! # Configuration File
//!
//! Configuration is stored in TOML format at `~/.txgate/config.toml`.
//!
//! # Examples
//!
//! ```
//! use txgate_core::config::{Config, ServerConfig, KeysConfig};
//!
//! // Create a default configuration
//! let config = Config::default();
//! assert_eq!(config.server.socket_path, "~/.txgate/txgate.sock");
//! assert_eq!(config.server.timeout_secs, 30);
//!
//! // Generate default TOML
//! let toml_str = Config::default_toml();
//! println!("{}", toml_str);
//! ```
//!
//! # Default TOML Output
//!
//! ```toml
//! [server]
//! socket_path = "~/.txgate/txgate.sock"
//! timeout_secs = 30
//!
//! [keys]
//! directory = "~/.txgate/keys"
//! default_key = "default"
//!
//! [policy]
//! whitelist_enabled = false
//! whitelist = []
//! blacklist = []
//!
//! [policy.transaction_limits]
//! # ETH = "1000000000000000000"  # 1 ETH
//!
//! [policy.daily_limits]
//! # ETH = "10000000000000000000"  # 10 ETH
//! ```

use crate::error::{ConfigError, PolicyError};
use alloy_primitives::U256;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Top-level configuration for the `TxGate` signing service.
///
/// This struct contains all configuration sections for the `TxGate` daemon:
///
/// - **Server**: Unix socket path and request timeout settings
/// - **Keys**: Key storage directory and default key name
/// - **Policy**: Transaction approval rules (whitelist, blacklist, limits)
///
/// # Examples
///
/// ```
/// use txgate_core::config::Config;
///
/// // Load from TOML string
/// let toml_str = r#"
/// [server]
/// socket_path = "/var/run/txgate.sock"
/// timeout_secs = 60
///
/// [keys]
/// directory = "/var/lib/txgate/keys"
/// default_key = "main"
///
/// [policy]
/// whitelist_enabled = true
/// whitelist = ["0x742d35Cc6634C0532925a3b844Bc454e7595f"]
/// "#;
///
/// let config: Config = toml::from_str(toml_str).expect("valid TOML");
/// assert_eq!(config.server.timeout_secs, 60);
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    /// Server configuration for the `TxGate` daemon.
    #[serde(default)]
    pub server: ServerConfig,

    /// Policy configuration for transaction approval rules.
    #[serde(default)]
    pub policy: PolicyConfig,

    /// Key storage configuration.
    #[serde(default)]
    pub keys: KeysConfig,
}

/// Returns the default Unix socket path for the `TxGate` daemon.
///
/// The default path is `~/.txgate/txgate.sock`.
#[must_use]
fn default_socket_path() -> String {
    "~/.txgate/txgate.sock".to_string()
}

/// Returns the default request timeout in seconds.
///
/// The default timeout is 30 seconds.
#[must_use]
const fn default_timeout() -> u64 {
    30
}

/// Server configuration for the `TxGate` daemon.
///
/// This struct defines how the `TxGate` daemon listens for requests:
///
/// - **Socket path**: The Unix domain socket for IPC communication
/// - **Timeout**: Maximum time to wait for a signing request to complete
///
/// # Security Considerations
///
/// The Unix socket should be protected with appropriate file permissions.
/// By default, only the owning user should have read/write access.
///
/// # Examples
///
/// ```
/// use txgate_core::config::ServerConfig;
///
/// let config = ServerConfig::default();
/// assert_eq!(config.socket_path, "~/.txgate/txgate.sock");
/// assert_eq!(config.timeout_secs, 30);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerConfig {
    /// Unix socket path for the `TxGate` daemon.
    ///
    /// The daemon listens on this socket for incoming signing requests.
    /// The path supports `~` expansion for the home directory.
    ///
    /// Default: `~/.txgate/txgate.sock`
    #[serde(default = "default_socket_path")]
    pub socket_path: String,

    /// Request timeout in seconds.
    ///
    /// Maximum time the daemon will wait for a signing request to complete.
    /// This includes policy evaluation, key loading, and cryptographic operations.
    ///
    /// Default: 30 seconds
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            socket_path: default_socket_path(),
            timeout_secs: default_timeout(),
        }
    }
}

/// Returns the default directory for encrypted key files.
///
/// The default directory is `~/.txgate/keys`.
#[must_use]
fn default_keys_dir() -> String {
    "~/.txgate/keys".to_string()
}

/// Returns the default key name for signing operations.
///
/// The default key name is `"default"`.
#[must_use]
fn default_key_name() -> String {
    "default".to_string()
}

/// Key storage configuration for the `TxGate` signing service.
///
/// This struct defines where encrypted keys are stored and which key
/// to use by default for signing operations.
///
/// # Directory Structure
///
/// Keys are stored as encrypted JSON files in the configured directory:
/// ```text
/// ~/.txgate/keys/
/// ├── default.json
/// ├── backup.json
/// └── production.json
/// ```
///
/// # Security Considerations
///
/// - The keys directory should have restricted permissions (0700)
/// - Key files are encrypted with a password-derived key
/// - Key material is zeroed from memory after use
///
/// # Examples
///
/// ```
/// use txgate_core::config::KeysConfig;
///
/// let config = KeysConfig::default();
/// assert_eq!(config.directory, "~/.txgate/keys");
/// assert_eq!(config.default_key, "default");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeysConfig {
    /// Directory for encrypted key files.
    ///
    /// The path supports `~` expansion for the home directory.
    ///
    /// Default: `~/.txgate/keys`
    #[serde(default = "default_keys_dir")]
    pub directory: String,

    /// Default key name to use for signing.
    ///
    /// This key is used when no specific key is requested.
    ///
    /// Default: `"default"`
    #[serde(default = "default_key_name")]
    pub default_key: String,
}

impl Default for KeysConfig {
    fn default() -> Self {
        Self {
            directory: default_keys_dir(),
            default_key: default_key_name(),
        }
    }
}

/// Policy configuration for transaction approval rules.
///
/// This struct defines the rules that govern which transactions are allowed
/// or denied by the policy engine. It supports:
///
/// - **Whitelist**: Addresses that are always allowed (when enabled)
/// - **Blacklist**: Addresses that are always denied
/// - **Transaction limits**: Maximum amount per single transaction
/// - **Daily limits**: Maximum total amount per 24-hour period
///
/// # Address Handling
///
/// Address comparisons are case-insensitive for Ethereum-style addresses.
/// This ensures that `0xABC` and `0xabc` are treated as the same address.
///
/// # Security Considerations
///
/// - An address cannot be in both whitelist and blacklist
/// - Blacklist takes precedence if both checks are enabled
/// - Transaction limits are enforced per token/currency
///
/// # Examples
///
/// ```
/// use txgate_core::config::PolicyConfig;
///
/// let config = PolicyConfig {
///     whitelist_enabled: true,
///     whitelist: vec!["0x1234...".to_string()],
///     blacklist: vec!["0xdead...".to_string()],
///     ..Default::default()
/// };
///
/// assert!(config.validate().is_ok());
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyConfig {
    /// Addresses that are always allowed (if whitelist is enabled).
    ///
    /// When `whitelist_enabled` is `true`, only addresses in this list
    /// are permitted as transaction recipients.
    #[serde(default)]
    pub whitelist: Vec<String>,

    /// Addresses that are always denied.
    ///
    /// Transactions to any address in this list will be rejected,
    /// regardless of whitelist status.
    #[serde(default)]
    pub blacklist: Vec<String>,

    /// Per-token transaction limits (max amount per single tx).
    ///
    /// Key: token address or "ETH" for native token.
    /// Value: maximum amount in the token's smallest unit (wei, etc.).
    ///
    /// # Examples
    ///
    /// ```
    /// use txgate_core::config::PolicyConfig;
    /// use alloy_primitives::U256;
    /// use std::collections::HashMap;
    ///
    /// let mut limits = HashMap::new();
    /// limits.insert("ETH".to_string(), U256::from(5_000_000_000_000_000_000u64)); // 5 ETH
    ///
    /// let config = PolicyConfig {
    ///     transaction_limits: limits,
    ///     ..Default::default()
    /// };
    /// ```
    #[serde(default)]
    pub transaction_limits: HashMap<String, U256>,

    /// Per-token daily limits (max total amount per 24h).
    ///
    /// Key: token address or "ETH" for native token.
    /// Value: maximum daily total in the token's smallest unit (wei, etc.).
    ///
    /// Note: Actual daily limit tracking requires a stateful tracker component
    /// that is not part of this configuration struct.
    #[serde(default)]
    pub daily_limits: HashMap<String, U256>,

    /// Whether whitelist is enabled.
    ///
    /// - `true`: Only addresses in `whitelist` are allowed
    /// - `false`: All addresses except those in `blacklist` are allowed
    #[serde(default)]
    pub whitelist_enabled: bool,
}

impl PolicyConfig {
    /// Creates a new empty policy configuration.
    ///
    /// All lists are empty and whitelist is disabled by default.
    ///
    /// # Examples
    ///
    /// ```
    /// use txgate_core::config::PolicyConfig;
    ///
    /// let config = PolicyConfig::new();
    /// assert!(!config.whitelist_enabled);
    /// assert!(config.whitelist.is_empty());
    /// assert!(config.blacklist.is_empty());
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Checks if an address is in the whitelist.
    ///
    /// Address comparison is case-insensitive.
    ///
    /// # Arguments
    ///
    /// * `address` - The address to check
    ///
    /// # Returns
    ///
    /// `true` if the address is in the whitelist, `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// use txgate_core::config::PolicyConfig;
    ///
    /// let config = PolicyConfig::new()
    ///     .with_whitelist(vec!["0xABC123".to_string()]);
    ///
    /// assert!(config.is_whitelisted("0xABC123"));
    /// assert!(config.is_whitelisted("0xabc123")); // Case insensitive
    /// assert!(!config.is_whitelisted("0xDEF456"));
    /// ```
    #[must_use]
    pub fn is_whitelisted(&self, address: &str) -> bool {
        let address_lower = address.to_lowercase();
        self.whitelist
            .iter()
            .any(|a| a.to_lowercase() == address_lower)
    }

    /// Checks if an address is in the blacklist.
    ///
    /// Address comparison is case-insensitive.
    ///
    /// # Arguments
    ///
    /// * `address` - The address to check
    ///
    /// # Returns
    ///
    /// `true` if the address is in the blacklist, `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// use txgate_core::config::PolicyConfig;
    ///
    /// let config = PolicyConfig::new()
    ///     .with_blacklist(vec!["0xDEAD".to_string()]);
    ///
    /// assert!(config.is_blacklisted("0xDEAD"));
    /// assert!(config.is_blacklisted("0xdead")); // Case insensitive
    /// assert!(!config.is_blacklisted("0xABC123"));
    /// ```
    #[must_use]
    pub fn is_blacklisted(&self, address: &str) -> bool {
        let address_lower = address.to_lowercase();
        self.blacklist
            .iter()
            .any(|a| a.to_lowercase() == address_lower)
    }

    /// Gets the per-transaction limit for a token.
    ///
    /// Token key comparison is case-insensitive.
    ///
    /// # Arguments
    ///
    /// * `token` - The token identifier (e.g., "ETH" or a contract address)
    ///
    /// # Returns
    ///
    /// The transaction limit if configured, `None` if no limit is set.
    ///
    /// # Examples
    ///
    /// ```
    /// use txgate_core::config::PolicyConfig;
    /// use alloy_primitives::U256;
    ///
    /// let config = PolicyConfig::new()
    ///     .with_transaction_limit("ETH", U256::from(5_000_000_000_000_000_000u64));
    ///
    /// assert_eq!(
    ///     config.get_transaction_limit("ETH"),
    ///     Some(U256::from(5_000_000_000_000_000_000u64))
    /// );
    /// assert_eq!(config.get_transaction_limit("eth"), Some(U256::from(5_000_000_000_000_000_000u64))); // Case insensitive
    /// assert!(config.get_transaction_limit("BTC").is_none());
    /// ```
    #[must_use]
    pub fn get_transaction_limit(&self, token: &str) -> Option<U256> {
        let token_lower = token.to_lowercase();
        self.transaction_limits
            .iter()
            .find(|(k, _)| k.to_lowercase() == token_lower)
            .map(|(_, v)| *v)
    }

    /// Gets the daily limit for a token.
    ///
    /// Token key comparison is case-insensitive.
    ///
    /// # Arguments
    ///
    /// * `token` - The token identifier (e.g., "ETH" or a contract address)
    ///
    /// # Returns
    ///
    /// The daily limit if configured, `None` if no limit is set.
    ///
    /// # Examples
    ///
    /// ```
    /// use txgate_core::config::PolicyConfig;
    /// use alloy_primitives::U256;
    ///
    /// let config = PolicyConfig::new()
    ///     .with_daily_limit("ETH", U256::from(10_000_000_000_000_000_000u64));
    ///
    /// assert_eq!(
    ///     config.get_daily_limit("ETH"),
    ///     Some(U256::from(10_000_000_000_000_000_000u64))
    /// );
    /// assert!(config.get_daily_limit("BTC").is_none());
    /// ```
    #[must_use]
    pub fn get_daily_limit(&self, token: &str) -> Option<U256> {
        let token_lower = token.to_lowercase();
        self.daily_limits
            .iter()
            .find(|(k, _)| k.to_lowercase() == token_lower)
            .map(|(_, v)| *v)
    }

    /// Validates the policy configuration.
    ///
    /// Checks for configuration errors such as:
    /// - Addresses appearing in both whitelist and blacklist
    ///
    /// # Returns
    ///
    /// `Ok(())` if the configuration is valid, or a `PolicyError` describing the issue.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::InvalidConfiguration`] if:
    /// - An address appears in both the whitelist and blacklist (case-insensitive)
    ///
    /// # Examples
    ///
    /// ```
    /// use txgate_core::config::PolicyConfig;
    ///
    /// // Valid config - no overlap
    /// let valid = PolicyConfig::new()
    ///     .with_whitelist(vec!["0xAAA".to_string()])
    ///     .with_blacklist(vec!["0xBBB".to_string()]);
    /// assert!(valid.validate().is_ok());
    ///
    /// // Invalid config - same address in both lists
    /// let invalid = PolicyConfig::new()
    ///     .with_whitelist(vec!["0xAAA".to_string()])
    ///     .with_blacklist(vec!["0xAAA".to_string()]);
    /// assert!(invalid.validate().is_err());
    /// ```
    pub fn validate(&self) -> Result<(), PolicyError> {
        // Check for overlapping addresses between whitelist and blacklist
        for whitelist_addr in &self.whitelist {
            let whitelist_lower = whitelist_addr.to_lowercase();
            for blacklist_addr in &self.blacklist {
                if blacklist_addr.to_lowercase() == whitelist_lower {
                    return Err(PolicyError::invalid_configuration(format!(
                        "address '{whitelist_addr}' appears in both whitelist and blacklist"
                    )));
                }
            }
        }

        Ok(())
    }

    /// Builder method to set the whitelist.
    ///
    /// This enables the whitelist automatically.
    ///
    /// # Arguments
    ///
    /// * `addresses` - List of addresses to whitelist
    ///
    /// # Examples
    ///
    /// ```
    /// use txgate_core::config::PolicyConfig;
    ///
    /// let config = PolicyConfig::new()
    ///     .with_whitelist(vec!["0xAAA".to_string(), "0xBBB".to_string()]);
    ///
    /// assert!(config.whitelist_enabled);
    /// assert_eq!(config.whitelist.len(), 2);
    /// ```
    #[must_use]
    pub fn with_whitelist(mut self, addresses: Vec<String>) -> Self {
        self.whitelist = addresses;
        self.whitelist_enabled = true;
        self
    }

    /// Builder method to set the blacklist.
    ///
    /// # Arguments
    ///
    /// * `addresses` - List of addresses to blacklist
    ///
    /// # Examples
    ///
    /// ```
    /// use txgate_core::config::PolicyConfig;
    ///
    /// let config = PolicyConfig::new()
    ///     .with_blacklist(vec!["0xDEAD".to_string()]);
    ///
    /// assert_eq!(config.blacklist.len(), 1);
    /// ```
    #[must_use]
    pub fn with_blacklist(mut self, addresses: Vec<String>) -> Self {
        self.blacklist = addresses;
        self
    }

    /// Builder method to add a per-transaction limit for a token.
    ///
    /// # Arguments
    ///
    /// * `token` - Token identifier (e.g., "ETH" or contract address)
    /// * `limit` - Maximum amount per transaction
    ///
    /// # Examples
    ///
    /// ```
    /// use txgate_core::config::PolicyConfig;
    /// use alloy_primitives::U256;
    ///
    /// let config = PolicyConfig::new()
    ///     .with_transaction_limit("ETH", U256::from(5_000_000_000_000_000_000u64))
    ///     .with_transaction_limit("USDC", U256::from(10_000_000_000u64)); // 10k USDC
    ///
    /// assert!(config.get_transaction_limit("ETH").is_some());
    /// assert!(config.get_transaction_limit("USDC").is_some());
    /// ```
    #[must_use]
    pub fn with_transaction_limit(mut self, token: &str, limit: U256) -> Self {
        self.transaction_limits.insert(token.to_string(), limit);
        self
    }

    /// Builder method to add a daily limit for a token.
    ///
    /// # Arguments
    ///
    /// * `token` - Token identifier (e.g., "ETH" or contract address)
    /// * `limit` - Maximum total amount per 24-hour period
    ///
    /// # Examples
    ///
    /// ```
    /// use txgate_core::config::PolicyConfig;
    /// use alloy_primitives::U256;
    ///
    /// let config = PolicyConfig::new()
    ///     .with_daily_limit("ETH", U256::from(10_000_000_000_000_000_000u64));
    ///
    /// assert!(config.get_daily_limit("ETH").is_some());
    /// ```
    #[must_use]
    pub fn with_daily_limit(mut self, token: &str, limit: U256) -> Self {
        self.daily_limits.insert(token.to_string(), limit);
        self
    }

    /// Builder method to enable or disable whitelist mode.
    ///
    /// # Arguments
    ///
    /// * `enabled` - Whether whitelist mode should be enabled
    ///
    /// # Examples
    ///
    /// ```
    /// use txgate_core::config::PolicyConfig;
    ///
    /// let config = PolicyConfig::new()
    ///     .with_whitelist_enabled(false);
    ///
    /// assert!(!config.whitelist_enabled);
    /// ```
    #[must_use]
    pub const fn with_whitelist_enabled(mut self, enabled: bool) -> Self {
        self.whitelist_enabled = enabled;
        self
    }
}

impl Config {
    /// Creates a new configuration with default values.
    ///
    /// # Examples
    ///
    /// ```
    /// use txgate_core::config::Config;
    ///
    /// let config = Config::new();
    /// assert_eq!(config.server.timeout_secs, 30);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Validates the configuration.
    ///
    /// This method checks for configuration errors such as:
    /// - Invalid socket path (empty)
    /// - Invalid timeout (zero)
    /// - Invalid keys directory (empty)
    /// - Invalid default key name (empty)
    /// - Invalid policy configuration (whitelist/blacklist overlap)
    ///
    /// # Returns
    ///
    /// `Ok(())` if the configuration is valid, or a `ConfigError` describing the issue.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::InvalidValue`] if:
    /// - `server.socket_path` is empty
    /// - `server.timeout_secs` is zero
    /// - `keys.directory` is empty
    /// - `keys.default_key` is empty
    ///
    /// Returns a wrapped [`PolicyError`] (via [`ConfigError::ParseFailed`]) if:
    /// - An address appears in both the whitelist and blacklist
    ///
    /// # Examples
    ///
    /// ```
    /// use txgate_core::config::Config;
    ///
    /// let config = Config::default();
    /// assert!(config.validate().is_ok());
    ///
    /// // Invalid: empty socket path
    /// let mut invalid_config = Config::default();
    /// invalid_config.server.socket_path = String::new();
    /// assert!(invalid_config.validate().is_err());
    /// ```
    ///
    /// [`PolicyError`]: crate::error::PolicyError
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Validate server configuration
        if self.server.socket_path.is_empty() {
            return Err(ConfigError::invalid_value("server.socket_path", "<empty>"));
        }

        if self.server.timeout_secs == 0 {
            return Err(ConfigError::invalid_value("server.timeout_secs", "0"));
        }

        // Validate keys configuration
        if self.keys.directory.is_empty() {
            return Err(ConfigError::invalid_value("keys.directory", "<empty>"));
        }

        if self.keys.default_key.is_empty() {
            return Err(ConfigError::invalid_value("keys.default_key", "<empty>"));
        }

        // Validate policy configuration
        self.policy
            .validate()
            .map_err(|e| ConfigError::parse_failed(format!("policy validation failed: {e}")))?;

        Ok(())
    }

    /// Generates the default configuration as a TOML string.
    ///
    /// This method produces a well-formatted TOML configuration file with
    /// comments explaining each section. It can be used to create an initial
    /// configuration file for new installations.
    ///
    /// # Returns
    ///
    /// A TOML-formatted string containing the default configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// use txgate_core::config::Config;
    ///
    /// let toml = Config::default_toml();
    /// assert!(toml.contains("[server]"));
    /// assert!(toml.contains("[keys]"));
    /// assert!(toml.contains("[policy]"));
    /// ```
    #[must_use]
    pub fn default_toml() -> String {
        r#"[server]
socket_path = "~/.txgate/txgate.sock"
timeout_secs = 30

[keys]
directory = "~/.txgate/keys"
default_key = "default"

[policy]
whitelist_enabled = false
whitelist = []
blacklist = []

[policy.transaction_limits]
# ETH = "1000000000000000000"  # 1 ETH

[policy.daily_limits]
# ETH = "10000000000000000000"  # 10 ETH
"#
        .to_string()
    }

    /// Creates a configuration builder for customizing values.
    ///
    /// # Examples
    ///
    /// ```
    /// use txgate_core::config::Config;
    ///
    /// let config = Config::builder()
    ///     .socket_path("/var/run/txgate.sock")
    ///     .timeout_secs(60)
    ///     .build();
    ///
    /// assert_eq!(config.server.socket_path, "/var/run/txgate.sock");
    /// ```
    #[must_use]
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder::new()
    }
}

/// Builder for creating customized [`Config`] instances.
///
/// This builder provides a fluent API for constructing configuration
/// objects with non-default values.
///
/// # Examples
///
/// ```
/// use txgate_core::config::{Config, ConfigBuilder};
///
/// let config = ConfigBuilder::new()
///     .socket_path("/custom/path.sock")
///     .timeout_secs(120)
///     .keys_directory("/custom/keys")
///     .default_key("production")
///     .build();
///
/// assert_eq!(config.server.socket_path, "/custom/path.sock");
/// assert_eq!(config.server.timeout_secs, 120);
/// assert_eq!(config.keys.directory, "/custom/keys");
/// assert_eq!(config.keys.default_key, "production");
/// ```
#[derive(Debug, Clone, Default)]
pub struct ConfigBuilder {
    config: Config,
}

impl ConfigBuilder {
    /// Creates a new configuration builder with default values.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: Config::default(),
        }
    }

    /// Sets the Unix socket path.
    ///
    /// # Arguments
    ///
    /// * `path` - The socket path to use
    #[must_use]
    pub fn socket_path(mut self, path: impl Into<String>) -> Self {
        self.config.server.socket_path = path.into();
        self
    }

    /// Sets the request timeout in seconds.
    ///
    /// # Arguments
    ///
    /// * `secs` - The timeout value in seconds
    #[must_use]
    pub const fn timeout_secs(mut self, secs: u64) -> Self {
        self.config.server.timeout_secs = secs;
        self
    }

    /// Sets the keys directory.
    ///
    /// # Arguments
    ///
    /// * `dir` - The directory path for key storage
    #[must_use]
    pub fn keys_directory(mut self, dir: impl Into<String>) -> Self {
        self.config.keys.directory = dir.into();
        self
    }

    /// Sets the default key name.
    ///
    /// # Arguments
    ///
    /// * `name` - The default key name
    #[must_use]
    pub fn default_key(mut self, name: impl Into<String>) -> Self {
        self.config.keys.default_key = name.into();
        self
    }

    /// Sets the policy configuration.
    ///
    /// # Arguments
    ///
    /// * `policy` - The policy configuration to use
    #[must_use]
    pub fn policy(mut self, policy: PolicyConfig) -> Self {
        self.config.policy = policy;
        self
    }

    /// Builds the final configuration.
    ///
    /// # Returns
    ///
    /// The configured [`Config`] instance.
    #[must_use]
    pub fn build(self) -> Config {
        self.config
    }
}

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
        clippy::unreadable_literal
    )]

    use super::*;

    // -------------------------------------------------------------------------
    // Config basic tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_config_default() {
        let config = Config::default();

        assert_eq!(config.server.socket_path, "~/.txgate/txgate.sock");
        assert_eq!(config.server.timeout_secs, 30);
        assert_eq!(config.keys.directory, "~/.txgate/keys");
        assert_eq!(config.keys.default_key, "default");
        assert!(!config.policy.whitelist_enabled);
        assert!(config.policy.whitelist.is_empty());
        assert!(config.policy.blacklist.is_empty());
    }

    #[test]
    fn test_config_new() {
        let config = Config::new();
        assert_eq!(config, Config::default());
    }

    // -------------------------------------------------------------------------
    // ServerConfig tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_server_config_default() {
        let config = ServerConfig::default();

        assert_eq!(config.socket_path, "~/.txgate/txgate.sock");
        assert_eq!(config.timeout_secs, 30);
    }

    #[test]
    fn test_server_config_custom() {
        let config = ServerConfig {
            socket_path: "/var/run/txgate.sock".to_string(),
            timeout_secs: 60,
        };

        assert_eq!(config.socket_path, "/var/run/txgate.sock");
        assert_eq!(config.timeout_secs, 60);
    }

    // -------------------------------------------------------------------------
    // KeysConfig tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_keys_config_default() {
        let config = KeysConfig::default();

        assert_eq!(config.directory, "~/.txgate/keys");
        assert_eq!(config.default_key, "default");
    }

    #[test]
    fn test_keys_config_custom() {
        let config = KeysConfig {
            directory: "/var/lib/txgate/keys".to_string(),
            default_key: "production".to_string(),
        };

        assert_eq!(config.directory, "/var/lib/txgate/keys");
        assert_eq!(config.default_key, "production");
    }

    // -------------------------------------------------------------------------
    // PolicyConfig tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_policy_config_default() {
        let config = PolicyConfig::default();

        assert!(config.whitelist.is_empty());
        assert!(config.blacklist.is_empty());
        assert!(config.transaction_limits.is_empty());
        assert!(config.daily_limits.is_empty());
        assert!(!config.whitelist_enabled);
    }

    #[test]
    fn test_policy_config_new() {
        let config = PolicyConfig::new();
        assert_eq!(config, PolicyConfig::default());
    }

    #[test]
    fn test_policy_is_whitelisted() {
        let config = PolicyConfig::new().with_whitelist(vec!["0xABC123".to_string()]);

        assert!(config.is_whitelisted("0xABC123"));
        assert!(config.is_whitelisted("0xabc123")); // Case insensitive
        assert!(!config.is_whitelisted("0xDEF456"));
    }

    #[test]
    fn test_policy_is_blacklisted() {
        let config = PolicyConfig::new().with_blacklist(vec!["0xDEAD".to_string()]);

        assert!(config.is_blacklisted("0xDEAD"));
        assert!(config.is_blacklisted("0xdead")); // Case insensitive
        assert!(!config.is_blacklisted("0xABC123"));
    }

    #[test]
    fn test_policy_transaction_limit() {
        let config = PolicyConfig::new()
            .with_transaction_limit("ETH", U256::from(5_000_000_000_000_000_000u64));

        assert_eq!(
            config.get_transaction_limit("ETH"),
            Some(U256::from(5_000_000_000_000_000_000u64))
        );
        assert_eq!(
            config.get_transaction_limit("eth"),
            Some(U256::from(5_000_000_000_000_000_000u64))
        );
        assert!(config.get_transaction_limit("BTC").is_none());
    }

    #[test]
    fn test_policy_daily_limit() {
        let config =
            PolicyConfig::new().with_daily_limit("ETH", U256::from(10_000_000_000_000_000_000u64));

        assert_eq!(
            config.get_daily_limit("ETH"),
            Some(U256::from(10_000_000_000_000_000_000u64))
        );
        assert!(config.get_daily_limit("BTC").is_none());
    }

    #[test]
    fn test_policy_validate_passes() {
        let config = PolicyConfig::new()
            .with_whitelist(vec!["0xAAA".to_string()])
            .with_blacklist(vec!["0xBBB".to_string()]);

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_policy_validate_fails_overlap() {
        let config = PolicyConfig::new()
            .with_whitelist(vec!["0xAAA".to_string()])
            .with_blacklist(vec!["0xAAA".to_string()]);

        assert!(config.validate().is_err());
    }

    #[test]
    fn test_policy_validate_fails_case_insensitive_overlap() {
        let config = PolicyConfig::new()
            .with_whitelist(vec!["0xABC".to_string()])
            .with_blacklist(vec!["0xabc".to_string()]);

        assert!(config.validate().is_err());
    }

    // -------------------------------------------------------------------------
    // Validation tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_validate_passes_for_default_config() {
        let config = Config::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_fails_for_empty_socket_path() {
        let mut config = Config::default();
        config.server.socket_path = String::new();

        let result = config.validate();
        assert!(result.is_err());

        let err = result.expect_err("should have error");
        assert!(matches!(err, ConfigError::InvalidValue { .. }));
        assert!(err.to_string().contains("socket_path"));
    }

    #[test]
    fn test_validate_fails_for_zero_timeout() {
        let mut config = Config::default();
        config.server.timeout_secs = 0;

        let result = config.validate();
        assert!(result.is_err());

        let err = result.expect_err("should have error");
        assert!(matches!(err, ConfigError::InvalidValue { .. }));
        assert!(err.to_string().contains("timeout_secs"));
    }

    #[test]
    fn test_validate_fails_for_empty_keys_directory() {
        let mut config = Config::default();
        config.keys.directory = String::new();

        let result = config.validate();
        assert!(result.is_err());

        let err = result.expect_err("should have error");
        assert!(matches!(err, ConfigError::InvalidValue { .. }));
        assert!(err.to_string().contains("directory"));
    }

    #[test]
    fn test_validate_fails_for_empty_default_key() {
        let mut config = Config::default();
        config.keys.default_key = String::new();

        let result = config.validate();
        assert!(result.is_err());

        let err = result.expect_err("should have error");
        assert!(matches!(err, ConfigError::InvalidValue { .. }));
        assert!(err.to_string().contains("default_key"));
    }

    #[test]
    fn test_validate_fails_for_invalid_policy() {
        let mut config = Config::default();
        config.policy.whitelist = vec!["0xAAA".to_string()];
        config.policy.blacklist = vec!["0xAAA".to_string()];

        let result = config.validate();
        assert!(result.is_err());

        let err = result.expect_err("should have error");
        assert!(matches!(err, ConfigError::ParseFailed { .. }));
        assert!(err.to_string().contains("policy validation failed"));
    }

    // -------------------------------------------------------------------------
    // TOML serialization tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_toml_serialization_roundtrip() {
        let original = Config::default();

        let toml_str = toml::to_string(&original).expect("TOML serialization failed");
        let deserialized: Config = toml::from_str(&toml_str).expect("TOML deserialization failed");

        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_toml_deserialization_with_defaults() {
        let toml_str = r#"
            [server]
            socket_path = "/custom/path.sock"
        "#;

        let config: Config = toml::from_str(toml_str).expect("TOML deserialization failed");

        assert_eq!(config.server.socket_path, "/custom/path.sock");
        assert_eq!(config.server.timeout_secs, 30); // default
        assert_eq!(config.keys.directory, "~/.txgate/keys"); // default
        assert_eq!(config.keys.default_key, "default"); // default
    }

    #[test]
    fn test_toml_deserialization_empty_config() {
        let toml_str = "";
        let config: Config = toml::from_str(toml_str).expect("TOML deserialization failed");

        assert_eq!(config, Config::default());
    }

    #[test]
    fn test_toml_deserialization_missing_sections() {
        // Only server section present
        let toml_str = r#"
            [server]
            socket_path = "/var/run/txgate.sock"
            timeout_secs = 60
        "#;

        let config: Config = toml::from_str(toml_str).expect("TOML deserialization failed");

        assert_eq!(config.server.socket_path, "/var/run/txgate.sock");
        assert_eq!(config.server.timeout_secs, 60);
        // Keys and policy should use defaults
        assert_eq!(config.keys, KeysConfig::default());
        assert_eq!(config.policy, PolicyConfig::default());
    }

    #[test]
    fn test_toml_deserialization_partial_sections() {
        let toml_str = r#"
            [server]
            timeout_secs = 120

            [keys]
            default_key = "prod"
        "#;

        let config: Config = toml::from_str(toml_str).expect("TOML deserialization failed");

        // Only specified values should override defaults
        assert_eq!(config.server.socket_path, "~/.txgate/txgate.sock"); // default
        assert_eq!(config.server.timeout_secs, 120);
        assert_eq!(config.keys.directory, "~/.txgate/keys"); // default
        assert_eq!(config.keys.default_key, "prod");
    }

    #[test]
    fn test_toml_deserialization_full_config() {
        let toml_str = r#"
            [server]
            socket_path = "/var/run/txgate.sock"
            timeout_secs = 60

            [keys]
            directory = "/var/lib/txgate/keys"
            default_key = "production"

            [policy]
            whitelist_enabled = true
            whitelist = ["0x742d35Cc6634C0532925a3b844Bc454e7595f"]
            blacklist = ["0xDEADBEEF"]
        "#;

        let config: Config = toml::from_str(toml_str).expect("TOML deserialization failed");

        assert_eq!(config.server.socket_path, "/var/run/txgate.sock");
        assert_eq!(config.server.timeout_secs, 60);
        assert_eq!(config.keys.directory, "/var/lib/txgate/keys");
        assert_eq!(config.keys.default_key, "production");
        assert!(config.policy.whitelist_enabled);
        assert_eq!(
            config.policy.whitelist,
            vec!["0x742d35Cc6634C0532925a3b844Bc454e7595f"]
        );
        assert_eq!(config.policy.blacklist, vec!["0xDEADBEEF"]);
    }

    #[test]
    fn test_toml_with_policy_limits() {
        let toml_str = r#"
            [policy]
            whitelist_enabled = false

            [policy.transaction_limits]
            ETH = "1000000000000000000"

            [policy.daily_limits]
            ETH = "10000000000000000000"
        "#;

        let config: Config = toml::from_str(toml_str).expect("TOML deserialization failed");

        assert_eq!(
            config.policy.get_transaction_limit("ETH"),
            Some(U256::from(1_000_000_000_000_000_000u64))
        );
        assert_eq!(
            config.policy.get_daily_limit("ETH"),
            Some(U256::from(10_000_000_000_000_000_000u64))
        );
    }

    // -------------------------------------------------------------------------
    // default_toml() tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_default_toml_contains_all_sections() {
        let toml = Config::default_toml();

        assert!(toml.contains("[server]"));
        assert!(toml.contains("[keys]"));
        assert!(toml.contains("[policy]"));
        assert!(toml.contains("[policy.transaction_limits]"));
        assert!(toml.contains("[policy.daily_limits]"));
    }

    #[test]
    fn test_default_toml_contains_default_values() {
        let toml = Config::default_toml();

        assert!(toml.contains("socket_path = \"~/.txgate/txgate.sock\""));
        assert!(toml.contains("timeout_secs = 30"));
        assert!(toml.contains("directory = \"~/.txgate/keys\""));
        assert!(toml.contains("default_key = \"default\""));
        assert!(toml.contains("whitelist_enabled = false"));
    }

    #[test]
    fn test_default_toml_is_parseable() {
        let toml_str = Config::default_toml();
        let config: Config = toml::from_str(&toml_str).expect("default TOML should be parseable");

        // Verify it produces the expected default config
        assert_eq!(config.server.socket_path, "~/.txgate/txgate.sock");
        assert_eq!(config.server.timeout_secs, 30);
    }

    // -------------------------------------------------------------------------
    // Builder tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_builder_default() {
        let config = ConfigBuilder::new().build();
        assert_eq!(config, Config::default());
    }

    #[test]
    fn test_builder_socket_path() {
        let config = Config::builder().socket_path("/custom/path.sock").build();

        assert_eq!(config.server.socket_path, "/custom/path.sock");
    }

    #[test]
    fn test_builder_timeout_secs() {
        let config = Config::builder().timeout_secs(120).build();

        assert_eq!(config.server.timeout_secs, 120);
    }

    #[test]
    fn test_builder_keys_directory() {
        let config = Config::builder().keys_directory("/custom/keys").build();

        assert_eq!(config.keys.directory, "/custom/keys");
    }

    #[test]
    fn test_builder_default_key() {
        let config = Config::builder().default_key("production").build();

        assert_eq!(config.keys.default_key, "production");
    }

    #[test]
    fn test_builder_policy() {
        let policy = PolicyConfig::new()
            .with_whitelist(vec!["0xAAA".to_string()])
            .with_transaction_limit("ETH", U256::from(1_000_000u64));

        let config = Config::builder().policy(policy.clone()).build();

        assert_eq!(config.policy, policy);
    }

    #[test]
    fn test_builder_chain() {
        let config = Config::builder()
            .socket_path("/var/run/txgate.sock")
            .timeout_secs(60)
            .keys_directory("/var/lib/txgate/keys")
            .default_key("main")
            .build();

        assert_eq!(config.server.socket_path, "/var/run/txgate.sock");
        assert_eq!(config.server.timeout_secs, 60);
        assert_eq!(config.keys.directory, "/var/lib/txgate/keys");
        assert_eq!(config.keys.default_key, "main");
    }

    // -------------------------------------------------------------------------
    // Clone and equality tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_config_clone() {
        let original = Config::builder()
            .socket_path("/custom/path.sock")
            .timeout_secs(60)
            .build();

        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn test_config_equality() {
        let config1 = Config::builder()
            .socket_path("/path1.sock")
            .timeout_secs(30)
            .build();

        let config2 = Config::builder()
            .socket_path("/path1.sock")
            .timeout_secs(30)
            .build();

        assert_eq!(config1, config2);
    }

    #[test]
    fn test_config_inequality() {
        let config1 = Config::builder().socket_path("/path1.sock").build();

        let config2 = Config::builder().socket_path("/path2.sock").build();

        assert_ne!(config1, config2);
    }

    // -------------------------------------------------------------------------
    // Debug format tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_config_debug() {
        let config = Config::default();
        let debug_str = format!("{config:?}");

        assert!(debug_str.contains("Config"));
        assert!(debug_str.contains("server"));
        assert!(debug_str.contains("policy"));
        assert!(debug_str.contains("keys"));
    }

    #[test]
    fn test_server_config_debug() {
        let config = ServerConfig::default();
        let debug_str = format!("{config:?}");

        assert!(debug_str.contains("ServerConfig"));
        assert!(debug_str.contains("socket_path"));
        assert!(debug_str.contains("timeout_secs"));
    }

    #[test]
    fn test_keys_config_debug() {
        let config = KeysConfig::default();
        let debug_str = format!("{config:?}");

        assert!(debug_str.contains("KeysConfig"));
        assert!(debug_str.contains("directory"));
        assert!(debug_str.contains("default_key"));
    }

    #[test]
    fn test_policy_config_debug() {
        let config = PolicyConfig::default();
        let debug_str = format!("{config:?}");

        assert!(debug_str.contains("PolicyConfig"));
        assert!(debug_str.contains("whitelist"));
        assert!(debug_str.contains("blacklist"));
    }

    // -------------------------------------------------------------------------
    // JSON serialization tests (for API responses)
    // -------------------------------------------------------------------------

    #[test]
    fn test_json_serialization_roundtrip() {
        let original = Config::builder()
            .socket_path("/test.sock")
            .timeout_secs(45)
            .build();

        let json_str = serde_json::to_string(&original).expect("JSON serialization failed");
        let deserialized: Config =
            serde_json::from_str(&json_str).expect("JSON deserialization failed");

        assert_eq!(original, deserialized);
    }

    // -------------------------------------------------------------------------
    // PolicyConfig builder tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_policy_builder_chain() {
        let config = PolicyConfig::new()
            .with_whitelist(vec!["0xWhite".to_string()])
            .with_blacklist(vec!["0xBlack".to_string()])
            .with_transaction_limit("ETH", U256::from(100))
            .with_daily_limit("ETH", U256::from(1000))
            .with_whitelist_enabled(true);

        assert!(config.is_whitelisted("0xWhite"));
        assert!(config.is_blacklisted("0xBlack"));
        assert_eq!(config.get_transaction_limit("ETH"), Some(U256::from(100)));
        assert_eq!(config.get_daily_limit("ETH"), Some(U256::from(1000)));
        assert!(config.whitelist_enabled);
    }

    #[test]
    fn test_policy_with_whitelist_enables_whitelist() {
        let config = PolicyConfig::new().with_whitelist(vec!["0xTest".to_string()]);

        assert!(config.whitelist_enabled);
    }

    #[test]
    fn test_policy_with_whitelist_enabled_can_disable() {
        let config = PolicyConfig::new()
            .with_whitelist(vec!["0xTest".to_string()])
            .with_whitelist_enabled(false);

        assert!(!config.whitelist_enabled);
    }

    // -------------------------------------------------------------------------
    // Edge case tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_policy_empty_address_handling() {
        let config = PolicyConfig::new()
            .with_whitelist(vec!["".to_string()])
            .with_blacklist(vec!["".to_string()]);

        // Empty string in both lists should still cause validation to fail
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_policy_zero_limits() {
        let config = PolicyConfig::new()
            .with_transaction_limit("ETH", U256::ZERO)
            .with_daily_limit("ETH", U256::ZERO);

        assert_eq!(config.get_transaction_limit("ETH"), Some(U256::ZERO));
        assert_eq!(config.get_daily_limit("ETH"), Some(U256::ZERO));
    }

    #[test]
    fn test_policy_large_u256_limits() {
        let large_value = U256::MAX;
        let config = PolicyConfig::new()
            .with_transaction_limit("ETH", large_value)
            .with_daily_limit("ETH", large_value);

        assert_eq!(config.get_transaction_limit("ETH"), Some(large_value));
        assert_eq!(config.get_daily_limit("ETH"), Some(large_value));
    }

    #[test]
    fn test_policy_token_address_as_key() {
        let token_address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
        let config =
            PolicyConfig::new().with_transaction_limit(token_address, U256::from(1_000_000u64));

        assert!(config.get_transaction_limit(token_address).is_some());
        assert!(config
            .get_transaction_limit(&token_address.to_lowercase())
            .is_some());
    }

    #[test]
    fn test_policy_multiple_transaction_limits() {
        let config = PolicyConfig::new()
            .with_transaction_limit("ETH", U256::from(5_000_000_000_000_000_000u64))
            .with_transaction_limit("USDC", U256::from(10_000_000_000u64));

        assert_eq!(
            config.get_transaction_limit("ETH"),
            Some(U256::from(5_000_000_000_000_000_000u64))
        );
        assert_eq!(
            config.get_transaction_limit("USDC"),
            Some(U256::from(10_000_000_000u64))
        );
    }
}
