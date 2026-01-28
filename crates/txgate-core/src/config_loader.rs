//! Configuration loader for the `TxGate` signing service.
//!
//! This module provides utilities for loading, saving, and managing configuration
//! files from the filesystem. It handles path expansion (e.g., `~` to home directory)
//! and provides sensible defaults when configuration files don't exist.
//!
//! # Default Location
//!
//! Configuration is stored at `~/.txgate/config.toml` by default.
//!
//! # Examples
//!
//! ## Loading configuration with defaults
//!
//! ```no_run
//! use txgate_core::config_loader::load_config;
//!
//! // Load config from default location, using defaults if file doesn't exist
//! let config = load_config().expect("failed to load config");
//! ```
//!
//! ## Using `ConfigLoader` for more control
//!
//! ```no_run
//! use txgate_core::config_loader::ConfigLoader;
//! use std::path::PathBuf;
//!
//! // Create loader with default base directory (~/.txgate)
//! let loader = ConfigLoader::new().expect("failed to create loader");
//!
//! // Check if config exists
//! if loader.exists() {
//!     let config = loader.load().expect("failed to load config");
//!     println!("Loaded config with timeout: {}s", config.server.timeout_secs);
//! } else {
//!     // Write default configuration
//!     loader.write_default().expect("failed to write default config");
//! }
//! ```
//!
//! ## Custom base directory
//!
//! ```no_run
//! use txgate_core::config_loader::ConfigLoader;
//! use std::path::PathBuf;
//!
//! let loader = ConfigLoader::with_base_dir(PathBuf::from("/custom/txgate"));
//! let config = loader.load().expect("failed to load config");
//! ```

use crate::config::Config;
use crate::error::ConfigError;
use std::fs;
use std::path::{Path, PathBuf};

/// The default configuration file name.
const CONFIG_FILE_NAME: &str = "config.toml";

/// The default base directory name within the home directory.
const BASE_DIR_NAME: &str = ".txgate";

/// Configuration loader that handles reading and writing configuration files.
///
/// The `ConfigLoader` manages configuration file operations including:
/// - Loading configuration from TOML files
/// - Saving configuration to TOML files
/// - Creating default configuration files
/// - Path expansion for `~` (home directory)
///
/// # Examples
///
/// ```no_run
/// use txgate_core::config_loader::ConfigLoader;
///
/// // Create with default base directory (~/.txgate)
/// let loader = ConfigLoader::new().expect("failed to create loader");
///
/// // Load configuration (returns defaults if file doesn't exist)
/// let config = loader.load().expect("failed to load config");
/// ```
#[derive(Debug, Clone)]
pub struct ConfigLoader {
    /// Base directory for `TxGate` files (default: ~/.txgate).
    base_dir: PathBuf,
}

impl ConfigLoader {
    /// Creates a new `ConfigLoader` with the default base directory (`~/.txgate`).
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::NoHomeDirectory`] if the home directory cannot be determined.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use txgate_core::config_loader::ConfigLoader;
    ///
    /// let loader = ConfigLoader::new().expect("failed to create loader");
    /// ```
    pub fn new() -> Result<Self, ConfigError> {
        let base_dir = default_base_dir()?;
        Ok(Self { base_dir })
    }

    /// Creates a `ConfigLoader` with a custom base directory.
    ///
    /// # Arguments
    ///
    /// * `base_dir` - The base directory for `TxGate` files
    ///
    /// # Examples
    ///
    /// ```
    /// use txgate_core::config_loader::ConfigLoader;
    /// use std::path::PathBuf;
    ///
    /// let loader = ConfigLoader::with_base_dir(PathBuf::from("/custom/txgate"));
    /// ```
    #[must_use]
    pub const fn with_base_dir(base_dir: PathBuf) -> Self {
        Self { base_dir }
    }

    /// Returns the path to the configuration file.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use txgate_core::config_loader::ConfigLoader;
    ///
    /// let loader = ConfigLoader::new().expect("failed to create loader");
    /// let path = loader.config_path();
    /// // path is something like "/home/user/.txgate/config.toml"
    /// ```
    #[must_use]
    pub fn config_path(&self) -> PathBuf {
        self.base_dir.join(CONFIG_FILE_NAME)
    }

    /// Returns the base directory for `TxGate` files.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use txgate_core::config_loader::ConfigLoader;
    ///
    /// let loader = ConfigLoader::new().expect("failed to create loader");
    /// let base = loader.base_dir();
    /// // base is something like "/home/user/.txgate"
    /// ```
    #[must_use]
    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    /// Loads configuration from the file.
    ///
    /// If the configuration file doesn't exist, returns the default configuration.
    /// If the file exists but contains invalid TOML, returns a parse error.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::ParseFailed`] if the file contains invalid TOML.
    /// Returns [`ConfigError::Io`] if there's an I/O error reading the file.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use txgate_core::config_loader::ConfigLoader;
    ///
    /// let loader = ConfigLoader::new().expect("failed to create loader");
    /// let config = loader.load().expect("failed to load config");
    /// ```
    pub fn load(&self) -> Result<Config, ConfigError> {
        let config_path = self.config_path();

        if !config_path.exists() {
            return Ok(Config::default());
        }

        Self::load_from_path(&config_path)
    }

    /// Loads configuration from the file, failing if the file doesn't exist.
    ///
    /// Unlike [`load`](Self::load), this method returns an error if the
    /// configuration file is not found.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::FileNotFound`] if the configuration file doesn't exist.
    /// Returns [`ConfigError::ParseFailed`] if the file contains invalid TOML.
    /// Returns [`ConfigError::Io`] if there's an I/O error reading the file.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use txgate_core::config_loader::ConfigLoader;
    ///
    /// let loader = ConfigLoader::new().expect("failed to create loader");
    /// match loader.load_required() {
    ///     Ok(config) => println!("Config loaded: {:?}", config),
    ///     Err(e) => eprintln!("Config required but not found: {}", e),
    /// }
    /// ```
    pub fn load_required(&self) -> Result<Config, ConfigError> {
        let config_path = self.config_path();

        if !config_path.exists() {
            return Err(ConfigError::file_not_found(
                config_path.display().to_string(),
            ));
        }

        Self::load_from_path(&config_path)
    }

    /// Saves configuration to the file.
    ///
    /// Creates the base directory if it doesn't exist.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Io`] if there's an I/O error writing the file.
    /// Returns [`ConfigError::ParseFailed`] if the configuration cannot be serialized.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use txgate_core::config_loader::ConfigLoader;
    /// use txgate_core::config::Config;
    ///
    /// let loader = ConfigLoader::new().expect("failed to create loader");
    /// let config = Config::builder()
    ///     .timeout_secs(60)
    ///     .build();
    ///
    /// loader.save(&config).expect("failed to save config");
    /// ```
    pub fn save(&self, config: &Config) -> Result<(), ConfigError> {
        // Ensure base directory exists
        self.ensure_base_dir()?;

        let config_path = self.config_path();

        let toml_str = toml::to_string_pretty(config).map_err(|e| {
            ConfigError::parse_failed(format!("failed to serialize configuration: {e}"))
        })?;

        fs::write(&config_path, toml_str).map_err(|e| {
            ConfigError::io(
                format!("failed to write configuration to {}", config_path.display()),
                e,
            )
        })?;

        Ok(())
    }

    /// Writes the default configuration file.
    ///
    /// Creates the base directory if it doesn't exist.
    /// Uses the formatted default TOML from [`Config::default_toml`].
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Io`] if there's an I/O error writing the file.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use txgate_core::config_loader::ConfigLoader;
    ///
    /// let loader = ConfigLoader::new().expect("failed to create loader");
    /// loader.write_default().expect("failed to write default config");
    /// ```
    pub fn write_default(&self) -> Result<(), ConfigError> {
        // Ensure base directory exists
        self.ensure_base_dir()?;

        let config_path = self.config_path();
        let default_toml = Config::default_toml();

        fs::write(&config_path, default_toml).map_err(|e| {
            ConfigError::io(
                format!(
                    "failed to write default configuration to {}",
                    config_path.display()
                ),
                e,
            )
        })?;

        Ok(())
    }

    /// Checks if the configuration file exists.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use txgate_core::config_loader::ConfigLoader;
    ///
    /// let loader = ConfigLoader::new().expect("failed to create loader");
    /// if loader.exists() {
    ///     println!("Config file found");
    /// } else {
    ///     println!("Config file not found, will use defaults");
    /// }
    /// ```
    #[must_use]
    pub fn exists(&self) -> bool {
        self.config_path().exists()
    }

    /// Ensures the base directory exists, creating it if necessary.
    fn ensure_base_dir(&self) -> Result<(), ConfigError> {
        if !self.base_dir.exists() {
            fs::create_dir_all(&self.base_dir).map_err(|e| {
                ConfigError::io(
                    format!(
                        "failed to create base directory {}",
                        self.base_dir.display()
                    ),
                    e,
                )
            })?;
        }
        Ok(())
    }

    /// Loads configuration from a specific path.
    fn load_from_path(path: &Path) -> Result<Config, ConfigError> {
        let content = fs::read_to_string(path)
            .map_err(|e| ConfigError::io(format!("failed to read {}", path.display()), e))?;

        let config: Config = toml::from_str(&content).map_err(|e| {
            ConfigError::parse_failed(format!("invalid TOML in {}: {e}", path.display()))
        })?;

        Ok(config)
    }
}

/// Expands `~` in paths to the home directory.
///
/// If the path starts with `~`, it is replaced with the user's home directory.
/// Otherwise, the path is returned unchanged (converted to `PathBuf`).
///
/// # Errors
///
/// Returns [`ConfigError::NoHomeDirectory`] if the path starts with `~` and
/// the home directory cannot be determined.
///
/// # Examples
///
/// ```no_run
/// use txgate_core::config_loader::expand_path;
///
/// // Expands ~ to home directory
/// let path = expand_path("~/.txgate/config.toml").expect("failed to expand path");
/// // path is something like "/home/user/.txgate/config.toml"
///
/// // Absolute paths are unchanged
/// let path = expand_path("/etc/txgate/config.toml").expect("failed to expand path");
/// assert_eq!(path.to_string_lossy(), "/etc/txgate/config.toml");
/// ```
pub fn expand_path(path: &str) -> Result<PathBuf, ConfigError> {
    if let Some(rest) = path.strip_prefix("~/") {
        let home = dirs::home_dir().ok_or_else(ConfigError::no_home_directory)?;
        Ok(home.join(rest))
    } else if path == "~" {
        dirs::home_dir().ok_or_else(ConfigError::no_home_directory)
    } else {
        Ok(PathBuf::from(path))
    }
}

/// Returns the default base directory for `TxGate` files (`~/.txgate`).
///
/// # Errors
///
/// Returns [`ConfigError::NoHomeDirectory`] if the home directory cannot be determined.
///
/// # Examples
///
/// ```no_run
/// use txgate_core::config_loader::default_base_dir;
///
/// let base_dir = default_base_dir().expect("failed to get base dir");
/// // base_dir is something like "/home/user/.txgate"
/// ```
pub fn default_base_dir() -> Result<PathBuf, ConfigError> {
    let home = dirs::home_dir().ok_or_else(ConfigError::no_home_directory)?;
    Ok(home.join(BASE_DIR_NAME))
}

/// Loads configuration from the default location with defaults for missing values.
///
/// This is a convenience function that:
/// 1. Creates a [`ConfigLoader`] with the default base directory
/// 2. Loads the configuration (returning defaults if file doesn't exist)
///
/// # Errors
///
/// Returns [`ConfigError::NoHomeDirectory`] if the home directory cannot be determined.
/// Returns [`ConfigError::ParseFailed`] if the configuration file contains invalid TOML.
/// Returns [`ConfigError::Io`] if there's an I/O error reading the file.
///
/// # Examples
///
/// ```no_run
/// use txgate_core::config_loader::load_config;
///
/// let config = load_config().expect("failed to load config");
/// println!("Socket path: {}", config.server.socket_path);
/// ```
pub fn load_config() -> Result<Config, ConfigError> {
    let loader = ConfigLoader::new()?;
    loader.load()
}

/// Loads configuration from the default location and expands all paths.
///
/// This is a convenience function that:
/// 1. Loads the configuration using [`load_config`]
/// 2. Expands `~` in `server.socket_path` to the full path
/// 3. Expands `~` in `keys.directory` to the full path
///
/// # Errors
///
/// Returns [`ConfigError::NoHomeDirectory`] if the home directory cannot be determined.
/// Returns [`ConfigError::ParseFailed`] if the configuration file contains invalid TOML.
/// Returns [`ConfigError::Io`] if there's an I/O error reading the file.
///
/// # Examples
///
/// ```no_run
/// use txgate_core::config_loader::load_config_with_expanded_paths;
///
/// let config = load_config_with_expanded_paths().expect("failed to load config");
/// // socket_path is something like "/home/user/.txgate/txgate.sock"
/// println!("Socket path: {}", config.server.socket_path);
/// ```
pub fn load_config_with_expanded_paths() -> Result<Config, ConfigError> {
    let mut config = load_config()?;

    // Expand socket path
    let expanded_socket = expand_path(&config.server.socket_path)?;
    config.server.socket_path = expanded_socket.to_string_lossy().to_string();

    // Expand keys directory
    let expanded_keys_dir = expand_path(&config.keys.directory)?;
    config.keys.directory = expanded_keys_dir.to_string_lossy().to_string();

    Ok(config)
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
    use std::fs;
    use tempfile::TempDir;

    // -------------------------------------------------------------------------
    // expand_path tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_expand_path_with_tilde_prefix() {
        let result = expand_path("~/.txgate/config.toml");
        assert!(result.is_ok());

        let path = result.expect("should succeed");
        let home = dirs::home_dir().expect("home dir should exist");
        assert_eq!(path, home.join(".txgate/config.toml"));
    }

    #[test]
    fn test_expand_path_with_tilde_only() {
        let result = expand_path("~");
        assert!(result.is_ok());

        let path = result.expect("should succeed");
        let home = dirs::home_dir().expect("home dir should exist");
        assert_eq!(path, home);
    }

    #[test]
    fn test_expand_path_with_absolute_path() {
        let result = expand_path("/etc/txgate/config.toml");
        assert!(result.is_ok());

        let path = result.expect("should succeed");
        assert_eq!(path, PathBuf::from("/etc/txgate/config.toml"));
    }

    #[test]
    fn test_expand_path_with_relative_path() {
        let result = expand_path("txgate/config.toml");
        assert!(result.is_ok());

        let path = result.expect("should succeed");
        assert_eq!(path, PathBuf::from("txgate/config.toml"));
    }

    #[test]
    fn test_expand_path_with_embedded_tilde() {
        // Tilde in middle of path should not be expanded
        let result = expand_path("/path/to/~/config.toml");
        assert!(result.is_ok());

        let path = result.expect("should succeed");
        assert_eq!(path, PathBuf::from("/path/to/~/config.toml"));
    }

    // -------------------------------------------------------------------------
    // default_base_dir tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_default_base_dir() {
        let result = default_base_dir();
        assert!(result.is_ok());

        let path = result.expect("should succeed");
        let home = dirs::home_dir().expect("home dir should exist");
        assert_eq!(path, home.join(".txgate"));
    }

    // -------------------------------------------------------------------------
    // ConfigLoader::new tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_config_loader_new() {
        let result = ConfigLoader::new();
        assert!(result.is_ok());

        let loader = result.expect("should succeed");
        let expected_base = default_base_dir().expect("should get default base dir");
        assert_eq!(loader.base_dir(), expected_base);
    }

    // -------------------------------------------------------------------------
    // ConfigLoader::with_base_dir tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_config_loader_with_base_dir() {
        let custom_path = PathBuf::from("/custom/txgate");
        let loader = ConfigLoader::with_base_dir(custom_path.clone());
        assert_eq!(loader.base_dir(), custom_path);
    }

    // -------------------------------------------------------------------------
    // ConfigLoader::config_path tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_config_loader_config_path() {
        let base = PathBuf::from("/test/base");
        let loader = ConfigLoader::with_base_dir(base);
        assert_eq!(
            loader.config_path(),
            PathBuf::from("/test/base/config.toml")
        );
    }

    // -------------------------------------------------------------------------
    // ConfigLoader::exists tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_config_loader_exists_false() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let loader = ConfigLoader::with_base_dir(temp_dir.path().to_path_buf());

        assert!(!loader.exists());
    }

    #[test]
    fn test_config_loader_exists_true() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let config_path = temp_dir.path().join("config.toml");
        fs::write(&config_path, "# test config").expect("failed to write test file");

        let loader = ConfigLoader::with_base_dir(temp_dir.path().to_path_buf());
        assert!(loader.exists());
    }

    // -------------------------------------------------------------------------
    // ConfigLoader::load tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_load_with_missing_file_returns_defaults() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let loader = ConfigLoader::with_base_dir(temp_dir.path().to_path_buf());

        let result = loader.load();
        assert!(result.is_ok());

        let config = result.expect("should succeed");
        assert_eq!(config, Config::default());
    }

    #[test]
    fn test_load_with_valid_toml() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let config_path = temp_dir.path().join("config.toml");

        let toml_content = r#"
[server]
socket_path = "/custom/socket.sock"
timeout_secs = 60

[keys]
directory = "/custom/keys"
default_key = "production"

[policy]
whitelist_enabled = true
whitelist = ["0xABC"]
"#;
        fs::write(&config_path, toml_content).expect("failed to write test file");

        let loader = ConfigLoader::with_base_dir(temp_dir.path().to_path_buf());
        let result = loader.load();
        assert!(result.is_ok());

        let config = result.expect("should succeed");
        assert_eq!(config.server.socket_path, "/custom/socket.sock");
        assert_eq!(config.server.timeout_secs, 60);
        assert_eq!(config.keys.directory, "/custom/keys");
        assert_eq!(config.keys.default_key, "production");
        assert!(config.policy.whitelist_enabled);
        assert_eq!(config.policy.whitelist, vec!["0xABC"]);
    }

    #[test]
    fn test_load_with_partial_toml_uses_defaults() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let config_path = temp_dir.path().join("config.toml");

        let toml_content = r#"
[server]
timeout_secs = 120
"#;
        fs::write(&config_path, toml_content).expect("failed to write test file");

        let loader = ConfigLoader::with_base_dir(temp_dir.path().to_path_buf());
        let result = loader.load();
        assert!(result.is_ok());

        let config = result.expect("should succeed");
        // Specified value
        assert_eq!(config.server.timeout_secs, 120);
        // Default values
        assert_eq!(config.server.socket_path, "~/.txgate/txgate.sock");
        assert_eq!(config.keys.directory, "~/.txgate/keys");
        assert_eq!(config.keys.default_key, "default");
    }

    #[test]
    fn test_load_with_invalid_toml_returns_parse_error() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let config_path = temp_dir.path().join("config.toml");

        let invalid_toml = "this is not valid toml [[[";
        fs::write(&config_path, invalid_toml).expect("failed to write test file");

        let loader = ConfigLoader::with_base_dir(temp_dir.path().to_path_buf());
        let result = loader.load();
        assert!(result.is_err());

        let err = result.expect_err("should fail");
        assert!(matches!(err, ConfigError::ParseFailed { .. }));
    }

    #[test]
    fn test_load_with_empty_file_returns_defaults() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let config_path = temp_dir.path().join("config.toml");

        fs::write(&config_path, "").expect("failed to write test file");

        let loader = ConfigLoader::with_base_dir(temp_dir.path().to_path_buf());
        let result = loader.load();
        assert!(result.is_ok());

        let config = result.expect("should succeed");
        assert_eq!(config, Config::default());
    }

    // -------------------------------------------------------------------------
    // ConfigLoader::load_required tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_load_required_with_missing_file_returns_error() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let loader = ConfigLoader::with_base_dir(temp_dir.path().to_path_buf());

        let result = loader.load_required();
        assert!(result.is_err());

        let err = result.expect_err("should fail");
        assert!(matches!(err, ConfigError::FileNotFound { .. }));
    }

    #[test]
    fn test_load_required_with_existing_file() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let config_path = temp_dir.path().join("config.toml");

        fs::write(&config_path, "[server]\ntimeout_secs = 45").expect("failed to write test file");

        let loader = ConfigLoader::with_base_dir(temp_dir.path().to_path_buf());
        let result = loader.load_required();
        assert!(result.is_ok());

        let config = result.expect("should succeed");
        assert_eq!(config.server.timeout_secs, 45);
    }

    // -------------------------------------------------------------------------
    // ConfigLoader::save tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_save_creates_directory_and_file() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let base_dir = temp_dir.path().join("nested/txgate");
        let loader = ConfigLoader::with_base_dir(base_dir.clone());

        let config = Config::builder()
            .socket_path("/custom/socket.sock")
            .timeout_secs(90)
            .build();

        let result = loader.save(&config);
        assert!(result.is_ok());

        // Verify file was created
        assert!(loader.exists());

        // Verify content
        let content = fs::read_to_string(loader.config_path()).expect("failed to read file");
        assert!(content.contains("socket_path = \"/custom/socket.sock\""));
        assert!(content.contains("timeout_secs = 90"));
    }

    #[test]
    fn test_save_and_load_roundtrip() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let loader = ConfigLoader::with_base_dir(temp_dir.path().to_path_buf());

        let original = Config::builder()
            .socket_path("/test/socket.sock")
            .timeout_secs(75)
            .keys_directory("/test/keys")
            .default_key("test-key")
            .build();

        loader.save(&original).expect("save should succeed");

        let loaded = loader.load().expect("load should succeed");
        assert_eq!(original, loaded);
    }

    // -------------------------------------------------------------------------
    // ConfigLoader::write_default tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_write_default_creates_valid_config() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let loader = ConfigLoader::with_base_dir(temp_dir.path().to_path_buf());

        let result = loader.write_default();
        assert!(result.is_ok());

        // Verify file exists
        assert!(loader.exists());

        // Verify it can be loaded and matches defaults
        let loaded = loader.load().expect("load should succeed");
        assert_eq!(loaded.server.socket_path, "~/.txgate/txgate.sock");
        assert_eq!(loaded.server.timeout_secs, 30);
        assert_eq!(loaded.keys.directory, "~/.txgate/keys");
        assert_eq!(loaded.keys.default_key, "default");
    }

    #[test]
    fn test_write_default_creates_nested_directory() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let base_dir = temp_dir.path().join("deeply/nested/txgate/dir");
        let loader = ConfigLoader::with_base_dir(base_dir.clone());

        let result = loader.write_default();
        assert!(result.is_ok());

        assert!(base_dir.exists());
        assert!(loader.exists());
    }

    // -------------------------------------------------------------------------
    // load_config tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_load_config_function() {
        // This test just verifies the function doesn't panic
        // Actual file loading depends on system state
        let result = load_config();
        // Should succeed even if file doesn't exist (returns defaults)
        assert!(result.is_ok());
    }

    // -------------------------------------------------------------------------
    // load_config_with_expanded_paths tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_load_config_with_expanded_paths() {
        let result = load_config_with_expanded_paths();
        assert!(result.is_ok());

        let config = result.expect("should succeed");

        // Socket path should be expanded (not start with ~)
        assert!(!config.server.socket_path.starts_with('~'));

        // Keys directory should be expanded (not start with ~)
        assert!(!config.keys.directory.starts_with('~'));

        // They should contain the home directory
        let home = dirs::home_dir().expect("home dir should exist");
        assert!(config
            .server
            .socket_path
            .starts_with(home.to_string_lossy().as_ref()));
        assert!(config
            .keys
            .directory
            .starts_with(home.to_string_lossy().as_ref()));
    }

    // -------------------------------------------------------------------------
    // Edge case tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_config_loader_clone() {
        let loader = ConfigLoader::with_base_dir(PathBuf::from("/test/path"));
        let cloned = loader.clone();
        assert_eq!(loader.base_dir(), cloned.base_dir());
    }

    #[test]
    fn test_config_loader_debug() {
        let loader = ConfigLoader::with_base_dir(PathBuf::from("/test/path"));
        let debug_str = format!("{loader:?}");
        assert!(debug_str.contains("ConfigLoader"));
        assert!(debug_str.contains("/test/path"));
    }

    #[test]
    fn test_save_overwrites_existing_file() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let loader = ConfigLoader::with_base_dir(temp_dir.path().to_path_buf());

        // Save first config
        let config1 = Config::builder().timeout_secs(10).build();
        loader.save(&config1).expect("first save should succeed");

        // Save second config (overwrite)
        let config2 = Config::builder().timeout_secs(20).build();
        loader.save(&config2).expect("second save should succeed");

        // Load and verify it's the second config
        let loaded = loader.load().expect("load should succeed");
        assert_eq!(loaded.server.timeout_secs, 20);
    }
}
