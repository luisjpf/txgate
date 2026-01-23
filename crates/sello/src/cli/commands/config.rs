//! # Config Command
//!
//! Implementation of the `sello config` command that displays, edits, and
//! manages the Sello configuration file.
//!
//! ## Usage
//!
//! ```text
//! sello config           # Display current configuration
//! sello config edit      # Open configuration in $EDITOR
//! sello config path      # Show the configuration file path
//! ```
//!
//! ## Example
//!
//! ```no_run
//! use sello::cli::commands::config::ConfigCommand;
//! use sello::cli::args::ConfigAction;
//!
//! // Display config
//! let cmd = ConfigCommand { action: None };
//! cmd.run().expect("config display failed");
//!
//! // Edit config
//! let cmd = ConfigCommand { action: Some(ConfigAction::Edit) };
//! cmd.run().expect("config edit failed");
//!
//! // Show path
//! let cmd = ConfigCommand { action: Some(ConfigAction::Path) };
//! cmd.run().expect("config path failed");
//! ```

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use sello_core::config::Config;
use sello_core::config_loader::ConfigLoader;
use sello_core::error::ConfigError;

use crate::cli::args::ConfigAction;

// ============================================================================
// Constants
// ============================================================================

/// Base directory name within the home directory.
const BASE_DIR_NAME: &str = ".sello";

/// Config file name.
const CONFIG_FILE_NAME: &str = "config.toml";

/// Default editor fallback (Unix).
const DEFAULT_EDITOR: &str = "vi";

// ============================================================================
// ConfigCommandError
// ============================================================================

/// Errors that can occur during config command execution.
#[derive(Debug, thiserror::Error)]
pub enum ConfigCommandError {
    /// Sello is not initialized (no config file exists).
    #[error("Sello is not initialized. Run 'sello init' first.")]
    NotInitialized,

    /// Failed to load configuration.
    #[error("Failed to load configuration: {0}")]
    LoadError(#[source] ConfigError),

    /// Editor not found.
    #[error("Editor not found. Set $EDITOR environment variable.")]
    EditorNotFound,

    /// Editor exited with error.
    #[error("Editor exited with error: {0}")]
    EditorFailed(String),

    /// Configuration validation failed after edit.
    #[error("Configuration validation failed: {0}")]
    ValidationFailed(String),

    /// General I/O error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Home directory could not be determined.
    #[error("Could not determine home directory")]
    NoHomeDirectory,
}

impl From<ConfigError> for ConfigCommandError {
    fn from(err: ConfigError) -> Self {
        Self::LoadError(err)
    }
}

// ============================================================================
// ConfigCommand
// ============================================================================

/// The `sello config` command handler.
///
/// This command handles viewing and editing the Sello configuration file.
///
/// # Example
///
/// ```no_run
/// use sello::cli::commands::config::ConfigCommand;
/// use sello::cli::args::ConfigAction;
///
/// // Display configuration
/// let cmd = ConfigCommand { action: None };
/// match cmd.run() {
///     Ok(()) => println!("Configuration displayed"),
///     Err(e) => eprintln!("Error: {}", e),
/// }
/// ```
#[derive(Debug, Clone)]
pub struct ConfigCommand {
    /// The action to perform (None = show config).
    pub action: Option<ConfigAction>,
}

impl ConfigCommand {
    /// Create a new `ConfigCommand`.
    #[must_use]
    pub const fn new(action: Option<ConfigAction>) -> Self {
        Self { action }
    }

    /// Run the config command.
    ///
    /// This method dispatches to the appropriate handler based on the action:
    /// - `None` - Display the current configuration
    /// - `Some(ConfigAction::Edit)` - Open the configuration in an editor
    /// - `Some(ConfigAction::Path)` - Print the configuration file path
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Sello is not initialized (no config file)
    /// - Configuration cannot be loaded
    /// - Editor is not found or fails
    /// - Configuration is invalid after editing
    pub fn run(&self) -> Result<(), ConfigCommandError> {
        match &self.action {
            None => self.show_config(),
            Some(ConfigAction::Edit) => self.edit_config(),
            Some(ConfigAction::Path) => self.show_path(),
        }
    }

    /// Display the current configuration.
    ///
    /// Loads and pretty-prints the configuration file as TOML.
    ///
    /// Note: `&self` is kept for API consistency with other command structs,
    /// even though it's not currently used.
    #[allow(clippy::unused_self)]
    fn show_config(&self) -> Result<(), ConfigCommandError> {
        let config_path = get_config_path()?;

        if !config_path.exists() {
            return Err(ConfigCommandError::NotInitialized);
        }

        // Load the config
        let loader = ConfigLoader::with_base_dir(get_base_dir()?);
        let config = loader.load_required()?;

        // Pretty-print as TOML
        let output = format_toml_output(&config)?;
        println!("{output}");

        Ok(())
    }

    /// Open the configuration file in an editor.
    ///
    /// Steps:
    /// 1. Get editor from $EDITOR, $VISUAL, or fallback to "vi"
    /// 2. Get config file path
    /// 3. Open editor with config file
    /// 4. Wait for editor to exit
    /// 5. Validate config after edit
    /// 6. Report success or validation errors
    ///
    /// Note: `&self` is kept for API consistency with other command structs,
    /// even though it's not currently used.
    #[allow(clippy::unused_self)]
    fn edit_config(&self) -> Result<(), ConfigCommandError> {
        let config_path = get_config_path()?;

        if !config_path.exists() {
            return Err(ConfigCommandError::NotInitialized);
        }

        // 1. Get editor
        let editor = get_editor();

        // 2. Open editor with config file
        let status = Command::new(&editor)
            .arg(&config_path)
            .status()
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    ConfigCommandError::EditorNotFound
                } else {
                    ConfigCommandError::EditorFailed(format!("Failed to launch editor: {e}"))
                }
            })?;

        // 3. Check if editor exited successfully
        if !status.success() {
            let exit_code = status
                .code()
                .map_or_else(|| "signal".to_string(), |c| c.to_string());
            return Err(ConfigCommandError::EditorFailed(format!(
                "Editor exited with code: {exit_code}"
            )));
        }

        // 4. Validate config after edit
        validate_config_file(&config_path)?;

        println!("Configuration updated successfully.");
        Ok(())
    }

    /// Print the path to the configuration file.
    ///
    /// Note: `&self` is kept for API consistency with other command structs,
    /// even though it's not currently used.
    #[allow(clippy::unused_self)]
    fn show_path(&self) -> Result<(), ConfigCommandError> {
        let config_path = get_config_path()?;
        println!("{}", config_path.display());
        Ok(())
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Get the base directory for Sello files (~/.sello).
fn get_base_dir() -> Result<PathBuf, ConfigCommandError> {
    dirs::home_dir()
        .map(|home| home.join(BASE_DIR_NAME))
        .ok_or(ConfigCommandError::NoHomeDirectory)
}

/// Get the path to the configuration file.
fn get_config_path() -> Result<PathBuf, ConfigCommandError> {
    let base_dir = get_base_dir()?;
    Ok(base_dir.join(CONFIG_FILE_NAME))
}

/// Get the editor command from environment variables.
///
/// Checks in order: $EDITOR, $VISUAL, then falls back to "vi".
fn get_editor() -> String {
    // Try $EDITOR first
    if let Ok(editor) = env::var("EDITOR") {
        if !editor.is_empty() {
            return editor;
        }
    }

    // Try $VISUAL second
    if let Ok(visual) = env::var("VISUAL") {
        if !visual.is_empty() {
            return visual;
        }
    }

    // Fallback to default editor
    DEFAULT_EDITOR.to_string()
}

/// Validate the configuration file after editing.
///
/// Checks that:
/// 1. The file can be read
/// 2. The file contains valid TOML
/// 3. The configuration passes validation
fn validate_config_file(path: &Path) -> Result<(), ConfigCommandError> {
    // Read the file
    let content = fs::read_to_string(path)?;

    // Parse as TOML
    let config: Config = toml::from_str(&content)
        .map_err(|e| ConfigCommandError::ValidationFailed(format!("Invalid TOML syntax: {e}")))?;

    // Validate the configuration
    config.validate().map_err(|e| {
        ConfigCommandError::ValidationFailed(format!("Configuration validation error: {e}"))
    })?;

    Ok(())
}

/// Format the configuration as pretty TOML output.
fn format_toml_output(config: &Config) -> Result<String, ConfigCommandError> {
    toml::to_string_pretty(config).map_err(|e| {
        ConfigCommandError::ValidationFailed(format!("Failed to serialize configuration: {e}"))
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
    use std::env;
    use tempfile::TempDir;

    /// Create a temporary directory for testing.
    fn create_test_dir() -> TempDir {
        TempDir::new().expect("failed to create temp dir")
    }

    // ------------------------------------------------------------------------
    // show_path tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_show_path_returns_correct_path() {
        // The show_path method just prints the path and returns Ok
        // We can test that get_config_path returns the expected path
        let path = get_config_path().expect("should get config path");

        let home = dirs::home_dir().expect("should get home dir");
        let expected = home.join(".sello").join("config.toml");

        assert_eq!(path, expected);
    }

    // ------------------------------------------------------------------------
    // get_editor tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_get_editor_from_editor_env() {
        // Save original
        let original_editor = env::var("EDITOR").ok();
        let original_visual = env::var("VISUAL").ok();

        // Set test values
        env::set_var("EDITOR", "nvim");
        env::remove_var("VISUAL");

        let editor = get_editor();
        assert_eq!(editor, "nvim");

        // Restore
        if let Some(val) = original_editor {
            env::set_var("EDITOR", val);
        } else {
            env::remove_var("EDITOR");
        }
        if let Some(val) = original_visual {
            env::set_var("VISUAL", val);
        }
    }

    #[test]
    fn test_get_editor_from_visual_env() {
        // Save original
        let original_editor = env::var("EDITOR").ok();
        let original_visual = env::var("VISUAL").ok();

        // Set test values - EDITOR empty, VISUAL set
        env::set_var("EDITOR", "");
        env::set_var("VISUAL", "code");

        let editor = get_editor();
        assert_eq!(editor, "code");

        // Restore
        if let Some(val) = original_editor {
            env::set_var("EDITOR", val);
        } else {
            env::remove_var("EDITOR");
        }
        if let Some(val) = original_visual {
            env::set_var("VISUAL", val);
        }
    }

    #[test]
    fn test_get_editor_fallback() {
        // Save original
        let original_editor = env::var("EDITOR").ok();
        let original_visual = env::var("VISUAL").ok();

        // Remove both
        env::remove_var("EDITOR");
        env::remove_var("VISUAL");

        let editor = get_editor();
        assert_eq!(editor, "vi");

        // Restore
        if let Some(val) = original_editor {
            env::set_var("EDITOR", val);
        }
        if let Some(val) = original_visual {
            env::set_var("VISUAL", val);
        }
    }

    // ------------------------------------------------------------------------
    // validate_config_file tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_validate_config_file_valid() {
        let temp_dir = create_test_dir();
        let config_path = temp_dir.path().join("config.toml");

        // Write valid config
        let valid_config = Config::default_toml();
        fs::write(&config_path, valid_config).expect("should write config");

        let result = validate_config_file(&config_path);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_config_file_invalid_toml() {
        let temp_dir = create_test_dir();
        let config_path = temp_dir.path().join("config.toml");

        // Write invalid TOML
        fs::write(&config_path, "this is not valid toml [[[").expect("should write config");

        let result = validate_config_file(&config_path);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(ConfigCommandError::ValidationFailed(_))
        ));
    }

    #[test]
    fn test_validate_config_file_invalid_config() {
        let temp_dir = create_test_dir();
        let config_path = temp_dir.path().join("config.toml");

        // Write valid TOML but invalid config (empty socket path)
        let invalid_config = r#"
[server]
socket_path = ""
timeout_secs = 30

[keys]
directory = "~/.sello/keys"
default_key = "default"

[policy]
whitelist_enabled = false
"#;
        fs::write(&config_path, invalid_config).expect("should write config");

        let result = validate_config_file(&config_path);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(ConfigCommandError::ValidationFailed(_))
        ));
    }

    // ------------------------------------------------------------------------
    // format_toml_output tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_format_toml_output() {
        let config = Config::default();
        let output = format_toml_output(&config).expect("should format config");

        assert!(output.contains("[server]"));
        assert!(output.contains("[keys]"));
        assert!(output.contains("[policy]"));
    }

    // ------------------------------------------------------------------------
    // ConfigCommand tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_config_command_new() {
        let cmd = ConfigCommand::new(None);
        assert!(cmd.action.is_none());

        let cmd = ConfigCommand::new(Some(ConfigAction::Edit));
        assert!(matches!(cmd.action, Some(ConfigAction::Edit)));

        let cmd = ConfigCommand::new(Some(ConfigAction::Path));
        assert!(matches!(cmd.action, Some(ConfigAction::Path)));
    }

    #[test]
    fn test_show_config_not_initialized() {
        // Test when config file doesn't exist
        // This will use the real home directory, so we can't easily test
        // the not initialized case without modifying the real filesystem
        // Instead, we test the error type exists
        let err = ConfigCommandError::NotInitialized;
        assert_eq!(
            err.to_string(),
            "Sello is not initialized. Run 'sello init' first."
        );
    }

    // ------------------------------------------------------------------------
    // Error Display tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_config_command_error_display() {
        assert_eq!(
            ConfigCommandError::NotInitialized.to_string(),
            "Sello is not initialized. Run 'sello init' first."
        );

        assert_eq!(
            ConfigCommandError::EditorNotFound.to_string(),
            "Editor not found. Set $EDITOR environment variable."
        );

        assert_eq!(
            ConfigCommandError::EditorFailed("exit code 1".to_string()).to_string(),
            "Editor exited with error: exit code 1"
        );

        assert_eq!(
            ConfigCommandError::ValidationFailed("invalid field".to_string()).to_string(),
            "Configuration validation failed: invalid field"
        );

        assert_eq!(
            ConfigCommandError::NoHomeDirectory.to_string(),
            "Could not determine home directory"
        );
    }

    // ------------------------------------------------------------------------
    // Thread Safety tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_config_command_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ConfigCommand>();
    }

    #[test]
    fn test_config_command_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ConfigCommandError>();
    }

    // ------------------------------------------------------------------------
    // get_base_dir tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_get_base_dir() {
        let base_dir = get_base_dir().expect("should get base dir");
        let home = dirs::home_dir().expect("should get home dir");
        assert_eq!(base_dir, home.join(".sello"));
    }

    // ------------------------------------------------------------------------
    // Error conversion tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_config_error_conversion() {
        let config_err = ConfigError::file_not_found("/test/path");
        let cmd_err: ConfigCommandError = config_err.into();
        assert!(matches!(cmd_err, ConfigCommandError::LoadError(_)));
    }

    // ------------------------------------------------------------------------
    // Additional Coverage Tests - Phase 3
    // ------------------------------------------------------------------------

    #[test]
    fn test_config_command_debug() {
        let cmd = ConfigCommand::new(None);
        let debug_str = format!("{:?}", cmd);
        assert!(debug_str.contains("ConfigCommand"));
    }

    #[test]
    fn test_config_command_clone() {
        let cmd = ConfigCommand::new(Some(ConfigAction::Path));
        let cloned = cmd.clone();
        assert!(matches!(cloned.action, Some(ConfigAction::Path)));
    }

    #[test]
    fn test_config_command_error_io_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "not found");
        let config_err: ConfigCommandError = io_err.into();
        assert!(matches!(config_err, ConfigCommandError::Io(_)));
    }

    #[test]
    fn test_validate_config_file_nonexistent() {
        let path = std::path::Path::new("/nonexistent/path/config.toml");
        let result = validate_config_file(path);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_config_file_with_overlapping_policy() {
        let temp_dir = create_test_dir();
        let config_path = temp_dir.path().join("config.toml");

        // Config with overlapping whitelist/blacklist (should fail validation)
        let invalid_config = r#"
[server]
socket_path = "~/.sello/sello.sock"
timeout_secs = 30

[keys]
directory = "~/.sello/keys"
default_key = "default"

[policy]
whitelist_enabled = true
whitelist = ["0xAAA"]
blacklist = ["0xAAA"]
"#;
        fs::write(&config_path, invalid_config).expect("should write config");

        let result = validate_config_file(&config_path);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(ConfigCommandError::ValidationFailed(_))
        ));
    }

    #[test]
    fn test_get_editor_empty_visual() {
        // Save originals
        let original_editor = env::var("EDITOR").ok();
        let original_visual = env::var("VISUAL").ok();

        // Set EDITOR to empty, VISUAL to empty
        env::set_var("EDITOR", "");
        env::set_var("VISUAL", "");

        let editor = get_editor();
        // Should fall back to default
        assert_eq!(editor, DEFAULT_EDITOR);

        // Restore
        if let Some(val) = original_editor {
            env::set_var("EDITOR", val);
        } else {
            env::remove_var("EDITOR");
        }
        if let Some(val) = original_visual {
            env::set_var("VISUAL", val);
        } else {
            env::remove_var("VISUAL");
        }
    }

    #[test]
    fn test_config_command_all_actions() {
        // Test that all ConfigAction variants create commands properly
        let cmd_none = ConfigCommand::new(None);
        assert!(cmd_none.action.is_none());

        let cmd_edit = ConfigCommand::new(Some(ConfigAction::Edit));
        assert!(matches!(cmd_edit.action, Some(ConfigAction::Edit)));

        let cmd_path = ConfigCommand::new(Some(ConfigAction::Path));
        assert!(matches!(cmd_path.action, Some(ConfigAction::Path)));
    }

    #[test]
    fn test_config_command_error_source() {
        // Test that LoadError has a proper source
        let config_err = ConfigError::file_not_found("/test/path");
        let cmd_err = ConfigCommandError::LoadError(config_err);

        // Verify the error can be displayed
        let display = cmd_err.to_string();
        assert!(display.contains("Failed to load configuration"));
    }

    #[test]
    fn test_format_toml_output_preserves_structure() {
        let config = Config::default();
        let output = format_toml_output(&config).expect("should format");

        // Verify all sections are present
        assert!(output.contains("[server]"));
        assert!(output.contains("[keys]"));
        assert!(output.contains("[policy]"));

        // Verify it's valid TOML by parsing it back
        let parsed: Config = toml::from_str(&output).expect("should parse back");
        assert_eq!(parsed.keys.default_key, config.keys.default_key);
    }

    #[test]
    fn test_validate_config_file_empty_socket_path() {
        let temp_dir = create_test_dir();
        let config_path = temp_dir.path().join("config.toml");

        // Valid TOML but with empty socket_path which fails validation
        let invalid_config = r#"
[server]
socket_path = ""
timeout_secs = 30

[keys]
directory = "~/.sello/keys"
default_key = "default"

[policy]
whitelist_enabled = false
"#;
        fs::write(&config_path, invalid_config).expect("should write config");

        let result = validate_config_file(&config_path);
        // Should fail because socket_path is empty (validation fails)
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(ConfigCommandError::ValidationFailed(_))
        ));
    }
}
