//! # Passphrase Input Utilities
//!
//! Shared passphrase reading logic for all CLI commands.
//!
//! Supports two input modes:
//! 1. **Environment variable** — set `TXGATE_PASSPHRASE` for non-interactive use
//!    (CI/CD, scripts, server mode without a TTY)
//! 2. **Interactive prompt** — secure hidden input via `rpassword`
//!
//! ## Security Warning
//!
//! Environment variables may be visible to other processes on the same system
//! (e.g. via `/proc/<pid>/environ` on Linux). Use the interactive prompt when
//! working in shared or untrusted environments.
//!
//! ## Example
//!
//! ```bash
//! # Non-interactive: passphrase from environment
//! TXGATE_PASSPHRASE=mypass txgate serve --foreground
//!
//! # Interactive: prompted at runtime
//! txgate serve --foreground
//! ```

use std::io::Write;

/// Environment variable name for non-interactive passphrase input.
pub const ENV_VAR: &str = "TXGATE_PASSPHRASE";

/// Minimum passphrase length for key creation operations.
pub const MIN_PASSPHRASE_LENGTH: usize = 8;

/// Errors that can occur during passphrase input.
#[derive(Debug, thiserror::Error)]
pub enum PassphraseError {
    /// Passphrase was empty.
    #[error("Passphrase cannot be empty")]
    Empty,

    /// Passphrase does not meet minimum length.
    #[error("Passphrase must be at least {min} characters")]
    TooShort {
        /// Minimum required length.
        min: usize,
    },

    /// Confirmation did not match the original passphrase.
    #[error("Passphrases do not match")]
    Mismatch,

    /// User cancelled the passphrase input (EOF or empty).
    #[error("Passphrase input cancelled")]
    Cancelled,

    /// I/O error reading passphrase.
    #[error("Failed to read passphrase: {0}")]
    Io(#[from] std::io::Error),
}

/// Read a passphrase for unlocking an existing key.
///
/// Checks `TXGATE_PASSPHRASE` environment variable first, then falls back
/// to an interactive `rpassword` prompt.
///
/// # Errors
///
/// Returns [`PassphraseError`] if:
/// - The env var is set but empty
/// - The interactive prompt fails or is cancelled
pub fn read_passphrase() -> Result<String, PassphraseError> {
    if let Ok(val) = std::env::var(ENV_VAR) {
        if val.is_empty() {
            return Err(PassphraseError::Empty);
        }
        eprintln!("Using passphrase from {ENV_VAR} environment variable");
        return Ok(val);
    }

    println!("Enter passphrase to unlock key:");
    let passphrase = rpassword::read_password().map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            PassphraseError::Cancelled
        } else {
            PassphraseError::Io(e)
        }
    })?;

    if passphrase.is_empty() {
        return Err(PassphraseError::Cancelled);
    }

    Ok(passphrase)
}

/// Read a new passphrase for key creation (init, import, export).
///
/// Checks `TXGATE_PASSPHRASE` environment variable first (skips confirmation),
/// then falls back to an interactive prompt with confirmation.
///
/// # Errors
///
/// Returns [`PassphraseError`] if:
/// - The env var is set but too short
/// - The interactive prompt fails, is cancelled, or confirmation doesn't match
pub fn read_new_passphrase() -> Result<String, PassphraseError> {
    if let Ok(val) = std::env::var(ENV_VAR) {
        if val.is_empty() {
            return Err(PassphraseError::Empty);
        }
        if val.len() < MIN_PASSPHRASE_LENGTH {
            return Err(PassphraseError::TooShort {
                min: MIN_PASSPHRASE_LENGTH,
            });
        }
        eprintln!("Using passphrase from {ENV_VAR} environment variable");
        return Ok(val);
    }

    print!("Enter a passphrase to encrypt your key: ");
    std::io::stdout().flush()?;

    let passphrase = rpassword::read_password().map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            PassphraseError::Cancelled
        } else {
            PassphraseError::Io(e)
        }
    })?;

    if passphrase.is_empty() {
        return Err(PassphraseError::Cancelled);
    }

    if passphrase.len() < MIN_PASSPHRASE_LENGTH {
        return Err(PassphraseError::TooShort {
            min: MIN_PASSPHRASE_LENGTH,
        });
    }

    print!("Confirm passphrase: ");
    std::io::stdout().flush()?;

    let confirmation = rpassword::read_password().map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            PassphraseError::Cancelled
        } else {
            PassphraseError::Io(e)
        }
    })?;

    if passphrase != confirmation {
        return Err(PassphraseError::Mismatch);
    }

    Ok(passphrase)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use std::sync::Mutex;

    // Mutex to serialize env var tests (env vars are process-global)
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    // =========================================================================
    // read_passphrase tests (env var path)
    // =========================================================================

    #[test]
    fn test_read_passphrase_from_env_var() {
        let _lock = ENV_LOCK.lock().unwrap();
        std::env::set_var(ENV_VAR, "test-passphrase");

        let result = read_passphrase();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "test-passphrase");

        std::env::remove_var(ENV_VAR);
    }

    #[test]
    fn test_read_passphrase_empty_env_var() {
        let _lock = ENV_LOCK.lock().unwrap();
        std::env::set_var(ENV_VAR, "");

        let result = read_passphrase();
        assert!(matches!(result, Err(PassphraseError::Empty)));

        std::env::remove_var(ENV_VAR);
    }

    // =========================================================================
    // read_new_passphrase tests (env var path)
    // =========================================================================

    #[test]
    fn test_read_new_passphrase_from_env_var() {
        let _lock = ENV_LOCK.lock().unwrap();
        std::env::set_var(ENV_VAR, "longpassphrase");

        let result = read_new_passphrase();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "longpassphrase");

        std::env::remove_var(ENV_VAR);
    }

    #[test]
    fn test_read_new_passphrase_too_short_env_var() {
        let _lock = ENV_LOCK.lock().unwrap();
        std::env::set_var(ENV_VAR, "short");

        let result = read_new_passphrase();
        assert!(matches!(result, Err(PassphraseError::TooShort { min: 8 })));

        std::env::remove_var(ENV_VAR);
    }

    #[test]
    fn test_read_new_passphrase_empty_env_var() {
        let _lock = ENV_LOCK.lock().unwrap();
        std::env::set_var(ENV_VAR, "");

        let result = read_new_passphrase();
        assert!(matches!(result, Err(PassphraseError::Empty)));

        std::env::remove_var(ENV_VAR);
    }

    #[test]
    fn test_read_new_passphrase_exact_min_length() {
        let _lock = ENV_LOCK.lock().unwrap();
        std::env::set_var(ENV_VAR, "12345678"); // exactly 8 chars

        let result = read_new_passphrase();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "12345678");

        std::env::remove_var(ENV_VAR);
    }

    // =========================================================================
    // Error display tests
    // =========================================================================

    #[test]
    fn test_error_display() {
        assert_eq!(
            PassphraseError::Empty.to_string(),
            "Passphrase cannot be empty"
        );
        assert_eq!(
            PassphraseError::TooShort { min: 8 }.to_string(),
            "Passphrase must be at least 8 characters"
        );
        assert_eq!(
            PassphraseError::Mismatch.to_string(),
            "Passphrases do not match"
        );
        assert_eq!(
            PassphraseError::Cancelled.to_string(),
            "Passphrase input cancelled"
        );
    }

    #[test]
    fn test_passphrase_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<PassphraseError>();
    }
}
