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

use zeroize::Zeroizing;

/// Environment variable name for non-interactive passphrase input.
pub(crate) const ENV_VAR: &str = "TXGATE_PASSPHRASE";

/// Environment variable name for the export-specific new passphrase.
///
/// When set, `txgate key export` uses this for the new (export) passphrase,
/// allowing a different passphrase from the current one (`TXGATE_PASSPHRASE`).
pub(crate) const EXPORT_ENV_VAR: &str = "TXGATE_EXPORT_PASSPHRASE";

/// Minimum passphrase length for key creation operations.
pub(crate) const MIN_PASSPHRASE_LENGTH: usize = 8;

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
/// to an interactive `rpassword` prompt. The env var is removed from the
/// process environment after reading to limit exposure.
///
/// # Errors
///
/// Returns [`PassphraseError`] if:
/// - The env var is set but empty
/// - The interactive prompt fails or is cancelled
pub fn read_passphrase() -> Result<Zeroizing<String>, PassphraseError> {
    if let Ok(val) = std::env::var(ENV_VAR) {
        let val = Zeroizing::new(val);
        // Clear env var immediately to minimize exposure window
        clear_env_var(ENV_VAR);
        if val.is_empty() {
            return Err(PassphraseError::Empty);
        }
        eprintln!("Using passphrase from {ENV_VAR} environment variable");
        return Ok(val);
    }

    print!("Enter passphrase to unlock key: ");
    std::io::stdout().flush()?;

    let passphrase = read_password()?;

    if passphrase.is_empty() {
        return Err(PassphraseError::Cancelled);
    }

    Ok(passphrase)
}

/// Read a new passphrase for key creation (init, import).
///
/// Checks `TXGATE_PASSPHRASE` environment variable first (skips confirmation),
/// then falls back to an interactive prompt with confirmation. The env var is
/// removed from the process environment after reading.
///
/// # Errors
///
/// Returns [`PassphraseError`] if:
/// - The env var is set but too short
/// - The interactive prompt fails, is cancelled, or confirmation doesn't match
pub fn read_new_passphrase() -> Result<Zeroizing<String>, PassphraseError> {
    if let Ok(val) = std::env::var(ENV_VAR) {
        let val = Zeroizing::new(val);
        // Clear env var immediately to minimize exposure window
        clear_env_var(ENV_VAR);
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

    let passphrase = read_password()?;

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

    let confirmation = read_password()?;

    if !constant_time_eq(confirmation.as_bytes(), passphrase.as_bytes()) {
        return Err(PassphraseError::Mismatch);
    }

    Ok(passphrase)
}

/// Read a new passphrase for key export.
///
/// Checks `TXGATE_EXPORT_PASSPHRASE` first (for distinct export passphrase),
/// then falls back to `main_passphrase` if provided (the already-read unlock
/// passphrase sourced from `TXGATE_PASSPHRASE`), then the interactive prompt.
///
/// The `main_passphrase` fallback avoids re-reading `TXGATE_PASSPHRASE` from
/// the environment (which may already be cleared by [`read_passphrase`]).
/// Pass `None` when the unlock passphrase was entered interactively, so the
/// user gets a separate interactive prompt for the export passphrase.
///
/// # Errors
///
/// Returns [`PassphraseError`] if:
/// - The env var is set but too short
/// - The interactive prompt fails, is cancelled, or confirmation doesn't match
pub fn read_new_export_passphrase(
    main_passphrase: Option<&Zeroizing<String>>,
) -> Result<Zeroizing<String>, PassphraseError> {
    if let Ok(val) = std::env::var(EXPORT_ENV_VAR) {
        let val = Zeroizing::new(val);
        // Clear env var immediately to minimize exposure window
        clear_env_var(EXPORT_ENV_VAR);
        if val.is_empty() {
            return Err(PassphraseError::Empty);
        }
        if val.len() < MIN_PASSPHRASE_LENGTH {
            return Err(PassphraseError::TooShort {
                min: MIN_PASSPHRASE_LENGTH,
            });
        }
        eprintln!("Using export passphrase from {EXPORT_ENV_VAR} environment variable");
        return Ok(val);
    }

    // Fall back to the already-read TXGATE_PASSPHRASE value if available.
    // This keeps the passphrase in Zeroizing<String> (zeroized on drop)
    // rather than copying it to a new env var in the C runtime env block
    // (which is NOT zeroized by remove_var).
    if let Some(passphrase) = main_passphrase {
        if passphrase.len() >= MIN_PASSPHRASE_LENGTH {
            eprintln!("Using passphrase from {ENV_VAR} environment variable for export");
            return Ok(Zeroizing::new(String::from(&**passphrase)));
        }
    }

    // Fall back to interactive prompt
    read_new_passphrase()
}

/// Read a password from the terminal, mapping EOF to [`PassphraseError::Cancelled`].
///
/// Returns `Zeroizing<String>` to ensure the password is wiped from memory on drop.
fn read_password() -> Result<Zeroizing<String>, PassphraseError> {
    rpassword::read_password().map(Zeroizing::new).map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            PassphraseError::Cancelled
        } else {
            PassphraseError::Io(e)
        }
    })
}

/// Constant-time byte comparison for passphrase confirmation.
///
/// Prevents timing side-channels by always comparing all bytes
/// regardless of where the first difference occurs. Length comparison
/// is not constant-time, which is acceptable since both values originate
/// from the same user in the same session.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// Clear an environment variable to limit the exposure window.
///
/// This is defense-in-depth: it prevents child processes from inheriting the
/// passphrase. Note that on Linux, `/proc/<pid>/environ` reflects the initial
/// environment and is NOT updated by this call.
///
/// Note: `std::env::remove_var` will require `unsafe` in Rust 2024 edition
/// (see [rust#27970](https://github.com/rust-lang/rust/issues/27970)). When
/// upgrading, this call site will need an `unsafe` block with a safety comment
/// justifying single-threaded access.
fn clear_env_var(var: &str) {
    // Called during single-threaded startup before spawning
    // the tokio runtime, so there are no concurrent readers.
    std::env::remove_var(var);
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use std::sync::Mutex;

    // Mutex to serialize env var tests (env vars are process-global)
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// RAII guard that restores/removes an env var on drop.
    struct EnvGuard {
        var: &'static str,
        original: Option<String>,
    }

    impl EnvGuard {
        fn set(var: &'static str, value: &str) -> Self {
            let original = std::env::var(var).ok();
            std::env::set_var(var, value);
            Self { var, original }
        }

        fn remove(var: &'static str) -> Self {
            let original = std::env::var(var).ok();
            std::env::remove_var(var);
            Self { var, original }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            if let Some(ref val) = self.original {
                std::env::set_var(self.var, val);
            } else {
                std::env::remove_var(self.var);
            }
        }
    }

    // =========================================================================
    // read_passphrase tests (env var path)
    // =========================================================================

    #[test]
    fn test_read_passphrase_from_env_var() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::set(ENV_VAR, "test-passphrase");

        let passphrase = read_passphrase().unwrap();
        assert_eq!(&*passphrase, "test-passphrase");
    }

    #[test]
    fn test_read_passphrase_empty_env_var() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::set(ENV_VAR, "");

        let result = read_passphrase();
        assert!(matches!(result, Err(PassphraseError::Empty)));
    }

    #[test]
    fn test_read_passphrase_clears_env_var() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::set(ENV_VAR, "test-passphrase");

        let _passphrase = read_passphrase().unwrap();
        // Env var should be cleared after reading
        assert!(std::env::var(ENV_VAR).is_err());
    }

    // =========================================================================
    // read_new_passphrase tests (env var path)
    // =========================================================================

    #[test]
    fn test_read_new_passphrase_from_env_var() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::set(ENV_VAR, "longpassphrase");

        let passphrase = read_new_passphrase().unwrap();
        assert_eq!(&*passphrase, "longpassphrase");
    }

    #[test]
    fn test_read_new_passphrase_too_short_env_var() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::set(ENV_VAR, "short");

        let result = read_new_passphrase();
        assert!(matches!(result, Err(PassphraseError::TooShort { min: 8 })));
    }

    #[test]
    fn test_read_new_passphrase_empty_env_var() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::set(ENV_VAR, "");

        let result = read_new_passphrase();
        assert!(matches!(result, Err(PassphraseError::Empty)));
    }

    #[test]
    fn test_read_new_passphrase_exact_min_length() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::set(ENV_VAR, "12345678"); // exactly 8 chars

        let passphrase = read_new_passphrase().unwrap();
        assert_eq!(&*passphrase, "12345678");
    }

    #[test]
    fn test_read_new_passphrase_clears_env_var() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::set(ENV_VAR, "longpassphrase");

        let _passphrase = read_new_passphrase().unwrap();
        assert!(std::env::var(ENV_VAR).is_err());
    }

    // =========================================================================
    // read_new_export_passphrase tests
    // =========================================================================

    #[test]
    fn test_read_new_export_passphrase_from_export_env_var() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard_main = EnvGuard::remove(ENV_VAR);
        let _guard_export = EnvGuard::set(EXPORT_ENV_VAR, "export-pass-123");

        let passphrase = read_new_export_passphrase(None).unwrap();
        assert_eq!(&*passphrase, "export-pass-123");
        // Export env var should be cleared
        assert!(std::env::var(EXPORT_ENV_VAR).is_err());
    }

    #[test]
    fn test_read_new_export_passphrase_falls_back_to_main() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard_export = EnvGuard::remove(EXPORT_ENV_VAR);
        let _guard_main = EnvGuard::remove(ENV_VAR);

        // Simulate: the caller already read TXGATE_PASSPHRASE and passes it
        let main_pass = Zeroizing::new("main-pass-123".to_string());
        let passphrase = read_new_export_passphrase(Some(&main_pass)).unwrap();
        assert_eq!(&*passphrase, "main-pass-123");
    }

    #[test]
    fn test_read_new_export_passphrase_too_short() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard_main = EnvGuard::remove(ENV_VAR);
        let _guard_export = EnvGuard::set(EXPORT_ENV_VAR, "short");

        let result = read_new_export_passphrase(None);
        assert!(matches!(result, Err(PassphraseError::TooShort { min: 8 })));
    }

    #[test]
    fn test_read_new_export_passphrase_empty() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard_main = EnvGuard::remove(ENV_VAR);
        let _guard_export = EnvGuard::set(EXPORT_ENV_VAR, "");

        let result = read_new_export_passphrase(None);
        assert!(matches!(result, Err(PassphraseError::Empty)));
    }

    // =========================================================================
    // Env var clearing on error paths
    // =========================================================================

    #[test]
    fn test_read_passphrase_clears_env_var_on_empty() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::set(ENV_VAR, "");

        let result = read_passphrase();
        assert!(matches!(result, Err(PassphraseError::Empty)));
        // Env var should be cleared even on error
        assert!(std::env::var(ENV_VAR).is_err());
    }

    #[test]
    fn test_read_new_passphrase_clears_env_var_on_too_short() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::set(ENV_VAR, "short");

        let result = read_new_passphrase();
        assert!(matches!(result, Err(PassphraseError::TooShort { min: 8 })));
        // Env var should be cleared even on error
        assert!(std::env::var(ENV_VAR).is_err());
    }

    #[test]
    fn test_read_new_export_passphrase_clears_env_var_on_too_short() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard_main = EnvGuard::remove(ENV_VAR);
        let _guard_export = EnvGuard::set(EXPORT_ENV_VAR, "short");

        let result = read_new_export_passphrase(None);
        assert!(matches!(result, Err(PassphraseError::TooShort { min: 8 })));
        // Export env var should be cleared even on error
        assert!(std::env::var(EXPORT_ENV_VAR).is_err());
    }

    // =========================================================================
    // Env var priority tests
    // =========================================================================

    #[test]
    fn test_read_new_export_passphrase_prefers_export_over_main() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard_export = EnvGuard::set(EXPORT_ENV_VAR, "export-pass-123");
        let _guard_main = EnvGuard::remove(ENV_VAR);

        // Even with a fallback provided, TXGATE_EXPORT_PASSPHRASE takes priority
        let main_pass = Zeroizing::new("main-pass-1234".to_string());
        let passphrase = read_new_export_passphrase(Some(&main_pass)).unwrap();
        assert_eq!(&*passphrase, "export-pass-123");
        // Export env var should be cleared
        assert!(std::env::var(EXPORT_ENV_VAR).is_err());
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
    fn test_error_display_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pipe broken");
        let err = PassphraseError::Io(io_err);
        assert_eq!(err.to_string(), "Failed to read passphrase: pipe broken");
    }

    #[test]
    fn test_passphrase_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<PassphraseError>();
    }

    // =========================================================================
    // Constant-time comparison tests
    // =========================================================================

    #[test]
    fn test_constant_time_eq_equal() {
        assert!(constant_time_eq(b"hello", b"hello"));
    }

    #[test]
    fn test_constant_time_eq_different() {
        assert!(!constant_time_eq(b"hello", b"world"));
    }

    #[test]
    fn test_constant_time_eq_different_length() {
        assert!(!constant_time_eq(b"short", b"longer"));
    }

    #[test]
    fn test_constant_time_eq_empty() {
        assert!(constant_time_eq(b"", b""));
    }
}
