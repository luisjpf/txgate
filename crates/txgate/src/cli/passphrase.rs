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
use std::path::Path;

use txgate_core::config_loader::ConfigLoader;
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

/// Resolve whether env-var passphrases are allowed by loading config.
///
/// Delegates to [`resolve_allow_env_for_base_dir`] with the default
/// base directory (`~/.txgate`). Each passphrase call re-reads from
/// disk, which is negligible for a CLI tool that reads config at most
/// 2–3 times per invocation.
fn resolve_allow_env() -> bool {
    let Ok(base_dir) = txgate_core::config_loader::default_base_dir() else {
        // Can't determine home dir — allow env for backward compat
        return true;
    };
    resolve_allow_env_for_base_dir(&base_dir)
}

/// Resolve whether env-var passphrases are allowed, given a base directory.
///
/// Returns `true` if:
/// - `allow_env_passphrase = true` in `<base_dir>/config.toml`, or
/// - No config file exists (e.g., before `txgate init`)
///
/// Returns `false` if the config file exists with the default
/// `allow_env_passphrase = false`, or if the config is unparseable
/// (fail-closed).
pub(crate) fn resolve_allow_env_for_base_dir(base_dir: &Path) -> bool {
    let loader = ConfigLoader::with_base_dir(base_dir.to_path_buf());
    if !loader.exists() {
        // No config file yet (pre-init, import, etc.) — allow env
        return true;
    }
    match loader.load() {
        Ok(config) => config.server.allow_env_passphrase,
        Err(_) => {
            // Config exists but can't be parsed — be conservative, deny
            false
        }
    }
}

/// Read a passphrase for unlocking an existing key.
///
/// When `allow_env_passphrase` is `true` in the config (or no config file
/// exists), checks the `TXGATE_PASSPHRASE` environment variable first,
/// then falls back to an interactive `rpassword` prompt.
/// When the config sets `allow_env_passphrase = false`, the environment
/// variable is ignored (with a warning if it is set) and only the
/// interactive prompt is used.
///
/// The env var is removed from the process environment after reading to
/// limit exposure.
///
/// # Errors
///
/// Returns [`PassphraseError`] if:
/// - The env var is set but empty (when env passphrases are allowed)
/// - The interactive prompt fails or is cancelled
pub fn read_passphrase() -> Result<Zeroizing<String>, PassphraseError> {
    read_passphrase_inner(resolve_allow_env())
}

/// Inner implementation with explicit `allow_env` flag for testability.
pub(crate) fn read_passphrase_inner(allow_env: bool) -> Result<Zeroizing<String>, PassphraseError> {
    if let Ok(val) = std::env::var(ENV_VAR) {
        if allow_env {
            let val = Zeroizing::new(val);
            // Clear env var immediately to minimize exposure window
            clear_env_var(ENV_VAR);
            if val.is_empty() {
                return Err(PassphraseError::Empty);
            }
            eprintln!("Using passphrase from {ENV_VAR} environment variable");
            return Ok(val);
        }
        // Clear env var even when ignoring it (defense-in-depth:
        // prevents child processes from inheriting the secret).
        clear_env_var(ENV_VAR);
        eprintln!(
            "Warning: {ENV_VAR} is set but allow_env_passphrase is false in config. \
             Ignoring env var."
        );
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
/// When `allow_env_passphrase` is `true` in the config (or no config file
/// exists), checks `TXGATE_PASSPHRASE` environment variable first (skips
/// confirmation), then falls back to an interactive prompt with confirmation.
/// When the config sets `allow_env_passphrase = false`, the environment
/// variable is ignored (with a warning if it is set) and only the interactive
/// prompt is used. The env var is removed from the process environment after
/// reading.
///
/// # Errors
///
/// Returns [`PassphraseError`] if:
/// - The env var is set but too short (when env passphrases are allowed)
/// - The interactive prompt fails, is cancelled, or confirmation doesn't match
pub fn read_new_passphrase() -> Result<Zeroizing<String>, PassphraseError> {
    read_new_passphrase_inner(resolve_allow_env())
}

/// Inner implementation with explicit `allow_env` flag for testability.
pub(crate) fn read_new_passphrase_inner(
    allow_env: bool,
) -> Result<Zeroizing<String>, PassphraseError> {
    if let Ok(val) = std::env::var(ENV_VAR) {
        if allow_env {
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
        // Clear env var even when ignoring it (defense-in-depth:
        // prevents child processes from inheriting the secret).
        clear_env_var(ENV_VAR);
        eprintln!(
            "Warning: {ENV_VAR} is set but allow_env_passphrase is false in config. \
             Ignoring env var."
        );
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
/// When `allow_env_passphrase` is `false` in the config, env-var and
/// `main_passphrase` fallbacks are skipped and only the interactive prompt
/// is used.
///
/// The `main_passphrase` fallback avoids re-reading `TXGATE_PASSPHRASE` from
/// the environment (which may already be cleared by [`read_passphrase`]).
/// Pass `None` when the unlock passphrase was entered interactively, so the
/// user gets a separate interactive prompt for the export passphrase.
///
/// # Errors
///
/// Returns [`PassphraseError`] if:
/// - The env var is set but too short (when env passphrases are allowed)
/// - The interactive prompt fails, is cancelled, or confirmation doesn't match
pub fn read_new_export_passphrase(
    main_passphrase: Option<&Zeroizing<String>>,
) -> Result<Zeroizing<String>, PassphraseError> {
    read_new_export_passphrase_inner(main_passphrase, resolve_allow_env())
}

/// Inner implementation with explicit `allow_env` flag for testability.
pub(crate) fn read_new_export_passphrase_inner(
    main_passphrase: Option<&Zeroizing<String>>,
    allow_env: bool,
) -> Result<Zeroizing<String>, PassphraseError> {
    if allow_env {
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
    } else if std::env::var(EXPORT_ENV_VAR).is_ok() {
        // Clear export env var even when ignoring it (defense-in-depth).
        clear_env_var(EXPORT_ENV_VAR);
        eprintln!(
            "Warning: {EXPORT_ENV_VAR} is set but allow_env_passphrase is false in config. \
             Ignoring env var."
        );
    }

    // Fall back to interactive prompt.
    // Note: when allow_env=true and no export env var was set, this re-checks
    // TXGATE_PASSPHRASE — which has already been cleared by the preceding
    // read_passphrase() call, so it safely falls through to the interactive prompt.
    read_new_passphrase_inner(allow_env)
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

        let passphrase = read_passphrase_inner(true).unwrap();
        assert_eq!(&*passphrase, "test-passphrase");
    }

    #[test]
    fn test_read_passphrase_empty_env_var() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::set(ENV_VAR, "");

        let result = read_passphrase_inner(true);
        assert!(matches!(result, Err(PassphraseError::Empty)));
    }

    #[test]
    fn test_read_passphrase_clears_env_var() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::set(ENV_VAR, "test-passphrase");

        let _passphrase = read_passphrase_inner(true).unwrap();
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

        let passphrase = read_new_passphrase_inner(true).unwrap();
        assert_eq!(&*passphrase, "longpassphrase");
    }

    #[test]
    fn test_read_new_passphrase_too_short_env_var() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::set(ENV_VAR, "short");

        let result = read_new_passphrase_inner(true);
        assert!(matches!(result, Err(PassphraseError::TooShort { min: 8 })));
    }

    #[test]
    fn test_read_new_passphrase_empty_env_var() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::set(ENV_VAR, "");

        let result = read_new_passphrase_inner(true);
        assert!(matches!(result, Err(PassphraseError::Empty)));
    }

    #[test]
    fn test_read_new_passphrase_exact_min_length() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::set(ENV_VAR, "12345678"); // exactly 8 chars

        let passphrase = read_new_passphrase_inner(true).unwrap();
        assert_eq!(&*passphrase, "12345678");
    }

    #[test]
    fn test_read_new_passphrase_clears_env_var() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::set(ENV_VAR, "longpassphrase");

        let _passphrase = read_new_passphrase_inner(true).unwrap();
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

        let passphrase = read_new_export_passphrase_inner(None, true).unwrap();
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
        let passphrase = read_new_export_passphrase_inner(Some(&main_pass), true).unwrap();
        assert_eq!(&*passphrase, "main-pass-123");
    }

    #[test]
    fn test_read_new_export_passphrase_too_short() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard_main = EnvGuard::remove(ENV_VAR);
        let _guard_export = EnvGuard::set(EXPORT_ENV_VAR, "short");

        let result = read_new_export_passphrase_inner(None, true);
        assert!(matches!(result, Err(PassphraseError::TooShort { min: 8 })));
    }

    #[test]
    fn test_read_new_export_passphrase_empty() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard_main = EnvGuard::remove(ENV_VAR);
        let _guard_export = EnvGuard::set(EXPORT_ENV_VAR, "");

        let result = read_new_export_passphrase_inner(None, true);
        assert!(matches!(result, Err(PassphraseError::Empty)));
    }

    // =========================================================================
    // Env var clearing on error paths
    // =========================================================================

    #[test]
    fn test_read_passphrase_clears_env_var_on_empty() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::set(ENV_VAR, "");

        let result = read_passphrase_inner(true);
        assert!(matches!(result, Err(PassphraseError::Empty)));
        // Env var should be cleared even on error
        assert!(std::env::var(ENV_VAR).is_err());
    }

    #[test]
    fn test_read_new_passphrase_clears_env_var_on_too_short() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::set(ENV_VAR, "short");

        let result = read_new_passphrase_inner(true);
        assert!(matches!(result, Err(PassphraseError::TooShort { min: 8 })));
        // Env var should be cleared even on error
        assert!(std::env::var(ENV_VAR).is_err());
    }

    #[test]
    fn test_read_new_export_passphrase_clears_env_var_on_too_short() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard_main = EnvGuard::remove(ENV_VAR);
        let _guard_export = EnvGuard::set(EXPORT_ENV_VAR, "short");

        let result = read_new_export_passphrase_inner(None, true);
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
        let passphrase = read_new_export_passphrase_inner(Some(&main_pass), true).unwrap();
        assert_eq!(&*passphrase, "export-pass-123");
        // Export env var should be cleared
        assert!(std::env::var(EXPORT_ENV_VAR).is_err());
    }

    // =========================================================================
    // resolve_allow_env tests
    // =========================================================================

    #[test]
    fn test_resolve_allow_env_no_config_file() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        // No config file => allow env (backward compat for pre-init)
        assert!(resolve_allow_env_for_base_dir(temp_dir.path()));
    }

    #[test]
    fn test_resolve_allow_env_default_config() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.toml");
        std::fs::write(&config_path, "[server]\n").unwrap();
        // Default config has allow_env_passphrase = false
        assert!(!resolve_allow_env_for_base_dir(temp_dir.path()));
    }

    #[test]
    fn test_resolve_allow_env_enabled() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.toml");
        std::fs::write(&config_path, "[server]\nallow_env_passphrase = true\n").unwrap();
        assert!(resolve_allow_env_for_base_dir(temp_dir.path()));
    }

    #[test]
    fn test_resolve_allow_env_broken_config() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.toml");
        std::fs::write(&config_path, "not valid toml {{{").unwrap();
        // Broken config => deny (fail-closed)
        assert!(!resolve_allow_env_for_base_dir(temp_dir.path()));
    }

    // =========================================================================
    // allow_env=false tests (deny path)
    // =========================================================================

    #[test]
    fn test_read_passphrase_inner_false_ignores_and_clears_env_var() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::set(ENV_VAR, "should-be-ignored");

        // allow_env=false: should ignore env var and try interactive prompt
        // (which fails in test — no TTY)
        let result = read_passphrase_inner(false);
        assert!(result.is_err());
        // Env var should be cleared even when ignored (defense-in-depth)
        assert!(std::env::var(ENV_VAR).is_err());
    }

    #[test]
    fn test_read_new_passphrase_inner_false_ignores_and_clears_env_var() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::set(ENV_VAR, "longpassphrase-ignored");

        let result = read_new_passphrase_inner(false);
        assert!(result.is_err());
        assert!(std::env::var(ENV_VAR).is_err());
    }

    #[test]
    fn test_read_new_export_passphrase_inner_false_ignores_and_clears_env_var() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard_main = EnvGuard::remove(ENV_VAR);
        let _guard_export = EnvGuard::set(EXPORT_ENV_VAR, "export-pass-ignored");

        let result = read_new_export_passphrase_inner(None, false);
        assert!(result.is_err());
        // Export env var should be cleared even when ignored
        assert!(std::env::var(EXPORT_ENV_VAR).is_err());
    }

    #[test]
    fn test_read_new_export_passphrase_inner_false_ignores_main_passphrase() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard_main = EnvGuard::remove(ENV_VAR);
        let _guard_export = EnvGuard::remove(EXPORT_ENV_VAR);

        // Even with a valid main passphrase, allow_env=false should ignore it
        let main_pass = Zeroizing::new("main-pass-123".to_string());
        let result = read_new_export_passphrase_inner(Some(&main_pass), false);
        // Falls through to interactive prompt (fails in test)
        assert!(result.is_err());
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
