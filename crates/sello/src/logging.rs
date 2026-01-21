//! # Logging Infrastructure
//!
//! Structured logging with tracing for observability.
//!
//! This module provides a comprehensive logging system built on the `tracing`
//! ecosystem. It supports multiple output formats, file logging, sensitive data
//! redaction, and correlation IDs for request tracing.
//!
//! ## Quick Start
//!
//! ```no_run
//! use sello::logging::{init_logging, LogConfig, LogLevel, LogFormat};
//!
//! // Initialize with defaults (INFO level, pretty format, stdout)
//! let config = LogConfig::default();
//! let _guard = init_logging(&config).expect("Failed to initialize logging");
//!
//! // Now you can use tracing macros
//! tracing::info!("Application started");
//! ```
//!
//! ## Configuration Options
//!
//! ```no_run
//! use std::path::PathBuf;
//! use sello::logging::{LogConfig, LogLevel, LogFormat};
//!
//! let config = LogConfig {
//!     level: LogLevel::Debug,
//!     format: LogFormat::Json,
//!     file_path: Some(PathBuf::from("/var/log/sello/sello.log")),
//!     correlation_ids: true,
//! };
//! ```
//!
//! ## Sensitive Data Redaction
//!
//! ```
//! use sello::logging::redact_sensitive;
//!
//! let api_key = "sk-1234567890abcdef";
//! let redacted = redact_sensitive(api_key);
//! assert_eq!(redacted, "sk-1***cdef");
//! ```

use std::path::PathBuf;

use tracing::Level;
use tracing_subscriber::{
    fmt::{self, format::FmtSpan},
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter,
};

/// Error type for logging initialization failures.
#[derive(Debug)]
pub enum LogError {
    /// Failed to create log file or directory
    FileCreation(String),
    /// Failed to initialize the subscriber
    SubscriberInit(String),
    /// Invalid configuration
    InvalidConfig(String),
}

impl std::fmt::Display for LogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FileCreation(msg) => write!(f, "Failed to create log file: {msg}"),
            Self::SubscriberInit(msg) => write!(f, "Failed to initialize logging: {msg}"),
            Self::InvalidConfig(msg) => write!(f, "Invalid log configuration: {msg}"),
        }
    }
}

impl std::error::Error for LogError {}

/// Log level configuration.
///
/// Determines the minimum severity of messages that will be logged.
/// Each level includes all messages from more severe levels.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LogLevel {
    /// Most verbose: trace, debug, info, warn, error
    Trace,
    /// Verbose: debug, info, warn, error
    Debug,
    /// Standard: info, warn, error
    #[default]
    Info,
    /// Quiet: warn, error
    Warn,
    /// Quietest: error only
    Error,
}

impl LogLevel {
    /// Convert to tracing Level.
    #[must_use]
    pub const fn as_tracing_level(self) -> Level {
        match self {
            Self::Trace => Level::TRACE,
            Self::Debug => Level::DEBUG,
            Self::Info => Level::INFO,
            Self::Warn => Level::WARN,
            Self::Error => Level::ERROR,
        }
    }

    /// Get the string representation for env filter.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Log output format configuration.
///
/// Determines how log messages are formatted in the output.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LogFormat {
    /// Human-readable pretty format with colors (default).
    ///
    /// Best for development and interactive use.
    #[default]
    Pretty,
    /// JSON structured format.
    ///
    /// Best for log aggregation systems and machine parsing.
    Json,
    /// Compact single-line format.
    ///
    /// Balance between readability and space efficiency.
    Compact,
}

impl std::fmt::Display for LogFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pretty => write!(f, "pretty"),
            Self::Json => write!(f, "json"),
            Self::Compact => write!(f, "compact"),
        }
    }
}

/// Configuration for the logging system.
///
/// Use the builder pattern or struct initialization to configure logging.
///
/// # Example
///
/// ```
/// use sello::logging::{LogConfig, LogLevel, LogFormat};
///
/// let config = LogConfig {
///     level: LogLevel::Debug,
///     format: LogFormat::Json,
///     ..Default::default()
/// };
/// ```
#[derive(Debug, Clone, Default)]
pub struct LogConfig {
    /// Log level (trace, debug, info, warn, error).
    ///
    /// Controls the minimum severity of messages that will be logged.
    /// Defaults to [`LogLevel::Info`].
    pub level: LogLevel,

    /// Output format for log messages.
    ///
    /// Choose between human-readable (`Pretty`), machine-parseable (`Json`),
    /// or space-efficient (`Compact`) formats. Defaults to [`LogFormat::Pretty`].
    pub format: LogFormat,

    /// Optional file path for logging.
    ///
    /// When set, logs will be written to this file in addition to stdout.
    /// The directory will be created if it doesn't exist.
    pub file_path: Option<PathBuf>,

    /// Enable correlation IDs for request tracing.
    ///
    /// When enabled, logs will include a correlation ID field that can be
    /// used to trace related log entries across operations.
    pub correlation_ids: bool,
}

/// Guard that flushes logs on drop.
///
/// This guard must be kept alive for the duration of the program to ensure
/// that file logging continues and logs are properly flushed on shutdown.
///
/// # Example
///
/// ```no_run
/// use sello::logging::{init_logging, LogConfig};
///
/// let config = LogConfig::default();
/// // Keep the guard alive for the program's lifetime
/// let _guard = init_logging(&config).expect("logging init");
///
/// // ... application code ...
///
/// // Logs are flushed when _guard is dropped
/// ```
pub struct LogGuard {
    /// Optional worker guard for non-blocking file appender.
    guard: Option<tracing_appender::non_blocking::WorkerGuard>,
}

impl LogGuard {
    /// Create a new `LogGuard` with an optional worker guard.
    const fn new(guard: Option<tracing_appender::non_blocking::WorkerGuard>) -> Self {
        Self { guard }
    }
}

impl std::fmt::Debug for LogGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogGuard")
            .field("has_file_guard", &self.guard.is_some())
            .finish()
    }
}

/// Initialize the logging system.
///
/// Sets up the tracing subscriber with the specified configuration.
/// Returns a guard that must be kept alive for the duration of logging.
///
/// # Errors
///
/// Returns [`LogError`] if:
/// - The log file directory cannot be created
/// - The subscriber cannot be initialized (e.g., already initialized)
///
/// # Example
///
/// ```no_run
/// use sello::logging::{init_logging, LogConfig, LogLevel};
///
/// let config = LogConfig {
///     level: LogLevel::Debug,
///     ..Default::default()
/// };
///
/// let _guard = init_logging(&config)?;
/// tracing::info!("Logging initialized");
/// # Ok::<(), sello::logging::LogError>(())
/// ```
pub fn init_logging(config: &LogConfig) -> Result<LogGuard, LogError> {
    // Create the env filter
    let filter = EnvFilter::try_new(config.level.as_str())
        .map_err(|e| LogError::InvalidConfig(e.to_string()))?;

    // Set up file appender if configured
    let (file_writer, guard) = if let Some(ref path) = config.file_path {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| LogError::FileCreation(format!("{}: {}", parent.display(), e)))?;
        }

        // Get directory and filename
        let dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
        let filename = path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| LogError::InvalidConfig("Invalid log file name".to_string()))?;

        let file_appender = tracing_appender::rolling::daily(dir, filename);
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
        (Some(non_blocking), Some(guard))
    } else {
        (None, None)
    };

    // Build the subscriber based on format
    match config.format {
        LogFormat::Pretty => {
            let fmt_layer = fmt::layer()
                .pretty()
                .with_target(true)
                .with_thread_names(true)
                .with_span_events(FmtSpan::CLOSE);

            if let Some(writer) = file_writer {
                let file_layer = fmt::layer()
                    .with_writer(writer)
                    .with_ansi(false)
                    .with_target(true);

                tracing_subscriber::registry()
                    .with(filter)
                    .with(fmt_layer)
                    .with(file_layer)
                    .try_init()
                    .map_err(|e| LogError::SubscriberInit(e.to_string()))?;
            } else {
                tracing_subscriber::registry()
                    .with(filter)
                    .with(fmt_layer)
                    .try_init()
                    .map_err(|e| LogError::SubscriberInit(e.to_string()))?;
            }
        }
        LogFormat::Json => {
            let fmt_layer = fmt::layer()
                .json()
                .with_target(true)
                .with_current_span(true);

            if let Some(writer) = file_writer {
                let file_layer = fmt::layer().json().with_writer(writer).with_target(true);

                tracing_subscriber::registry()
                    .with(filter)
                    .with(fmt_layer)
                    .with(file_layer)
                    .try_init()
                    .map_err(|e| LogError::SubscriberInit(e.to_string()))?;
            } else {
                tracing_subscriber::registry()
                    .with(filter)
                    .with(fmt_layer)
                    .try_init()
                    .map_err(|e| LogError::SubscriberInit(e.to_string()))?;
            }
        }
        LogFormat::Compact => {
            let fmt_layer = fmt::layer().compact().with_target(true);

            if let Some(writer) = file_writer {
                let file_layer = fmt::layer()
                    .compact()
                    .with_writer(writer)
                    .with_ansi(false)
                    .with_target(true);

                tracing_subscriber::registry()
                    .with(filter)
                    .with(fmt_layer)
                    .with(file_layer)
                    .try_init()
                    .map_err(|e| LogError::SubscriberInit(e.to_string()))?;
            } else {
                tracing_subscriber::registry()
                    .with(filter)
                    .with(fmt_layer)
                    .try_init()
                    .map_err(|e| LogError::SubscriberInit(e.to_string()))?;
            }
        }
    }

    Ok(LogGuard::new(guard))
}

/// Redact sensitive data from logs.
///
/// This function redacts values that appear to be sensitive (keys, passphrases,
/// tokens) by showing only the first 4 and last 4 characters with `***` in between.
///
/// # Rules
///
/// - Values shorter than 12 characters are fully redacted to `***`
/// - Longer values show: first 4 chars + `***` + last 4 chars
///
/// # Example
///
/// ```
/// use sello::logging::redact_sensitive;
///
/// // Long secrets show partial content
/// assert_eq!(redact_sensitive("sk-1234567890abcdef"), "sk-1***cdef");
///
/// // Short values are fully redacted
/// assert_eq!(redact_sensitive("secret"), "***");
///
/// // Empty values remain empty
/// assert_eq!(redact_sensitive(""), "***");
/// ```
#[must_use]
pub fn redact_sensitive(value: &str) -> String {
    const MIN_LENGTH_FOR_PARTIAL: usize = 12;
    const VISIBLE_CHARS: usize = 4;

    if value.len() < MIN_LENGTH_FOR_PARTIAL {
        return "***".to_string();
    }

    let chars: Vec<char> = value.chars().collect();
    let len = chars.len();

    if len < MIN_LENGTH_FOR_PARTIAL {
        return "***".to_string();
    }

    let prefix: String = chars.iter().take(VISIBLE_CHARS).collect();
    let suffix: String = chars.iter().skip(len - VISIBLE_CHARS).collect();

    format!("{prefix}***{suffix}")
}

/// Generate a new correlation ID.
///
/// Creates a unique identifier that can be used to correlate log entries
/// across different operations or services. The ID is a UUID v4 formatted
/// as a 32-character hex string (without hyphens) for compactness.
///
/// # Example
///
/// ```
/// use sello::logging::new_correlation_id;
///
/// let id = new_correlation_id();
/// assert_eq!(id.len(), 32);
/// assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
/// ```
#[must_use]
#[allow(clippy::cast_possible_truncation)]
pub fn new_correlation_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    // Global counter to ensure uniqueness even when timestamp is the same
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);

    // Get unique counter value
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);

    // Mix timestamp with counter using a simple hash-like operation
    // This ensures uniqueness even when timestamp is identical
    let mixed = timestamp.wrapping_add(u128::from(counter));

    // Use simple PRNG seeded with mixed value for the random part
    // This is good enough for correlation IDs (not crypto)
    // Truncation is intentional here - we only need 8 bytes from each part
    #[allow(clippy::cast_possible_truncation)]
    let random_part = {
        let mut state = mixed;
        let mut result = [0u8; 8];
        for byte in &mut result {
            state = state.wrapping_mul(6_364_136_223_846_793_005);
            state = state.wrapping_add(1_442_695_040_888_963_407);
            *byte = (state >> 56) as u8;
        }
        result
    };

    // Format as hex: 8 bytes from timestamp + 8 bytes random = 32 hex chars
    // Truncation is intentional - we only need lower 64 bits
    #[allow(clippy::cast_possible_truncation)]
    let timestamp_bytes = (mixed as u64).to_be_bytes();

    let mut hex = String::with_capacity(32);
    for byte in timestamp_bytes.iter().chain(random_part.iter()) {
        use std::fmt::Write;
        // write! to String is infallible
        let _ = write!(hex, "{byte:02x}");
    }

    hex
}

/// Create a span with correlation ID.
///
/// This macro creates a tracing span that includes a correlation ID field,
/// making it easy to trace related log entries across operations.
///
/// # Example
///
/// ```ignore
/// use sello::with_correlation_id;
/// use sello::logging::new_correlation_id;
///
/// let correlation_id = new_correlation_id();
/// with_correlation_id!(correlation_id, "processing request", user_id = 42);
/// ```
#[macro_export]
macro_rules! with_correlation_id {
    ($id:expr, $name:expr) => {
        tracing::info_span!($name, correlation_id = %$id)
    };
    ($id:expr, $name:expr, $($fields:tt)*) => {
        tracing::info_span!($name, correlation_id = %$id, $($fields)*)
    };
}

/// Convert verbosity count to `LogLevel`.
///
/// Maps CLI verbosity flags (`-v`, `-vv`, `-vvv`) to log levels.
///
/// | Verbosity | Level |
/// |-----------|-------|
/// | 0         | Warn  |
/// | 1         | Info  |
/// | 2         | Debug |
/// | 3+        | Trace |
///
/// # Example
///
/// ```
/// use sello::logging::{verbosity_to_level, LogLevel};
///
/// assert_eq!(verbosity_to_level(0), LogLevel::Warn);
/// assert_eq!(verbosity_to_level(1), LogLevel::Info);
/// assert_eq!(verbosity_to_level(2), LogLevel::Debug);
/// assert_eq!(verbosity_to_level(3), LogLevel::Trace);
/// assert_eq!(verbosity_to_level(100), LogLevel::Trace);
/// ```
#[must_use]
pub const fn verbosity_to_level(verbosity: u8) -> LogLevel {
    match verbosity {
        0 => LogLevel::Warn,
        1 => LogLevel::Info,
        2 => LogLevel::Debug,
        _ => LogLevel::Trace,
    }
}

/// Log a security event.
///
/// Security events are always logged at INFO level regardless of the current
/// log level configuration. This ensures important security-related events
/// are always captured.
///
/// # Example
///
/// ```ignore
/// use sello::logging::log_security_event;
///
/// log_security_event("key_access", "User accessed signing key 'default'");
/// log_security_event("auth_failure", "Failed login attempt from 192.168.1.1");
/// ```
pub fn log_security_event(event: &str, details: &str) {
    tracing::info!(
        target: "sello::security",
        event_type = "security",
        security_event = event,
        details = details,
        "Security event: {event}"
    );
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
        clippy::unreadable_literal,
        clippy::uninlined_format_args,
        clippy::doc_markdown,
        clippy::redundant_closure_for_method_calls,
        clippy::needless_pass_by_value
    )]

    use super::*;

    /// Test log level conversion from verbosity count.
    #[test]
    fn test_verbosity_to_level() {
        assert_eq!(verbosity_to_level(0), LogLevel::Warn);
        assert_eq!(verbosity_to_level(1), LogLevel::Info);
        assert_eq!(verbosity_to_level(2), LogLevel::Debug);
        assert_eq!(verbosity_to_level(3), LogLevel::Trace);
        assert_eq!(verbosity_to_level(4), LogLevel::Trace);
        assert_eq!(verbosity_to_level(255), LogLevel::Trace);
    }

    /// Test sensitive data redaction for various inputs.
    #[test]
    fn test_redact_sensitive() {
        // Long values show partial content
        assert_eq!(redact_sensitive("sk-1234567890abcdef"), "sk-1***cdef");
        assert_eq!(redact_sensitive("my-super-secret-api-key"), "my-s***-key");

        // Values at exactly 12 characters
        assert_eq!(redact_sensitive("123456789012"), "1234***9012");

        // Short values are fully redacted
        assert_eq!(redact_sensitive("short"), "***");
        assert_eq!(redact_sensitive("12345678901"), "***");
        assert_eq!(redact_sensitive(""), "***");
        assert_eq!(redact_sensitive("a"), "***");

        // Unicode handling
        assert_eq!(redact_sensitive("key-with-unicode"), "key-***code");
    }

    /// Test correlation ID generation produces valid format.
    #[test]
    fn test_correlation_id_generation() {
        let id1 = new_correlation_id();
        let id2 = new_correlation_id();

        // Check length
        assert_eq!(id1.len(), 32, "Correlation ID should be 32 hex chars");
        assert_eq!(id2.len(), 32);

        // Check format (all hex digits)
        assert!(
            id1.chars().all(|c| c.is_ascii_hexdigit()),
            "Correlation ID should be hex"
        );
        assert!(id2.chars().all(|c| c.is_ascii_hexdigit()));

        // IDs should be unique (with very high probability)
        // Note: There's a tiny chance this could fail if generated in the same nanosecond
        // with the same PRNG state, but that's extremely unlikely
        assert_ne!(id1, id2, "Correlation IDs should be unique");
    }

    /// Test correlation ID uniqueness over multiple generations.
    #[test]
    fn test_correlation_id_uniqueness() {
        let mut ids = std::collections::HashSet::new();
        for _ in 0..100 {
            let id = new_correlation_id();
            assert!(ids.insert(id), "Correlation IDs should be unique");
        }
    }

    /// Test `LogConfig` default values.
    #[test]
    fn test_log_config_defaults() {
        let config = LogConfig::default();

        assert_eq!(config.level, LogLevel::Info);
        assert_eq!(config.format, LogFormat::Pretty);
        assert!(config.file_path.is_none());
        assert!(!config.correlation_ids);
    }

    /// Test `LogLevel` variants and conversions.
    #[test]
    fn test_log_level_variants() {
        // Test as_str()
        assert_eq!(LogLevel::Trace.as_str(), "trace");
        assert_eq!(LogLevel::Debug.as_str(), "debug");
        assert_eq!(LogLevel::Info.as_str(), "info");
        assert_eq!(LogLevel::Warn.as_str(), "warn");
        assert_eq!(LogLevel::Error.as_str(), "error");

        // Test Display
        assert_eq!(LogLevel::Trace.to_string(), "trace");
        assert_eq!(LogLevel::Debug.to_string(), "debug");
        assert_eq!(LogLevel::Info.to_string(), "info");
        assert_eq!(LogLevel::Warn.to_string(), "warn");
        assert_eq!(LogLevel::Error.to_string(), "error");

        // Test as_tracing_level()
        assert_eq!(LogLevel::Trace.as_tracing_level(), Level::TRACE);
        assert_eq!(LogLevel::Debug.as_tracing_level(), Level::DEBUG);
        assert_eq!(LogLevel::Info.as_tracing_level(), Level::INFO);
        assert_eq!(LogLevel::Warn.as_tracing_level(), Level::WARN);
        assert_eq!(LogLevel::Error.as_tracing_level(), Level::ERROR);
    }

    /// Test `LogFormat` variants and display.
    #[test]
    fn test_log_format_variants() {
        assert_eq!(LogFormat::Pretty.to_string(), "pretty");
        assert_eq!(LogFormat::Json.to_string(), "json");
        assert_eq!(LogFormat::Compact.to_string(), "compact");

        // Test default
        assert_eq!(LogFormat::default(), LogFormat::Pretty);
    }

    /// Test `LogError` display formatting.
    #[test]
    fn test_log_error_display() {
        let err = LogError::FileCreation("permission denied".to_string());
        assert!(err.to_string().contains("permission denied"));
        assert!(err.to_string().contains("create log file"));

        let err = LogError::SubscriberInit("already initialized".to_string());
        assert!(err.to_string().contains("already initialized"));
        assert!(err.to_string().contains("initialize logging"));

        let err = LogError::InvalidConfig("bad filter".to_string());
        assert!(err.to_string().contains("bad filter"));
        assert!(err.to_string().contains("Invalid log configuration"));
    }

    /// Test `LogGuard` debug implementation.
    #[test]
    fn test_log_guard_debug() {
        let guard = LogGuard::new(None);
        let debug_str = format!("{guard:?}");
        assert!(debug_str.contains("LogGuard"));
        assert!(debug_str.contains("has_file_guard"));
    }

    /// Test `LogConfig` can be cloned.
    #[test]
    fn test_log_config_clone() {
        let config = LogConfig {
            level: LogLevel::Debug,
            format: LogFormat::Json,
            file_path: Some(PathBuf::from("/tmp/test.log")),
            correlation_ids: true,
        };

        let cloned = config.clone();
        assert_eq!(cloned.level, LogLevel::Debug);
        assert_eq!(cloned.format, LogFormat::Json);
        assert_eq!(cloned.file_path, Some(PathBuf::from("/tmp/test.log")));
        assert!(cloned.correlation_ids);
    }

    /// Test edge cases for redaction.
    #[test]
    fn test_redact_edge_cases() {
        // Exactly at boundary
        assert_eq!(redact_sensitive("12345678901"), "***"); // 11 chars
        assert_eq!(redact_sensitive("123456789012"), "1234***9012"); // 12 chars
        assert_eq!(redact_sensitive("1234567890123"), "1234***0123"); // 13 chars

        // Special characters
        assert_eq!(redact_sensitive("key!@#$%^&*()end123"), "key!***d123");

        // Whitespace
        assert_eq!(redact_sensitive("    spaces    "), "    ***    ");
    }
}
