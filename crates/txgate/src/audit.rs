//! # Audit Logging with HMAC Chain
//!
//! Provides tamper-evident audit logging for security-critical signing events.
//!
//! This module implements a cryptographically chained audit log using HMAC-SHA256.
//! Each log entry includes an HMAC computed over the entry data concatenated with
//! the previous entry's HMAC, creating a tamper-evident chain that can detect
//! any modifications to historical log entries.
//!
//! ## Features
//!
//! - **HMAC Chain**: Each entry is cryptographically linked to the previous entry
//! - **Tamper Detection**: Verification can detect any modifications to the log
//! - **Thread-Safe**: Safe for concurrent logging from multiple threads
//! - **Log Rotation**: Automatic rotation when file size exceeds threshold
//! - **Gzip Compression**: Rotated files are compressed to save space
//!
//! ## Security Properties
//!
//! - Forward integrity: Tampering with any entry invalidates all subsequent HMACs
//! - Key protection: HMAC key must be stored securely (separate from logs)
//! - Non-repudiation: Entries cannot be modified without detection
//!
//! ## Example
//!
//! ```no_run
//! use txgate::audit::{AuditLogger, SignEvent, PolicyResultInput};
//! use std::path::Path;
//!
//! // Initialize with a 32-byte HMAC key
//! let key = [0u8; 32]; // In production, use a secure random key
//! let logger = AuditLogger::new(Path::new("/var/log/txgate"), &key)
//!     .expect("Failed to create audit logger");
//!
//! // Log a signing event
//! let event = SignEvent {
//!     correlation_id: "abc123".to_string(),
//!     chain: "ethereum".to_string(),
//!     tx_hash: [0u8; 32],
//!     recipient: Some([0u8; 20]),
//!     amount: "1000000000000000000".to_string(), // 1 ETH in wei
//!     token: None,
//!     tx_type: "transfer".to_string(),
//!     policy_result: PolicyResultInput::Allowed,
//!     signature: None,
//! };
//!
//! logger.log_sign_event(event).expect("Failed to log event");
//!
//! // Verify chain integrity
//! let result = logger.verify_chain().expect("Verification failed");
//! assert!(result.valid);
//! ```

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use chrono::Utc;
use flate2::write::GzEncoder;
use flate2::Compression;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

/// Type alias for HMAC-SHA256.
type HmacSha256 = Hmac<Sha256>;

/// Default maximum file size before rotation (10 MB).
const DEFAULT_MAX_FILE_SIZE: u64 = 10 * 1024 * 1024;

/// Name of the audit log file.
const AUDIT_LOG_FILENAME: &str = "audit.jsonl";

/// Name of the HMAC key file.
const AUDIT_KEY_FILENAME: &str = "audit.key";

/// Initial HMAC value for the first entry in a chain.
///
/// This is a fixed value used as the "previous HMAC" for the first entry,
/// ensuring deterministic verification.
const INITIAL_HMAC: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Audit log entry stored in JSONL format.
///
/// Each entry contains transaction details and a cryptographic HMAC
/// that chains it to the previous entry for tamper detection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEntry {
    /// Sequence number (monotonically increasing).
    ///
    /// Used to detect missing or reordered entries.
    pub seq: u64,

    /// ISO 8601 timestamp when the event occurred.
    pub timestamp: String,

    /// Correlation ID for request tracing.
    ///
    /// Links this audit entry to related logs and requests.
    pub correlation_id: String,

    /// Blockchain network identifier (e.g., "ethereum", "polygon").
    pub chain: String,

    /// Transaction hash being signed (hex-encoded with 0x prefix).
    pub tx_hash: String,

    /// Recipient address (hex-encoded with 0x prefix, if applicable).
    pub recipient: Option<String>,

    /// Transfer amount as a decimal string (in smallest unit).
    pub amount: String,

    /// Token contract address (hex-encoded, `None` for native token).
    pub token: Option<String>,

    /// Transaction type (e.g., "transfer", "`token_transfer`", "`contract_call`").
    pub tx_type: String,

    /// Policy evaluation result ("allowed" or "denied").
    pub policy_result: String,

    /// Cryptographic signature (hex-encoded, if signing occurred).
    pub signature: Option<String>,

    /// HMAC-SHA256 of this entry concatenated with previous HMAC.
    ///
    /// This creates a cryptographic chain for tamper detection.
    pub hmac: String,
}

/// Input event for logging a signing operation.
///
/// This struct captures all relevant details about a signing event
/// before it is transformed into an [`AuditEntry`].
#[derive(Debug, Clone)]
pub struct SignEvent {
    /// Correlation ID for request tracing.
    pub correlation_id: String,

    /// Blockchain network identifier.
    pub chain: String,

    /// Transaction hash (32 bytes).
    pub tx_hash: [u8; 32],

    /// Recipient address (20 bytes, for Ethereum-compatible chains).
    pub recipient: Option<[u8; 20]>,

    /// Transfer amount as a decimal string.
    ///
    /// Using string representation to avoid precision loss with large numbers.
    pub amount: String,

    /// Token contract address (20 bytes, `None` for native token).
    pub token: Option<[u8; 20]>,

    /// Transaction type identifier.
    pub tx_type: String,

    /// Policy evaluation result.
    pub policy_result: PolicyResultInput,

    /// Cryptographic signature (64 bytes for ECDSA).
    pub signature: Option<[u8; 64]>,
}

/// Policy result for audit logging input.
///
/// Simplified representation of policy evaluation outcomes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyResultInput {
    /// Transaction was allowed by policy.
    Allowed,

    /// Transaction was denied by policy.
    Denied {
        /// The rule that denied the transaction.
        rule: String,
        /// Human-readable reason for denial.
        reason: String,
    },
}

impl PolicyResultInput {
    /// Convert to string representation for audit log.
    fn as_audit_string(&self) -> String {
        match self {
            Self::Allowed => "allowed".to_string(),
            Self::Denied { rule, reason } => format!("denied:{rule}:{reason}"),
        }
    }
}

/// Result of HMAC chain verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyResult {
    /// Whether the entire chain is valid.
    pub valid: bool,

    /// Number of entries successfully verified.
    pub entries_checked: u64,

    /// Sequence number of the first invalid entry (if any).
    pub first_invalid_seq: Option<u64>,

    /// Error message describing the verification failure (if any).
    pub error_message: Option<String>,
}

impl VerifyResult {
    /// Create a successful verification result.
    const fn success(entries_checked: u64) -> Self {
        Self {
            valid: true,
            entries_checked,
            first_invalid_seq: None,
            error_message: None,
        }
    }

    /// Create a failed verification result.
    fn failure(entries_checked: u64, first_invalid_seq: u64, message: impl Into<String>) -> Self {
        Self {
            valid: false,
            entries_checked,
            first_invalid_seq: Some(first_invalid_seq),
            error_message: Some(message.into()),
        }
    }
}

/// Errors that can occur during audit logging operations.
#[derive(Debug)]
pub enum AuditError {
    /// I/O error during file operations.
    Io(std::io::Error),

    /// Failed to serialize or deserialize audit entry.
    Serialization(String),

    /// HMAC key file not found or unreadable.
    KeyNotFound,

    /// Invalid key format or length.
    InvalidKey(String),

    /// HMAC chain verification failed.
    ChainBroken {
        /// Sequence number where verification failed.
        seq: u64,
        /// Description of the verification failure.
        message: String,
    },

    /// Log rotation operation failed.
    RotationFailed(String),

    /// Lock acquisition failed (concurrent access issue).
    LockError(String),
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "IO error: {e}"),
            Self::Serialization(msg) => write!(f, "Failed to serialize entry: {msg}"),
            Self::KeyNotFound => write!(f, "Failed to read audit key"),
            Self::InvalidKey(msg) => write!(f, "Invalid audit key: {msg}"),
            Self::ChainBroken { seq, message } => {
                write!(f, "Chain verification failed at seq {seq}: {message}")
            }
            Self::RotationFailed(msg) => write!(f, "Log rotation failed: {msg}"),
            Self::LockError(msg) => write!(f, "Lock error: {msg}"),
        }
    }
}

impl std::error::Error for AuditError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for AuditError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Thread-safe audit logger with HMAC chain integrity.
///
/// The `AuditLogger` maintains a cryptographic chain of audit entries
/// using HMAC-SHA256. Each entry's HMAC is computed over the entry data
/// concatenated with the previous entry's HMAC.
///
/// ## Thread Safety
///
/// The logger uses atomic operations for sequence numbers and a mutex
/// for the HMAC chain state, making it safe for concurrent use.
///
/// ## File Format
///
/// Entries are stored in JSONL format (one JSON object per line) for
/// easy parsing and streaming access.
pub struct AuditLogger {
    /// Directory containing log files.
    log_dir: PathBuf,

    /// Path to the current audit log file.
    log_path: PathBuf,

    /// HMAC key (32 bytes for HMAC-SHA256).
    hmac_key: [u8; 32],

    /// Current sequence number (atomic for thread-safe increment).
    current_seq: AtomicU64,

    /// HMAC of the last entry (protected by mutex for thread safety).
    last_hmac: Mutex<String>,

    /// Maximum file size before rotation (bytes).
    max_file_size: u64,
}

impl AuditLogger {
    /// Create a new audit logger.
    ///
    /// Initializes the logger with the specified log directory and HMAC key.
    /// If an existing log file is found, it reads the last entry to restore
    /// the chain state.
    ///
    /// # Arguments
    ///
    /// * `log_dir` - Directory where log files will be stored
    /// * `hmac_key` - 32-byte key for HMAC-SHA256 computation
    ///
    /// # Errors
    ///
    /// Returns [`AuditError`] if:
    /// - The log directory cannot be created
    /// - The existing log file cannot be read
    /// - The existing log file is corrupted
    ///
    /// # Example
    ///
    /// ```no_run
    /// use txgate::audit::AuditLogger;
    /// use std::path::Path;
    ///
    /// let key = [0u8; 32]; // Use a secure random key in production
    /// let logger = AuditLogger::new(Path::new("/var/log/txgate"), &key)?;
    /// # Ok::<(), txgate::audit::AuditError>(())
    /// ```
    #[allow(clippy::similar_names)]
    pub fn new(log_dir: &Path, hmac_key: &[u8; 32]) -> Result<Self, AuditError> {
        // Create logs subdirectory
        let logs_subdir = log_dir.join("logs");
        fs::create_dir_all(&logs_subdir)?;

        let log_path = logs_subdir.join(AUDIT_LOG_FILENAME);

        // Restore state from existing log if present
        let (current_seq, last_hmac) = Self::restore_state(&log_path, hmac_key)?;

        Ok(Self {
            log_dir: logs_subdir,
            log_path,
            hmac_key: *hmac_key,
            current_seq: AtomicU64::new(current_seq),
            last_hmac: Mutex::new(last_hmac),
            max_file_size: DEFAULT_MAX_FILE_SIZE,
        })
    }

    /// Create an audit logger from configuration.
    ///
    /// Reads the HMAC key from `~/.txgate/audit.key` (or the specified base directory).
    /// The key file should contain exactly 32 bytes (or 64 hex characters).
    ///
    /// # Arguments
    ///
    /// * `base_dir` - Base directory containing configuration files (typically `~/.txgate`)
    ///
    /// # Errors
    ///
    /// Returns [`AuditError`] if:
    /// - The key file does not exist
    /// - The key file has invalid format
    /// - The logger cannot be initialized
    ///
    /// # Example
    ///
    /// ```no_run
    /// use txgate::audit::AuditLogger;
    /// use std::path::Path;
    ///
    /// let logger = AuditLogger::from_config(Path::new("/home/user/.txgate"))?;
    /// # Ok::<(), txgate::audit::AuditError>(())
    /// ```
    pub fn from_config(base_dir: &Path) -> Result<Self, AuditError> {
        let key_path = base_dir.join(AUDIT_KEY_FILENAME);

        let key_data = fs::read(&key_path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                AuditError::KeyNotFound
            } else {
                AuditError::Io(e)
            }
        })?;

        let hmac_key = Self::parse_key(&key_data)?;

        Self::new(base_dir, &hmac_key)
    }

    /// Log a signing event.
    ///
    /// Creates a new audit entry with the current timestamp and sequence number,
    /// computes the HMAC chain, and appends the entry to the log file.
    ///
    /// # Arguments
    ///
    /// * `event` - The signing event to log
    ///
    /// # Errors
    ///
    /// Returns [`AuditError`] if:
    /// - The entry cannot be serialized
    /// - The log file cannot be written
    /// - Log rotation fails
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    #[allow(clippy::significant_drop_tightening)]
    pub fn log_sign_event(&self, event: SignEvent) -> Result<(), AuditError> {
        // Rotate if needed (before acquiring lock to minimize lock hold time)
        self.rotate_if_needed()?;

        // Acquire lock for HMAC chain
        let mut last_hmac_guard = self
            .last_hmac
            .lock()
            .map_err(|e| AuditError::LockError(e.to_string()))?;

        // Get next sequence number atomically
        let seq = self.current_seq.fetch_add(1, Ordering::SeqCst);

        // Create timestamp
        let timestamp = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

        // Create entry without HMAC first
        let mut entry = AuditEntry {
            seq,
            timestamp,
            correlation_id: event.correlation_id,
            chain: event.chain,
            tx_hash: format!("0x{}", hex::encode(event.tx_hash)),
            recipient: event.recipient.map(|r| format!("0x{}", hex::encode(r))),
            amount: event.amount,
            token: event.token.map(|t| format!("0x{}", hex::encode(t))),
            tx_type: event.tx_type,
            policy_result: event.policy_result.as_audit_string(),
            signature: event.signature.map(|s| format!("0x{}", hex::encode(s))),
            hmac: String::new(), // Will be filled below
        };

        // Compute HMAC
        entry.hmac = self.compute_entry_hmac(&entry, &last_hmac_guard);

        // Serialize to JSON
        let json =
            serde_json::to_string(&entry).map_err(|e| AuditError::Serialization(e.to_string()))?;

        // Append to log file
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)?;

        writeln!(file, "{json}")?;
        file.flush()?;

        // Update last HMAC
        *last_hmac_guard = entry.hmac;

        Ok(())
    }

    /// Verify the HMAC chain integrity.
    ///
    /// Reads all entries from the log file and verifies that each entry's
    /// HMAC is correctly computed based on its data and the previous HMAC.
    ///
    /// # Returns
    ///
    /// A [`VerifyResult`] indicating whether the chain is valid and,
    /// if not, where the first discrepancy was found.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError`] if:
    /// - The log file cannot be read
    /// - An entry cannot be deserialized
    ///
    /// # Example
    ///
    /// ```no_run
    /// use txgate::audit::AuditLogger;
    /// use std::path::Path;
    ///
    /// let key = [0u8; 32];
    /// let logger = AuditLogger::new(Path::new("/var/log/txgate"), &key)?;
    ///
    /// let result = logger.verify_chain()?;
    /// if result.valid {
    ///     println!("Chain verified: {} entries", result.entries_checked);
    /// } else {
    ///     println!("Chain broken at seq {}: {}",
    ///         result.first_invalid_seq.unwrap_or(0),
    ///         result.error_message.unwrap_or_default());
    /// }
    /// # Ok::<(), txgate::audit::AuditError>(())
    /// ```
    pub fn verify_chain(&self) -> Result<VerifyResult, AuditError> {
        // Check if log file exists
        if !self.log_path.exists() {
            return Ok(VerifyResult::success(0));
        }

        let file = File::open(&self.log_path)?;
        let reader = BufReader::new(file);

        let mut prev_hmac = INITIAL_HMAC.to_string();
        let mut entries_checked: u64 = 0;
        let mut expected_seq: u64 = 0;

        for (line_num, line_result) in reader.lines().enumerate() {
            let line = line_result?;

            // Skip empty lines
            if line.trim().is_empty() {
                continue;
            }

            // Parse entry
            let entry: AuditEntry = serde_json::from_str(&line)
                .map_err(|e| AuditError::Serialization(format!("Line {}: {}", line_num + 1, e)))?;

            // Check sequence number
            if entry.seq != expected_seq {
                return Ok(VerifyResult::failure(
                    entries_checked,
                    entry.seq,
                    format!(
                        "Sequence mismatch: expected {}, got {}",
                        expected_seq, entry.seq
                    ),
                ));
            }

            // Verify HMAC
            let expected_hmac = self.compute_entry_hmac(&entry, &prev_hmac);
            if entry.hmac != expected_hmac {
                return Ok(VerifyResult::failure(
                    entries_checked,
                    entry.seq,
                    "HMAC mismatch: entry may have been tampered with",
                ));
            }

            prev_hmac = entry.hmac;
            entries_checked += 1;
            expected_seq += 1;
        }

        Ok(VerifyResult::success(entries_checked))
    }

    /// Set the maximum file size for rotation.
    ///
    /// When the log file exceeds this size, it will be rotated and compressed.
    ///
    /// # Arguments
    ///
    /// * `size` - Maximum file size in bytes
    #[must_use]
    pub const fn with_max_file_size(mut self, size: u64) -> Self {
        self.max_file_size = size;
        self
    }

    /// Compute HMAC for an audit entry.
    ///
    /// The HMAC is computed over a canonical representation of the entry:
    /// `seq || timestamp || correlation_id || chain || tx_hash || ... || prev_hmac`
    fn compute_entry_hmac(&self, entry: &AuditEntry, prev_hmac: &str) -> String {
        // Create canonical data for HMAC computation
        // Using || as separator to ensure unambiguous parsing
        let data = format!(
            "{}||{}||{}||{}||{}||{}||{}||{}||{}||{}||{}||{}",
            entry.seq,
            entry.timestamp,
            entry.correlation_id,
            entry.chain,
            entry.tx_hash,
            entry.recipient.as_deref().unwrap_or(""),
            entry.amount,
            entry.token.as_deref().unwrap_or(""),
            entry.tx_type,
            entry.policy_result,
            entry.signature.as_deref().unwrap_or(""),
            prev_hmac
        );

        // Compute HMAC-SHA256
        // SAFETY: HMAC-SHA256 accepts keys of any length, so new_from_slice never fails
        // for a 32-byte key. Using unwrap_or_else with unreachable for clarity.
        let mut mac = HmacSha256::new_from_slice(&self.hmac_key)
            .unwrap_or_else(|_| unreachable!("HMAC-SHA256 accepts any key length"));
        mac.update(data.as_bytes());
        let result = mac.finalize();

        hex::encode(result.into_bytes())
    }

    /// Restore state from existing log file.
    ///
    /// Reads the last entry to get the current sequence number and HMAC.
    fn restore_state(log_path: &Path, hmac_key: &[u8; 32]) -> Result<(u64, String), AuditError> {
        if !log_path.exists() {
            return Ok((0, INITIAL_HMAC.to_string()));
        }

        let file = File::open(log_path)?;
        let reader = BufReader::new(file);

        let mut last_seq: u64 = 0;
        let mut last_hmac = INITIAL_HMAC.to_string();
        let mut found_entries = false;

        // Create temporary logger for verification
        let temp_key = *hmac_key;
        let mut prev_hmac = INITIAL_HMAC.to_string();

        for line_result in reader.lines() {
            let line = line_result?;

            if line.trim().is_empty() {
                continue;
            }

            let entry: AuditEntry = serde_json::from_str(&line)
                .map_err(|e| AuditError::Serialization(e.to_string()))?;

            // Verify HMAC during restore to detect corruption
            let expected_hmac = compute_hmac(&temp_key, &entry, &prev_hmac);
            if entry.hmac != expected_hmac {
                return Err(AuditError::ChainBroken {
                    seq: entry.seq,
                    message: "HMAC verification failed during state restore".to_string(),
                });
            }

            last_seq = entry.seq;
            last_hmac.clone_from(&entry.hmac);
            prev_hmac = entry.hmac;
            found_entries = true;
        }

        if found_entries {
            // Next sequence number
            Ok((last_seq + 1, last_hmac))
        } else {
            Ok((0, INITIAL_HMAC.to_string()))
        }
    }

    /// Parse HMAC key from raw data.
    ///
    /// Supports both raw 32-byte keys and hex-encoded 64-character keys.
    fn parse_key(data: &[u8]) -> Result<[u8; 32], AuditError> {
        // Try as raw 32 bytes first
        if data.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(data);
            return Ok(key);
        }

        // Try as hex string (with or without newline)
        let hex_str = String::from_utf8_lossy(data);
        let hex_str = hex_str.trim();

        if hex_str.len() == 64 {
            let bytes = hex::decode(hex_str)
                .map_err(|e| AuditError::InvalidKey(format!("Invalid hex: {e}")))?;

            if bytes.len() == 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes);
                return Ok(key);
            }
        }

        Err(AuditError::InvalidKey(format!(
            "Key must be 32 bytes or 64 hex characters, got {} bytes",
            data.len()
        )))
    }

    /// Rotate log file if it exceeds the maximum size.
    fn rotate_if_needed(&self) -> Result<(), AuditError> {
        // Check if rotation is needed
        let metadata = match fs::metadata(&self.log_path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(AuditError::Io(e)),
        };

        if metadata.len() < self.max_file_size {
            return Ok(());
        }

        // Find the next rotation number
        let mut rotation_num = 1;
        loop {
            let rotated_path = self
                .log_dir
                .join(format!("{AUDIT_LOG_FILENAME}.{rotation_num}.gz"));
            if !rotated_path.exists() {
                break;
            }
            rotation_num += 1;
        }

        // Compress and move the current log
        let rotated_path = self
            .log_dir
            .join(format!("{AUDIT_LOG_FILENAME}.{rotation_num}.gz"));

        // Read current log
        let content = fs::read(&self.log_path)
            .map_err(|e| AuditError::RotationFailed(format!("Failed to read log: {e}")))?;

        // Write compressed file
        let gz_file = File::create(&rotated_path)
            .map_err(|e| AuditError::RotationFailed(format!("Failed to create gz file: {e}")))?;
        let mut encoder = GzEncoder::new(BufWriter::new(gz_file), Compression::default());
        encoder
            .write_all(&content)
            .map_err(|e| AuditError::RotationFailed(format!("Failed to write gz: {e}")))?;
        encoder
            .finish()
            .map_err(|e| AuditError::RotationFailed(format!("Failed to finish gz: {e}")))?;

        // Truncate current log file (keep it for new entries)
        // Note: We don't delete because the HMAC chain continues
        File::create(&self.log_path)
            .map_err(|e| AuditError::RotationFailed(format!("Failed to truncate log: {e}")))?;

        tracing::info!(
            rotated_to = %rotated_path.display(),
            "Audit log rotated"
        );

        Ok(())
    }
}

impl std::fmt::Debug for AuditLogger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditLogger")
            .field("log_path", &self.log_path)
            .field("current_seq", &self.current_seq.load(Ordering::Relaxed))
            .field("max_file_size", &self.max_file_size)
            .finish_non_exhaustive()
    }
}

/// Standalone HMAC computation for use in state restoration.
fn compute_hmac(key: &[u8; 32], entry: &AuditEntry, prev_hmac: &str) -> String {
    let data = format!(
        "{}||{}||{}||{}||{}||{}||{}||{}||{}||{}||{}||{}",
        entry.seq,
        entry.timestamp,
        entry.correlation_id,
        entry.chain,
        entry.tx_hash,
        entry.recipient.as_deref().unwrap_or(""),
        entry.amount,
        entry.token.as_deref().unwrap_or(""),
        entry.tx_type,
        entry.policy_result,
        entry.signature.as_deref().unwrap_or(""),
        prev_hmac
    );

    // SAFETY: HMAC-SHA256 accepts keys of any length, so new_from_slice never fails
    // for a 32-byte key. Using unwrap_or_else with unreachable for clarity.
    let mut mac = HmacSha256::new_from_slice(key)
        .unwrap_or_else(|_| unreachable!("HMAC-SHA256 accepts any key length"));
    mac.update(data.as_bytes());
    let result = mac.finalize();

    hex::encode(result.into_bytes())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::map_unwrap_or
    )]

    use super::*;
    use std::thread;
    use tempfile::TempDir;

    /// Helper to create a test logger with a known key.
    fn create_test_logger(dir: &Path) -> AuditLogger {
        let key = [0x42u8; 32];
        AuditLogger::new(dir, &key).expect("Failed to create logger")
    }

    /// Helper to create a sample sign event.
    fn sample_event() -> SignEvent {
        SignEvent {
            correlation_id: "test-correlation-123".to_string(),
            chain: "ethereum".to_string(),
            tx_hash: [0xab; 32],
            recipient: Some([0xcd; 20]),
            amount: "1000000000000000000".to_string(),
            token: None,
            tx_type: "transfer".to_string(),
            policy_result: PolicyResultInput::Allowed,
            signature: Some([0xef; 64]),
        }
    }

    mod entry_creation_tests {
        use super::*;

        #[test]
        fn test_create_audit_entry() {
            let temp_dir = TempDir::new().expect("Failed to create temp dir");
            let logger = create_test_logger(temp_dir.path());

            let event = sample_event();
            logger.log_sign_event(event).expect("Failed to log event");

            // Verify the entry was created
            let result = logger.verify_chain().expect("Verification failed");
            assert!(result.valid);
            assert_eq!(result.entries_checked, 1);
        }

        #[test]
        fn test_entry_fields_populated() {
            let temp_dir = TempDir::new().expect("Failed to create temp dir");
            let logger = create_test_logger(temp_dir.path());

            let event = sample_event();
            logger.log_sign_event(event).expect("Failed to log event");

            // Read the entry back
            let log_path = temp_dir.path().join("logs").join(AUDIT_LOG_FILENAME);
            let content = fs::read_to_string(&log_path).expect("Failed to read log");
            let entry: AuditEntry =
                serde_json::from_str(content.trim()).expect("Failed to parse entry");

            assert_eq!(entry.seq, 0);
            assert_eq!(entry.correlation_id, "test-correlation-123");
            assert_eq!(entry.chain, "ethereum");
            assert_eq!(entry.tx_hash, format!("0x{}", hex::encode([0xab; 32])));
            assert_eq!(
                entry.recipient,
                Some(format!("0x{}", hex::encode([0xcd; 20])))
            );
            assert_eq!(entry.amount, "1000000000000000000");
            assert!(entry.token.is_none());
            assert_eq!(entry.tx_type, "transfer");
            assert_eq!(entry.policy_result, "allowed");
            assert_eq!(
                entry.signature,
                Some(format!("0x{}", hex::encode([0xef; 64])))
            );
            assert!(!entry.hmac.is_empty());
        }

        #[test]
        fn test_denied_policy_result() {
            let temp_dir = TempDir::new().expect("Failed to create temp dir");
            let logger = create_test_logger(temp_dir.path());

            let mut event = sample_event();
            event.policy_result = PolicyResultInput::Denied {
                rule: "whitelist".to_string(),
                reason: "recipient not in whitelist".to_string(),
            };
            logger.log_sign_event(event).expect("Failed to log event");

            // Read the entry back
            let log_path = temp_dir.path().join("logs").join(AUDIT_LOG_FILENAME);
            let content = fs::read_to_string(&log_path).expect("Failed to read log");
            let entry: AuditEntry =
                serde_json::from_str(content.trim()).expect("Failed to parse entry");

            assert_eq!(
                entry.policy_result,
                "denied:whitelist:recipient not in whitelist"
            );
        }
    }

    mod hmac_tests {
        use super::*;

        #[test]
        fn test_hmac_computation_deterministic() {
            let key = [0x42u8; 32];
            let entry = AuditEntry {
                seq: 0,
                timestamp: "2025-01-15T10:30:00.000Z".to_string(),
                correlation_id: "test-123".to_string(),
                chain: "ethereum".to_string(),
                tx_hash: "0xabcd".to_string(),
                recipient: Some("0x1234".to_string()),
                amount: "1000".to_string(),
                token: None,
                tx_type: "transfer".to_string(),
                policy_result: "allowed".to_string(),
                signature: None,
                hmac: String::new(),
            };

            let hmac1 = compute_hmac(&key, &entry, INITIAL_HMAC);
            let hmac2 = compute_hmac(&key, &entry, INITIAL_HMAC);

            assert_eq!(hmac1, hmac2);
            assert_eq!(hmac1.len(), 64); // 32 bytes = 64 hex chars
        }

        #[test]
        fn test_hmac_changes_with_data() {
            let key = [0x42u8; 32];
            let entry1 = AuditEntry {
                seq: 0,
                timestamp: "2025-01-15T10:30:00.000Z".to_string(),
                correlation_id: "test-123".to_string(),
                chain: "ethereum".to_string(),
                tx_hash: "0xabcd".to_string(),
                recipient: Some("0x1234".to_string()),
                amount: "1000".to_string(),
                token: None,
                tx_type: "transfer".to_string(),
                policy_result: "allowed".to_string(),
                signature: None,
                hmac: String::new(),
            };

            let mut entry2 = entry1.clone();
            entry2.amount = "2000".to_string();

            let hmac1 = compute_hmac(&key, &entry1, INITIAL_HMAC);
            let hmac2 = compute_hmac(&key, &entry2, INITIAL_HMAC);

            assert_ne!(hmac1, hmac2);
        }

        #[test]
        fn test_hmac_chain_dependency() {
            let key = [0x42u8; 32];
            let entry = AuditEntry {
                seq: 0,
                timestamp: "2025-01-15T10:30:00.000Z".to_string(),
                correlation_id: "test-123".to_string(),
                chain: "ethereum".to_string(),
                tx_hash: "0xabcd".to_string(),
                recipient: None,
                amount: "1000".to_string(),
                token: None,
                tx_type: "transfer".to_string(),
                policy_result: "allowed".to_string(),
                signature: None,
                hmac: String::new(),
            };

            let hmac1 = compute_hmac(&key, &entry, INITIAL_HMAC);
            let hmac2 = compute_hmac(&key, &entry, "different_prev_hmac");

            assert_ne!(hmac1, hmac2);
        }
    }

    mod chain_verification_tests {
        use super::*;

        #[test]
        fn test_verify_valid_chain() {
            let temp_dir = TempDir::new().expect("Failed to create temp dir");
            let logger = create_test_logger(temp_dir.path());

            // Log multiple events
            for i in 0..5 {
                let mut event = sample_event();
                event.correlation_id = format!("test-{i}");
                logger.log_sign_event(event).expect("Failed to log event");
            }

            let result = logger.verify_chain().expect("Verification failed");
            assert!(result.valid);
            assert_eq!(result.entries_checked, 5);
            assert!(result.first_invalid_seq.is_none());
            assert!(result.error_message.is_none());
        }

        #[test]
        fn test_detect_tampered_entry() {
            let temp_dir = TempDir::new().expect("Failed to create temp dir");
            let logger = create_test_logger(temp_dir.path());

            // Log some events
            for i in 0..3 {
                let mut event = sample_event();
                event.correlation_id = format!("test-{i}");
                logger.log_sign_event(event).expect("Failed to log event");
            }

            // Tamper with the log file
            let log_path = temp_dir.path().join("logs").join(AUDIT_LOG_FILENAME);
            let content = fs::read_to_string(&log_path).expect("Failed to read log");
            let lines: Vec<&str> = content.lines().collect();

            // Modify the second entry
            let mut entries: Vec<AuditEntry> = lines
                .iter()
                .map(|line| serde_json::from_str(line).expect("Failed to parse"))
                .collect();
            entries[1].amount = "999999".to_string(); // Tamper!

            // Write back
            let tampered_content: String = entries
                .iter()
                .map(|e| serde_json::to_string(e).expect("Failed to serialize"))
                .collect::<Vec<_>>()
                .join("\n");
            fs::write(&log_path, tampered_content + "\n").expect("Failed to write");

            // Verify should detect tampering
            let result = logger.verify_chain().expect("Verification failed");
            assert!(!result.valid);
            assert_eq!(result.first_invalid_seq, Some(1));
            assert!(result
                .error_message
                .as_ref()
                .map(|m| m.contains("HMAC mismatch"))
                .unwrap_or(false));
        }

        #[test]
        fn test_detect_missing_entry() {
            let temp_dir = TempDir::new().expect("Failed to create temp dir");
            let logger = create_test_logger(temp_dir.path());

            // Log some events
            for i in 0..3 {
                let mut event = sample_event();
                event.correlation_id = format!("test-{i}");
                logger.log_sign_event(event).expect("Failed to log event");
            }

            // Remove the middle entry
            let log_path = temp_dir.path().join("logs").join(AUDIT_LOG_FILENAME);
            let content = fs::read_to_string(&log_path).expect("Failed to read log");
            let lines: Vec<&str> = content.lines().collect();

            // Keep only first and last
            let modified_content = format!("{}\n{}\n", lines[0], lines[2]);
            fs::write(&log_path, modified_content).expect("Failed to write");

            // Verify should detect sequence gap
            let result = logger.verify_chain().expect("Verification failed");
            assert!(!result.valid);
            assert!(result
                .error_message
                .as_ref()
                .map(|m| m.contains("Sequence mismatch"))
                .unwrap_or(false));
        }

        #[test]
        fn test_verify_empty_log() {
            let temp_dir = TempDir::new().expect("Failed to create temp dir");
            let logger = create_test_logger(temp_dir.path());

            let result = logger.verify_chain().expect("Verification failed");
            assert!(result.valid);
            assert_eq!(result.entries_checked, 0);
        }
    }

    mod log_rotation_tests {
        use super::*;

        #[test]
        fn test_log_rotation() {
            let temp_dir = TempDir::new().expect("Failed to create temp dir");
            let key = [0x42u8; 32];

            // Create logger with small max file size for testing
            let logger = AuditLogger::new(temp_dir.path(), &key)
                .expect("Failed to create logger")
                .with_max_file_size(500); // 500 bytes

            // Log enough events to trigger rotation
            for i in 0..20 {
                let mut event = sample_event();
                event.correlation_id = format!("test-correlation-{i:03}");
                logger.log_sign_event(event).expect("Failed to log event");
            }

            // Check that rotation occurred
            let rotated_path = temp_dir
                .path()
                .join("logs")
                .join(format!("{AUDIT_LOG_FILENAME}.1.gz"));
            assert!(rotated_path.exists(), "Rotated file should exist");

            // Verify the rotated file is gzip compressed
            let gz_content = fs::read(&rotated_path).expect("Failed to read gz file");
            // Check gzip magic number
            assert!(
                gz_content.len() >= 2 && gz_content[0] == 0x1f && gz_content[1] == 0x8b,
                "File should be gzip compressed"
            );
        }
    }

    mod concurrent_logging_tests {
        use super::*;

        #[test]
        fn test_concurrent_logging() {
            let temp_dir = TempDir::new().expect("Failed to create temp dir");
            let key = [0x42u8; 32];
            let logger =
                std::sync::Arc::new(AuditLogger::new(temp_dir.path(), &key).expect("Failed"));

            let mut handles = vec![];

            // Spawn multiple threads logging concurrently
            for thread_id in 0..4 {
                let logger_clone = std::sync::Arc::clone(&logger);
                let handle = thread::spawn(move || {
                    for i in 0..10 {
                        let mut event = sample_event();
                        event.correlation_id = format!("thread-{thread_id}-event-{i}");
                        logger_clone
                            .log_sign_event(event)
                            .expect("Failed to log event");
                    }
                });
                handles.push(handle);
            }

            // Wait for all threads
            for handle in handles {
                handle.join().expect("Thread panicked");
            }

            // Verify chain integrity
            let result = logger.verify_chain().expect("Verification failed");
            assert!(result.valid);
            assert_eq!(result.entries_checked, 40); // 4 threads x 10 events
        }
    }

    mod key_parsing_tests {
        use super::*;

        #[test]
        fn test_parse_raw_key() {
            let raw_key = [0x42u8; 32];
            let parsed = AuditLogger::parse_key(&raw_key).expect("Failed to parse");
            assert_eq!(parsed, raw_key);
        }

        #[test]
        fn test_parse_hex_key() {
            let hex_key = "4242424242424242424242424242424242424242424242424242424242424242";
            let parsed = AuditLogger::parse_key(hex_key.as_bytes()).expect("Failed to parse");
            assert_eq!(parsed, [0x42u8; 32]);
        }

        #[test]
        fn test_parse_hex_key_with_newline() {
            let hex_key = "4242424242424242424242424242424242424242424242424242424242424242\n";
            let parsed = AuditLogger::parse_key(hex_key.as_bytes()).expect("Failed to parse");
            assert_eq!(parsed, [0x42u8; 32]);
        }

        #[test]
        fn test_parse_invalid_key_length() {
            let short_key = [0x42u8; 16];
            let result = AuditLogger::parse_key(&short_key);
            assert!(result.is_err());
        }
    }

    mod state_restoration_tests {
        use super::*;

        #[test]
        fn test_restore_state_from_existing_log() {
            let temp_dir = TempDir::new().expect("Failed to create temp dir");
            let key = [0x42u8; 32];

            // Create logger and log some events
            {
                let logger = AuditLogger::new(temp_dir.path(), &key).expect("Failed");
                for i in 0..5 {
                    let mut event = sample_event();
                    event.correlation_id = format!("test-{i}");
                    logger.log_sign_event(event).expect("Failed to log event");
                }
            }

            // Create new logger (should restore state)
            let logger = AuditLogger::new(temp_dir.path(), &key).expect("Failed");

            // Log another event
            let mut event = sample_event();
            event.correlation_id = "test-5".to_string();
            logger.log_sign_event(event).expect("Failed to log event");

            // Verify chain still valid
            let result = logger.verify_chain().expect("Verification failed");
            assert!(result.valid);
            assert_eq!(result.entries_checked, 6);

            // Verify sequence numbers are correct
            let log_path = temp_dir.path().join("logs").join(AUDIT_LOG_FILENAME);
            let content = fs::read_to_string(&log_path).expect("Failed to read");
            let entries: Vec<AuditEntry> = content
                .lines()
                .map(|line| serde_json::from_str(line).expect("Failed to parse"))
                .collect();

            for (i, entry) in entries.iter().enumerate() {
                assert_eq!(entry.seq, i as u64);
            }
        }
    }

    mod audit_error_tests {
        use super::*;

        #[test]
        fn test_error_display() {
            let io_err = AuditError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "file not found",
            ));
            assert!(io_err.to_string().contains("IO error"));

            let ser_err = AuditError::Serialization("invalid json".to_string());
            assert!(ser_err.to_string().contains("serialize"));

            let key_err = AuditError::KeyNotFound;
            assert!(key_err.to_string().contains("audit key"));

            let chain_err = AuditError::ChainBroken {
                seq: 42,
                message: "tampered".to_string(),
            };
            assert!(chain_err.to_string().contains("seq 42"));

            let rot_err = AuditError::RotationFailed("disk full".to_string());
            assert!(rot_err.to_string().contains("rotation"));
        }
    }

    mod verify_result_tests {
        use super::*;

        #[test]
        fn test_verify_result_success() {
            let result = VerifyResult::success(100);
            assert!(result.valid);
            assert_eq!(result.entries_checked, 100);
            assert!(result.first_invalid_seq.is_none());
            assert!(result.error_message.is_none());
        }

        #[test]
        fn test_verify_result_failure() {
            let result = VerifyResult::failure(50, 50, "test error");
            assert!(!result.valid);
            assert_eq!(result.entries_checked, 50);
            assert_eq!(result.first_invalid_seq, Some(50));
            assert_eq!(result.error_message, Some("test error".to_string()));
        }
    }
}
