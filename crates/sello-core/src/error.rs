//! Error types for the Sello signing service.
//!
//! This module provides comprehensive error types for all failure modes
//! in the Sello system, organized by domain:
//!
//! - [`ParseError`] - Transaction parsing failures
//! - [`SignError`] - Signing operation failures
//! - [`StoreError`] - Key storage failures
//! - [`PolicyError`] - Policy evaluation failures
//! - [`ConfigError`] - Configuration failures
//! - [`SelloError`] - Top-level error that wraps all error types
//!
//! # Example
//!
//! ```rust
//! use sello_core::error::{ParseError, SelloError};
//!
//! fn parse_transaction(data: &[u8]) -> Result<(), SelloError> {
//!     if data.is_empty() {
//!         return Err(ParseError::MalformedTransaction {
//!             context: "empty transaction data".to_string(),
//!         }.into());
//!     }
//!     Ok(())
//! }
//! ```

use std::fmt;

/// Top-level error type for the Sello signing service.
///
/// This enum wraps all domain-specific error types and provides
/// automatic conversion via the `#[from]` attribute.
#[derive(Debug, thiserror::Error)]
pub enum SelloError {
    /// Transaction parsing failed.
    #[error("Parse error: {0}")]
    Parse(#[from] ParseError),

    /// Policy denied the transaction.
    #[error("Policy denied: {rule} - {reason}")]
    PolicyDenied {
        /// The policy rule that denied the request.
        rule: String,
        /// Human-readable reason for denial.
        reason: String,
    },

    /// Signing operation failed.
    #[error("Signing error: {0}")]
    Sign(#[from] SignError),

    /// Key storage operation failed.
    #[error("Storage error: {0}")]
    Store(#[from] StoreError),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),

    /// Policy evaluation error (not denial, but evaluation failure).
    #[error("Policy error: {0}")]
    Policy(#[from] PolicyError),
}

impl SelloError {
    /// Create a policy denied error.
    #[must_use]
    pub fn policy_denied(rule: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::PolicyDenied {
            rule: rule.into(),
            reason: reason.into(),
        }
    }
}

/// JSON-RPC 2.0 error codes.
///
/// Standard codes from -32700 to -32600 are defined by the JSON-RPC spec.
/// Application-specific codes use the -32000 to -32099 range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum RpcErrorCode {
    /// Invalid JSON was received by the server.
    ParseFailed = -32700,
    /// The JSON sent is not a valid Request object.
    InvalidRequest = -32600,
    /// The method does not exist or is not available.
    MethodNotFound = -32601,
    /// Invalid method parameter(s).
    InvalidParams = -32602,
    /// Internal JSON-RPC error.
    InternalError = -32603,

    // Application-specific codes (-32000 to -32099)
    /// Policy denied the transaction.
    PolicyDenied = -32001,
    /// The requested chain is not supported.
    ChainNotSupported = -32002,
    /// The requested key was not found.
    KeyNotFound = -32003,
    /// The signing operation failed.
    SignatureFailed = -32004,
}

impl RpcErrorCode {
    /// Get the numeric error code value.
    #[must_use]
    pub const fn code(self) -> i32 {
        self as i32
    }

    /// Get a human-readable message for this error code.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::ParseFailed => "Parse error",
            Self::InvalidRequest => "Invalid Request",
            Self::MethodNotFound => "Method not found",
            Self::InvalidParams => "Invalid params",
            Self::InternalError => "Internal error",
            Self::PolicyDenied => "Policy denied",
            Self::ChainNotSupported => "Chain not supported",
            Self::KeyNotFound => "Key not found",
            Self::SignatureFailed => "Signature failed",
        }
    }
}

impl fmt::Display for RpcErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.message(), self.code())
    }
}

impl From<&SelloError> for RpcErrorCode {
    fn from(error: &SelloError) -> Self {
        match error {
            SelloError::Parse(ParseError::UnsupportedChain { .. }) => Self::ChainNotSupported,
            SelloError::Parse(_) => Self::ParseFailed,
            SelloError::PolicyDenied { .. } | SelloError::Policy(_) => Self::PolicyDenied,
            SelloError::Sign(SignError::KeyNotFound { .. })
            | SelloError::Store(StoreError::KeyNotFound { .. }) => Self::KeyNotFound,
            SelloError::Sign(_) => Self::SignatureFailed,
            SelloError::Store(_) | SelloError::Config(_) => Self::InternalError,
        }
    }
}

impl From<SelloError> for RpcErrorCode {
    fn from(error: SelloError) -> Self {
        Self::from(&error)
    }
}

// ============================================================================
// ParseError
// ============================================================================

/// Errors that can occur during transaction parsing.
///
/// These errors indicate that the input transaction data could not be
/// parsed into a structured format for policy evaluation.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    /// The transaction type byte is not recognized.
    #[error("unknown transaction type")]
    UnknownTxType,

    /// RLP decoding failed.
    #[error("RLP decoding failed: {context}")]
    InvalidRlp {
        /// Context about what was being decoded.
        context: String,
    },

    /// The transaction structure is malformed.
    #[error("malformed transaction: {context}")]
    MalformedTransaction {
        /// Context about what was malformed.
        context: String,
    },

    /// The calldata structure is invalid (e.g., wrong length for ERC-20).
    #[error("malformed calldata")]
    MalformedCalldata,

    /// The chain is not supported by this signer.
    #[error("unsupported chain: {chain}")]
    UnsupportedChain {
        /// The chain identifier that was requested.
        chain: String,
    },

    /// The address format is invalid for the chain.
    #[error("invalid address: {address}")]
    InvalidAddress {
        /// The malformed address string.
        address: String,
    },
}

impl ParseError {
    /// Create an `InvalidRlp` error with context.
    #[must_use]
    pub fn invalid_rlp(context: impl Into<String>) -> Self {
        Self::InvalidRlp {
            context: context.into(),
        }
    }

    /// Create a `MalformedTransaction` error with context.
    #[must_use]
    pub fn malformed_transaction(context: impl Into<String>) -> Self {
        Self::MalformedTransaction {
            context: context.into(),
        }
    }

    /// Create an `UnsupportedChain` error.
    #[must_use]
    pub fn unsupported_chain(chain: impl Into<String>) -> Self {
        Self::UnsupportedChain {
            chain: chain.into(),
        }
    }

    /// Create an `InvalidAddress` error.
    #[must_use]
    pub fn invalid_address(address: impl Into<String>) -> Self {
        Self::InvalidAddress {
            address: address.into(),
        }
    }
}

// ============================================================================
// SignError
// ============================================================================

/// Errors that can occur during signing operations.
///
/// These errors indicate failures in the cryptographic signing process,
/// including key access and algorithm mismatches.
#[derive(Debug, thiserror::Error)]
pub enum SignError {
    /// The requested key does not exist in the key store.
    #[error("key not found: {name}")]
    KeyNotFound {
        /// The name of the key that was not found.
        name: String,
    },

    /// The key material is invalid or corrupted.
    #[error("invalid key material")]
    InvalidKey,

    /// The signing operation failed.
    #[error("signature failed: {context}")]
    SignatureFailed {
        /// Context about why signing failed.
        context: String,
    },

    /// The key uses a different curve than expected.
    #[error("wrong curve: expected {expected}, got {actual}")]
    WrongCurve {
        /// The expected curve name (e.g., "secp256k1").
        expected: String,
        /// The actual curve name of the key.
        actual: String,
    },
}

impl SignError {
    /// Create a `KeyNotFound` error.
    #[must_use]
    pub fn key_not_found(name: impl Into<String>) -> Self {
        Self::KeyNotFound { name: name.into() }
    }

    /// Create a `SignatureFailed` error with context.
    #[must_use]
    pub fn signature_failed(context: impl Into<String>) -> Self {
        Self::SignatureFailed {
            context: context.into(),
        }
    }

    /// Create a `WrongCurve` error.
    #[must_use]
    pub fn wrong_curve(expected: impl Into<String>, actual: impl Into<String>) -> Self {
        Self::WrongCurve {
            expected: expected.into(),
            actual: actual.into(),
        }
    }
}

// ============================================================================
// StoreError
// ============================================================================

/// Errors that can occur during key storage operations.
///
/// These errors indicate failures in reading, writing, or managing
/// encrypted key files.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// File system I/O error.
    #[error("I/O error: {0}")]
    IoError(#[source] std::io::Error),

    /// Key encryption failed.
    #[error("encryption failed")]
    EncryptionFailed,

    /// Key decryption failed (likely wrong password).
    #[error("decryption failed (wrong password?)")]
    DecryptionFailed,

    /// A key with this name already exists.
    #[error("key already exists: {name}")]
    KeyExists {
        /// The name of the existing key.
        name: String,
    },

    /// The requested key does not exist.
    #[error("key not found: {name}")]
    KeyNotFound {
        /// The name of the key that was not found.
        name: String,
    },

    /// The key file format is invalid.
    #[error("invalid key file format")]
    InvalidFormat,

    /// Insufficient file system permissions.
    #[error("permission denied")]
    PermissionDenied,
}

impl StoreError {
    /// Create an `IoError` from a `std::io::Error`.
    #[must_use]
    pub const fn io_error(error: std::io::Error) -> Self {
        Self::IoError(error)
    }

    /// Create a `KeyExists` error.
    #[must_use]
    pub fn key_exists(name: impl Into<String>) -> Self {
        Self::KeyExists { name: name.into() }
    }

    /// Create a `KeyNotFound` error.
    #[must_use]
    pub fn key_not_found(name: impl Into<String>) -> Self {
        Self::KeyNotFound { name: name.into() }
    }
}

impl From<std::io::Error> for StoreError {
    fn from(error: std::io::Error) -> Self {
        // Map specific I/O errors to more specific store errors
        match error.kind() {
            std::io::ErrorKind::PermissionDenied => Self::PermissionDenied,
            std::io::ErrorKind::NotFound => Self::InvalidFormat,
            _ => Self::IoError(error),
        }
    }
}

// ============================================================================
// PolicyError
// ============================================================================

/// Errors that can occur during policy evaluation.
///
/// Note: These are evaluation errors, not policy denials. For denials,
/// see [`SelloError::PolicyDenied`].
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// The address is on the blacklist.
    #[error("address is blacklisted: {address}")]
    Blacklisted {
        /// The blacklisted address.
        address: String,
    },

    /// The address is not on the whitelist (when whitelist is enabled).
    #[error("address not in whitelist: {address}")]
    NotWhitelisted {
        /// The address that is not whitelisted.
        address: String,
    },

    /// The transaction amount exceeds the per-transaction limit.
    #[error("exceeds transaction limit: limit={limit}, amount={amount}")]
    ExceedsTransactionLimit {
        /// The configured limit.
        limit: String,
        /// The requested amount.
        amount: String,
    },

    /// The transaction would exceed the daily limit.
    #[error("exceeds daily limit: limit={limit}, current={current}, amount={amount}")]
    ExceedsDailyLimit {
        /// The configured daily limit.
        limit: String,
        /// The current daily total.
        current: String,
        /// The requested amount.
        amount: String,
    },

    /// The policy configuration is invalid.
    #[error("invalid configuration: {context}")]
    InvalidConfiguration {
        /// Context about what is invalid.
        context: String,
    },
}

impl PolicyError {
    /// Create a `Blacklisted` error.
    #[must_use]
    pub fn blacklisted(address: impl Into<String>) -> Self {
        Self::Blacklisted {
            address: address.into(),
        }
    }

    /// Create a `NotWhitelisted` error.
    #[must_use]
    pub fn not_whitelisted(address: impl Into<String>) -> Self {
        Self::NotWhitelisted {
            address: address.into(),
        }
    }

    /// Create an `ExceedsTransactionLimit` error.
    #[must_use]
    pub fn exceeds_transaction_limit(limit: impl Into<String>, amount: impl Into<String>) -> Self {
        Self::ExceedsTransactionLimit {
            limit: limit.into(),
            amount: amount.into(),
        }
    }

    /// Create an `ExceedsDailyLimit` error.
    #[must_use]
    pub fn exceeds_daily_limit(
        limit: impl Into<String>,
        current: impl Into<String>,
        amount: impl Into<String>,
    ) -> Self {
        Self::ExceedsDailyLimit {
            limit: limit.into(),
            current: current.into(),
            amount: amount.into(),
        }
    }

    /// Create an `InvalidConfiguration` error.
    #[must_use]
    pub fn invalid_configuration(context: impl Into<String>) -> Self {
        Self::InvalidConfiguration {
            context: context.into(),
        }
    }

    /// Convert this policy error into a denial reason string.
    #[must_use]
    pub fn denial_reason(&self) -> String {
        self.to_string()
    }

    /// Get the rule name that triggered this error.
    #[must_use]
    pub const fn rule_name(&self) -> &'static str {
        match self {
            Self::Blacklisted { .. } => "blacklist",
            Self::NotWhitelisted { .. } => "whitelist",
            Self::ExceedsTransactionLimit { .. } => "tx_limit",
            Self::ExceedsDailyLimit { .. } => "daily_limit",
            Self::InvalidConfiguration { .. } => "configuration",
        }
    }
}

// ============================================================================
// ConfigError
// ============================================================================

/// Errors that can occur during configuration loading.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The configuration file was not found.
    #[error("configuration file not found: {path}")]
    FileNotFound {
        /// The path that was not found.
        path: String,
    },

    /// Failed to parse the configuration file.
    #[error("failed to parse configuration: {context}")]
    ParseFailed {
        /// Context about the parsing failure.
        context: String,
    },

    /// A configuration value is invalid.
    #[error("invalid value for {field}: {value}")]
    InvalidValue {
        /// The field name with the invalid value.
        field: String,
        /// The invalid value.
        value: String,
    },

    /// A required configuration field is missing.
    #[error("missing required field: {field}")]
    MissingField {
        /// The name of the missing field.
        field: String,
    },
}

impl ConfigError {
    /// Create a `FileNotFound` error.
    #[must_use]
    pub fn file_not_found(path: impl Into<String>) -> Self {
        Self::FileNotFound { path: path.into() }
    }

    /// Create a `ParseFailed` error.
    #[must_use]
    pub fn parse_failed(context: impl Into<String>) -> Self {
        Self::ParseFailed {
            context: context.into(),
        }
    }

    /// Create an `InvalidValue` error.
    #[must_use]
    pub fn invalid_value(field: impl Into<String>, value: impl Into<String>) -> Self {
        Self::InvalidValue {
            field: field.into(),
            value: value.into(),
        }
    }

    /// Create a `MissingField` error.
    #[must_use]
    pub fn missing_field(field: impl Into<String>) -> Self {
        Self::MissingField {
            field: field.into(),
        }
    }
}

// ============================================================================
// Result type aliases
// ============================================================================

/// A `Result` type alias using [`SelloError`] as the error type.
pub type Result<T> = std::result::Result<T, SelloError>;

/// A `Result` type alias for parsing operations.
pub type ParseResult<T> = std::result::Result<T, ParseError>;

/// A `Result` type alias for signing operations.
pub type SignResult<T> = std::result::Result<T, SignError>;

/// A `Result` type alias for storage operations.
pub type StoreResult<T> = std::result::Result<T, StoreError>;

/// A `Result` type alias for policy operations.
pub type PolicyResult<T> = std::result::Result<T, PolicyError>;

/// A `Result` type alias for configuration operations.
pub type ConfigResult<T> = std::result::Result<T, ConfigError>;

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::items_after_statements)]

    use super::*;

    // ------------------------------------------------------------------------
    // SelloError tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_sello_error_from_parse_error() {
        let parse_err = ParseError::UnknownTxType;
        let sello_err: SelloError = parse_err.into();

        assert!(matches!(
            sello_err,
            SelloError::Parse(ParseError::UnknownTxType)
        ));
        assert_eq!(
            sello_err.to_string(),
            "Parse error: unknown transaction type"
        );
    }

    #[test]
    fn test_sello_error_from_sign_error() {
        let sign_err = SignError::key_not_found("test-key");
        let sello_err: SelloError = sign_err.into();

        assert!(matches!(
            sello_err,
            SelloError::Sign(SignError::KeyNotFound { .. })
        ));
        assert_eq!(
            sello_err.to_string(),
            "Signing error: key not found: test-key"
        );
    }

    #[test]
    fn test_sello_error_from_store_error() {
        let store_err = StoreError::DecryptionFailed;
        let sello_err: SelloError = store_err.into();

        assert!(matches!(
            sello_err,
            SelloError::Store(StoreError::DecryptionFailed)
        ));
        assert_eq!(
            sello_err.to_string(),
            "Storage error: decryption failed (wrong password?)"
        );
    }

    #[test]
    fn test_sello_error_from_policy_error() {
        let policy_err = PolicyError::blacklisted("0x1234");
        let sello_err: SelloError = policy_err.into();

        assert!(matches!(
            sello_err,
            SelloError::Policy(PolicyError::Blacklisted { .. })
        ));
        assert_eq!(
            sello_err.to_string(),
            "Policy error: address is blacklisted: 0x1234"
        );
    }

    #[test]
    fn test_sello_error_from_config_error() {
        let config_err = ConfigError::missing_field("api_key");
        let sello_err: SelloError = config_err.into();

        assert!(matches!(
            sello_err,
            SelloError::Config(ConfigError::MissingField { .. })
        ));
        assert_eq!(
            sello_err.to_string(),
            "Configuration error: missing required field: api_key"
        );
    }

    #[test]
    fn test_sello_error_policy_denied() {
        let err = SelloError::policy_denied("whitelist", "address not in whitelist");

        assert!(matches!(err, SelloError::PolicyDenied { .. }));
        assert_eq!(
            err.to_string(),
            "Policy denied: whitelist - address not in whitelist"
        );
    }

    // ------------------------------------------------------------------------
    // RpcErrorCode tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_rpc_error_code_values() {
        assert_eq!(RpcErrorCode::ParseFailed.code(), -32700);
        assert_eq!(RpcErrorCode::InvalidRequest.code(), -32600);
        assert_eq!(RpcErrorCode::MethodNotFound.code(), -32601);
        assert_eq!(RpcErrorCode::InvalidParams.code(), -32602);
        assert_eq!(RpcErrorCode::InternalError.code(), -32603);
        assert_eq!(RpcErrorCode::PolicyDenied.code(), -32001);
        assert_eq!(RpcErrorCode::ChainNotSupported.code(), -32002);
        assert_eq!(RpcErrorCode::KeyNotFound.code(), -32003);
        assert_eq!(RpcErrorCode::SignatureFailed.code(), -32004);
    }

    #[test]
    fn test_rpc_error_code_messages() {
        assert_eq!(RpcErrorCode::ParseFailed.message(), "Parse error");
        assert_eq!(RpcErrorCode::InvalidRequest.message(), "Invalid Request");
        assert_eq!(RpcErrorCode::MethodNotFound.message(), "Method not found");
        assert_eq!(RpcErrorCode::InvalidParams.message(), "Invalid params");
        assert_eq!(RpcErrorCode::InternalError.message(), "Internal error");
        assert_eq!(RpcErrorCode::PolicyDenied.message(), "Policy denied");
        assert_eq!(
            RpcErrorCode::ChainNotSupported.message(),
            "Chain not supported"
        );
        assert_eq!(RpcErrorCode::KeyNotFound.message(), "Key not found");
        assert_eq!(RpcErrorCode::SignatureFailed.message(), "Signature failed");
    }

    #[test]
    fn test_rpc_error_code_display() {
        assert_eq!(
            RpcErrorCode::ParseFailed.to_string(),
            "Parse error (-32700)"
        );
        assert_eq!(
            RpcErrorCode::KeyNotFound.to_string(),
            "Key not found (-32003)"
        );
    }

    #[test]
    fn test_rpc_error_code_from_sello_error() {
        // Parse errors
        let err = SelloError::Parse(ParseError::UnknownTxType);
        assert_eq!(RpcErrorCode::from(&err), RpcErrorCode::ParseFailed);

        let err = SelloError::Parse(ParseError::unsupported_chain("unknown"));
        assert_eq!(RpcErrorCode::from(&err), RpcErrorCode::ChainNotSupported);

        // Sign errors
        let err = SelloError::Sign(SignError::key_not_found("test"));
        assert_eq!(RpcErrorCode::from(&err), RpcErrorCode::KeyNotFound);

        let err = SelloError::Sign(SignError::InvalidKey);
        assert_eq!(RpcErrorCode::from(&err), RpcErrorCode::SignatureFailed);

        // Policy errors
        let err = SelloError::policy_denied("whitelist", "not allowed");
        assert_eq!(RpcErrorCode::from(&err), RpcErrorCode::PolicyDenied);

        let err = SelloError::Policy(PolicyError::blacklisted("0x1234"));
        assert_eq!(RpcErrorCode::from(&err), RpcErrorCode::PolicyDenied);

        // Store errors
        let err = SelloError::Store(StoreError::key_not_found("test"));
        assert_eq!(RpcErrorCode::from(&err), RpcErrorCode::KeyNotFound);

        let err = SelloError::Store(StoreError::DecryptionFailed);
        assert_eq!(RpcErrorCode::from(&err), RpcErrorCode::InternalError);

        // Config errors
        let err = SelloError::Config(ConfigError::missing_field("test"));
        assert_eq!(RpcErrorCode::from(&err), RpcErrorCode::InternalError);
    }

    // ------------------------------------------------------------------------
    // ParseError tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_parse_error_display() {
        assert_eq!(
            ParseError::UnknownTxType.to_string(),
            "unknown transaction type"
        );

        assert_eq!(
            ParseError::invalid_rlp("failed to decode nonce").to_string(),
            "RLP decoding failed: failed to decode nonce"
        );

        assert_eq!(
            ParseError::malformed_transaction("missing to field").to_string(),
            "malformed transaction: missing to field"
        );

        assert_eq!(
            ParseError::MalformedCalldata.to_string(),
            "malformed calldata"
        );

        assert_eq!(
            ParseError::unsupported_chain("cosmos").to_string(),
            "unsupported chain: cosmos"
        );

        assert_eq!(
            ParseError::invalid_address("0xinvalid").to_string(),
            "invalid address: 0xinvalid"
        );
    }

    #[test]
    fn test_parse_error_constructors() {
        let err = ParseError::invalid_rlp("test context");
        assert!(matches!(err, ParseError::InvalidRlp { context } if context == "test context"));

        let err = ParseError::malformed_transaction("test context");
        assert!(
            matches!(err, ParseError::MalformedTransaction { context } if context == "test context")
        );

        let err = ParseError::unsupported_chain("test-chain");
        assert!(matches!(err, ParseError::UnsupportedChain { chain } if chain == "test-chain"));

        let err = ParseError::invalid_address("bad-addr");
        assert!(matches!(err, ParseError::InvalidAddress { address } if address == "bad-addr"));
    }

    // ------------------------------------------------------------------------
    // SignError tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_sign_error_display() {
        assert_eq!(
            SignError::key_not_found("my-key").to_string(),
            "key not found: my-key"
        );

        assert_eq!(SignError::InvalidKey.to_string(), "invalid key material");

        assert_eq!(
            SignError::signature_failed("hash mismatch").to_string(),
            "signature failed: hash mismatch"
        );

        assert_eq!(
            SignError::wrong_curve("secp256k1", "ed25519").to_string(),
            "wrong curve: expected secp256k1, got ed25519"
        );
    }

    #[test]
    fn test_sign_error_constructors() {
        let err = SignError::key_not_found("test-key");
        assert!(matches!(err, SignError::KeyNotFound { name } if name == "test-key"));

        let err = SignError::signature_failed("test reason");
        assert!(matches!(err, SignError::SignatureFailed { context } if context == "test reason"));

        let err = SignError::wrong_curve("secp256k1", "ed25519");
        assert!(
            matches!(err, SignError::WrongCurve { expected, actual } if expected == "secp256k1" && actual == "ed25519")
        );
    }

    // ------------------------------------------------------------------------
    // StoreError tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_store_error_display() {
        assert_eq!(
            StoreError::EncryptionFailed.to_string(),
            "encryption failed"
        );

        assert_eq!(
            StoreError::DecryptionFailed.to_string(),
            "decryption failed (wrong password?)"
        );

        assert_eq!(
            StoreError::key_exists("existing-key").to_string(),
            "key already exists: existing-key"
        );

        assert_eq!(
            StoreError::key_not_found("missing-key").to_string(),
            "key not found: missing-key"
        );

        assert_eq!(
            StoreError::InvalidFormat.to_string(),
            "invalid key file format"
        );

        assert_eq!(
            StoreError::PermissionDenied.to_string(),
            "permission denied"
        );
    }

    #[test]
    fn test_store_error_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied");
        let store_err: StoreError = io_err.into();
        assert!(matches!(store_err, StoreError::PermissionDenied));

        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let store_err: StoreError = io_err.into();
        assert!(matches!(store_err, StoreError::InvalidFormat));

        let io_err = std::io::Error::other("something else");
        let store_err: StoreError = io_err.into();
        assert!(matches!(store_err, StoreError::IoError(_)));
    }

    #[test]
    fn test_store_error_constructors() {
        let err = StoreError::key_exists("test-key");
        assert!(matches!(err, StoreError::KeyExists { name } if name == "test-key"));

        let err = StoreError::key_not_found("test-key");
        assert!(matches!(err, StoreError::KeyNotFound { name } if name == "test-key"));
    }

    // ------------------------------------------------------------------------
    // PolicyError tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_policy_error_display() {
        assert_eq!(
            PolicyError::blacklisted("0x1234").to_string(),
            "address is blacklisted: 0x1234"
        );

        assert_eq!(
            PolicyError::not_whitelisted("0x5678").to_string(),
            "address not in whitelist: 0x5678"
        );

        assert_eq!(
            PolicyError::exceeds_transaction_limit("5 ETH", "10 ETH").to_string(),
            "exceeds transaction limit: limit=5 ETH, amount=10 ETH"
        );

        assert_eq!(
            PolicyError::exceeds_daily_limit("10 ETH", "8 ETH", "5 ETH").to_string(),
            "exceeds daily limit: limit=10 ETH, current=8 ETH, amount=5 ETH"
        );

        assert_eq!(
            PolicyError::invalid_configuration("missing whitelist").to_string(),
            "invalid configuration: missing whitelist"
        );
    }

    #[test]
    fn test_policy_error_rule_names() {
        assert_eq!(PolicyError::blacklisted("x").rule_name(), "blacklist");
        assert_eq!(PolicyError::not_whitelisted("x").rule_name(), "whitelist");
        assert_eq!(
            PolicyError::exceeds_transaction_limit("1", "2").rule_name(),
            "tx_limit"
        );
        assert_eq!(
            PolicyError::exceeds_daily_limit("1", "2", "3").rule_name(),
            "daily_limit"
        );
        assert_eq!(
            PolicyError::invalid_configuration("x").rule_name(),
            "configuration"
        );
    }

    #[test]
    fn test_policy_error_denial_reason() {
        let err = PolicyError::blacklisted("0x1234");
        assert_eq!(err.denial_reason(), "address is blacklisted: 0x1234");
    }

    // ------------------------------------------------------------------------
    // ConfigError tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_config_error_display() {
        assert_eq!(
            ConfigError::file_not_found("/path/to/config.toml").to_string(),
            "configuration file not found: /path/to/config.toml"
        );

        assert_eq!(
            ConfigError::parse_failed("invalid TOML syntax").to_string(),
            "failed to parse configuration: invalid TOML syntax"
        );

        assert_eq!(
            ConfigError::invalid_value("port", "-1").to_string(),
            "invalid value for port: -1"
        );

        assert_eq!(
            ConfigError::missing_field("api_key").to_string(),
            "missing required field: api_key"
        );
    }

    #[test]
    fn test_config_error_constructors() {
        let err = ConfigError::file_not_found("/test/path");
        assert!(matches!(err, ConfigError::FileNotFound { path } if path == "/test/path"));

        let err = ConfigError::parse_failed("test context");
        assert!(matches!(err, ConfigError::ParseFailed { context } if context == "test context"));

        let err = ConfigError::invalid_value("field", "value");
        assert!(
            matches!(err, ConfigError::InvalidValue { field, value } if field == "field" && value == "value")
        );

        let err = ConfigError::missing_field("test_field");
        assert!(matches!(err, ConfigError::MissingField { field } if field == "test_field"));
    }

    // ------------------------------------------------------------------------
    // Error trait implementation tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_store_error_source() {
        let io_err = std::io::Error::other("test error");
        let store_err = StoreError::io_error(io_err);

        // Verify the source chain works
        use std::error::Error;
        assert!(store_err.source().is_some());
    }

    #[test]
    fn test_sello_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SelloError>();
        assert_send_sync::<ParseError>();
        assert_send_sync::<SignError>();
        assert_send_sync::<StoreError>();
        assert_send_sync::<PolicyError>();
        assert_send_sync::<ConfigError>();
    }
}
