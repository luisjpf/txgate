//! Error handling and conversion tests.
//!
//! These tests verify that error types implement the correct traits,
//! have proper Display implementations, and convert correctly between types.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::doc_markdown,
    clippy::io_other_error,
    clippy::no_effect_underscore_binding
)]

use std::error::Error;
use std::path::PathBuf;
use txgate::audit::{AuditError, PolicyResultInput};
use txgate::cli::commands::{
    AddressError, ConfigCommandError, InitError, ServeError, SignCommandError, StatusError,
};
use txgate::logging::LogError;
use txgate::server::ServerError;

/// Test that all error types implement the Error trait.
#[test]
fn test_error_trait_implementation() {
    // LogError
    let err = LogError::FileCreation("test".to_string());
    assert!(err.source().is_none());

    // AuditError
    let err = AuditError::KeyNotFound;
    assert!(err.source().is_none());

    // InitError
    let err = InitError::AlreadyInitialized;
    assert!(err.source().is_none());

    // StatusError
    let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
    let err = StatusError::Io(io_err);
    assert!(err.source().is_some());

    // AddressError
    let err = AddressError::NotInitialized;
    assert!(err.source().is_none());

    // SignCommandError
    let err = SignCommandError::NotInitialized;
    assert!(err.source().is_none());

    // ConfigCommandError
    let err = ConfigCommandError::NotInitialized;
    assert!(err.source().is_none());

    // ServeError
    let err = ServeError::NotInitialized;
    assert!(err.source().is_none());
}

/// Test error Display implementations.
#[test]
fn test_error_display() {
    // LogError
    let err = LogError::InvalidConfig("bad value".to_string());
    assert!(err.to_string().contains("Invalid log configuration"));
    assert!(err.to_string().contains("bad value"));

    let err = LogError::SubscriberInit("already set".to_string());
    assert!(err.to_string().contains("initialize logging"));

    // AuditError
    let err = AuditError::InvalidKey("wrong length".to_string());
    assert!(err.to_string().contains("Invalid audit key"));

    let err = AuditError::RotationFailed("disk full".to_string());
    assert!(err.to_string().contains("rotation failed"));

    let err = AuditError::LockError("timeout".to_string());
    assert!(err.to_string().contains("Lock error"));

    // InitError
    let err = InitError::PassphraseMismatch;
    assert!(err.to_string().contains("do not match"));

    let err = InitError::PassphraseCancelled;
    assert!(err.to_string().contains("cancelled"));

    let err = InitError::NoHomeDirectory;
    assert!(err.to_string().contains("home directory"));

    // AddressError
    let err = AddressError::KeyNotFound;
    assert!(err.to_string().contains("Default key not found"));

    // SignCommandError
    let err = SignCommandError::PolicyDenied {
        rule: "test-rule".to_string(),
        reason: "over limit".to_string(),
    };
    assert!(err.to_string().contains("Policy denied"));

    let err = SignCommandError::InvalidTransaction("bad hex".to_string());
    assert!(err.to_string().contains("Invalid transaction"));

    // ConfigCommandError
    let err = ConfigCommandError::EditorFailed("vim crashed".to_string());
    assert!(err.to_string().contains("Editor exited with error"));

    // ServeError
    let err = ServeError::Cancelled;
    assert!(err.to_string().contains("cancelled"));

    let err = ServeError::AuditError("key missing".to_string());
    assert!(err.to_string().contains("Audit logger"));
}

/// Test error conversions.
#[test]
fn test_error_conversions() {
    // StatusError from ConfigError
    use txgate_core::error::ConfigError;

    let config_err = ConfigError::file_not_found("/path/to/config");
    let status_err: StatusError = config_err.into();
    assert!(matches!(status_err, StatusError::ConfigError(_)));

    // AuditError from io::Error
    let io_err = std::io::Error::new(std::io::ErrorKind::Other, "test");
    let audit_err: AuditError = io_err.into();
    assert!(matches!(audit_err, AuditError::Io(_)));

    // InitError from io::Error
    let io_err = std::io::Error::new(std::io::ErrorKind::Other, "test");
    let init_err: InitError = io_err.into();
    assert!(matches!(init_err, InitError::Io(_)));

    // StatusError from io::Error
    let io_err = std::io::Error::new(std::io::ErrorKind::Other, "test");
    let status_err: StatusError = io_err.into();
    assert!(matches!(status_err, StatusError::Io(_)));

    // ServeError from io::Error
    let io_err = std::io::Error::new(std::io::ErrorKind::Other, "test");
    let serve_err: ServeError = io_err.into();
    assert!(matches!(serve_err, ServeError::Io(_)));

    // AddressError - No StoreError conversion in the actual code
    // Test direct error construction instead
    let addr_err = AddressError::KeyLoadError("failed to load".to_string());
    assert!(addr_err.to_string().contains("Failed to load key"));

    let addr_err = AddressError::InvalidPassphrase;
    assert!(addr_err.to_string().contains("passphrase"));
}

/// Test PolicyResultInput construction.
#[test]
fn test_policy_result_input() {
    // Test that the enum can be constructed
    let _allowed = PolicyResultInput::Allowed;

    let _denied = PolicyResultInput::Denied {
        rule: "whitelist".to_string(),
        reason: "not in list".to_string(),
    };

    // The as_audit_string method is private, so we just verify construction works
}

/// Test ServerError Display variants.
#[test]
fn test_server_error_display() {
    let err = ServerError::Bind {
        path: PathBuf::from("/tmp/test.sock"),
        source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"),
    };
    let display = err.to_string();
    assert!(display.contains("failed to bind socket"));
    assert!(display.contains("/tmp/test.sock"));

    let err = ServerError::Permissions {
        path: PathBuf::from("/tmp/test.sock"),
        source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"),
    };
    let display = err.to_string();
    assert!(display.contains("failed to set socket permissions"));

    let err = ServerError::Connection(std::io::Error::new(
        std::io::ErrorKind::ConnectionReset,
        "reset",
    ));
    let display = err.to_string();
    assert!(display.contains("connection error"));

    let err = ServerError::Read(std::io::Error::new(
        std::io::ErrorKind::Other,
        "read failed",
    ));
    let display = err.to_string();
    assert!(display.contains("read error"));

    let err = ServerError::Write(std::io::Error::new(
        std::io::ErrorKind::Other,
        "write failed",
    ));
    let display = err.to_string();
    assert!(display.contains("write error"));

    let err = ServerError::Parse("invalid json".to_string());
    let display = err.to_string();
    assert!(display.contains("parse error"));
}

/// Test SignCommandError exit codes.
#[test]
fn test_sign_command_error_exit_codes() {
    use txgate::cli::commands::SignCommandError;

    let err = SignCommandError::NotInitialized;
    assert_eq!(err.exit_code(), 2);

    let err = SignCommandError::PolicyDenied {
        rule: "test".to_string(),
        reason: "test".to_string(),
    };
    assert_eq!(err.exit_code(), 1);

    let err = SignCommandError::InvalidTransaction("test".to_string());
    assert_eq!(err.exit_code(), 2);

    let err = SignCommandError::SigningFailed("test".to_string());
    assert_eq!(err.exit_code(), 2);

    let err = SignCommandError::ConfigError("test".to_string());
    assert_eq!(err.exit_code(), 2);

    let err = SignCommandError::KeyNotFound;
    assert_eq!(err.exit_code(), 2);
}

/// Test that error types are Send and Sync.
#[test]
fn test_errors_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}

    assert_send_sync::<LogError>();
    assert_send_sync::<AuditError>();
    assert_send_sync::<InitError>();
    assert_send_sync::<StatusError>();
    assert_send_sync::<AddressError>();
    assert_send_sync::<SignCommandError>();
    assert_send_sync::<ConfigCommandError>();
    assert_send_sync::<ServeError>();
    assert_send_sync::<ServerError>();
}

/// Test ConfigCommandError variants.
#[test]
fn test_config_command_error_variants() {
    let err = ConfigCommandError::NotInitialized;
    assert!(err.to_string().contains("not initialized"));

    let err = ConfigCommandError::EditorNotFound;
    assert!(err.to_string().contains("Editor not found"));

    let err = ConfigCommandError::EditorFailed("code 1".to_string());
    assert!(err.to_string().contains("Editor"));

    let err = ConfigCommandError::ValidationFailed("bad toml".to_string());
    assert!(err.to_string().contains("validation"));
}
