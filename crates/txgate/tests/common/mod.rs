//! # Test Utilities for `TxGate`
//!
//! This module provides shared test utilities and helpers for integration tests.
//!
//! ## Functions
//!
//! - [`load_fixture`] - Load a JSON fixture file from the fixtures directory
//! - [`temp_data_dir`] - Create an isolated temporary directory for test data
//!
//! ## Proptest Strategies
//!
//! This module also provides proptest strategies for property-based testing:
//!
//! - [`ethereum_address`] - Generate valid Ethereum addresses
//! - [`hex_bytes`] - Generate hex-encoded byte strings
//! - [`wei_amount`] - Generate valid wei amounts

#![allow(dead_code)]
// Allow expect() in test utilities since panicking on setup failures is acceptable in tests
#![allow(clippy::expect_used)]

use std::fmt::Write as FmtWrite;
use std::path::PathBuf;

use proptest::prelude::*;
use tempfile::TempDir;

/// Error type for fixture loading operations.
#[derive(Debug, thiserror::Error)]
pub enum FixtureError {
    /// The fixture file could not be found.
    #[error("Fixture not found: {0}")]
    NotFound(String),

    /// The fixture file could not be read.
    #[error("Failed to read fixture: {0}")]
    ReadError(#[from] std::io::Error),

    /// The fixture JSON could not be parsed.
    #[error("Failed to parse fixture JSON: {0}")]
    ParseError(#[from] serde_json::Error),
}

/// Load a JSON fixture file from the fixtures directory.
///
/// # Arguments
///
/// * `path` - Relative path to the fixture file from the `tests/fixtures/` directory.
///   For example, `"ethereum/legacy_transfer.json"`.
///
/// # Returns
///
/// Returns the parsed JSON value, or an error if the file cannot be loaded or parsed.
///
/// # Examples
///
/// ```ignore
/// use crate::common::load_fixture;
///
/// let fixture = load_fixture("ethereum/legacy_transfer.json")?;
/// let raw_tx = fixture["raw_tx"].as_str().unwrap();
/// ```
pub fn load_fixture(path: &str) -> Result<serde_json::Value, FixtureError> {
    let fixtures_dir = fixtures_dir();
    let fixture_path = fixtures_dir.join(path);

    if !fixture_path.exists() {
        return Err(FixtureError::NotFound(fixture_path.display().to_string()));
    }

    let content = std::fs::read_to_string(&fixture_path)?;
    let value: serde_json::Value = serde_json::from_str(&content)?;

    Ok(value)
}

/// Get the path to the fixtures directory.
///
/// This function determines the fixtures directory based on the `CARGO_MANIFEST_DIR`
/// environment variable, which is set during `cargo test`. It looks for fixtures
/// in the workspace root's tests/fixtures directory.
fn fixtures_dir() -> PathBuf {
    // CARGO_MANIFEST_DIR points to the crate directory (crates/txgate)
    // We need to go up two levels to reach the workspace root
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let manifest_path = PathBuf::from(manifest_dir);

    // Navigate up to workspace root: crates/txgate -> crates -> workspace
    manifest_path
        .parent() // crates
        .and_then(|p| p.parent()) // workspace root
        .map_or_else(
            || PathBuf::from("tests/fixtures"),
            |p| p.join("tests").join("fixtures"),
        )
}

/// Create a temporary directory for test data.
///
/// The directory will be automatically cleaned up when the returned `TempDir`
/// is dropped. This ensures test isolation and prevents test pollution.
///
/// # Returns
///
/// A `TempDir` instance that provides the path to the temporary directory.
///
/// # Examples
///
/// ```ignore
/// use crate::common::temp_data_dir;
///
/// let temp_dir = temp_data_dir();
/// let data_file = temp_dir.path().join("test_data.json");
/// std::fs::write(&data_file, "{}")?;
/// // Directory is cleaned up when temp_dir goes out of scope
/// ```
///
/// # Panics
///
/// Panics if the temporary directory cannot be created (e.g., due to
/// filesystem permissions or disk space issues).
#[must_use]
pub fn temp_data_dir() -> TempDir {
    tempfile::Builder::new()
        .prefix("txgate-test-")
        .tempdir()
        .expect("Failed to create temporary directory for test")
}

// =============================================================================
// Proptest Strategies
// =============================================================================

/// Convert a byte slice to a hex string.
fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // write! to a String never fails, so unwrap is safe here
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

/// Generate a valid Ethereum address (40 hex characters prefixed with 0x).
///
/// # Examples
///
/// ```ignore
/// use proptest::prelude::*;
/// use crate::common::ethereum_address;
///
/// proptest! {
///     #[test]
///     fn test_address_parsing(addr in ethereum_address()) {
///         assert!(addr.starts_with("0x"));
///         assert_eq!(addr.len(), 42);
///     }
/// }
/// ```
pub fn ethereum_address() -> impl Strategy<Value = String> {
    prop::collection::vec(prop::num::u8::ANY, 20).prop_map(|bytes| {
        let hex = bytes_to_hex(&bytes);
        format!("0x{hex}")
    })
}

/// Generate a hex-encoded byte string of a given length.
///
/// # Arguments
///
/// * `len` - The number of bytes to generate (the resulting string will be
///   `2 * len + 2` characters including the "0x" prefix).
///
/// # Examples
///
/// ```ignore
/// use proptest::prelude::*;
/// use crate::common::hex_bytes;
///
/// proptest! {
///     #[test]
///     fn test_hex_bytes(data in hex_bytes(32)) {
///         assert!(data.starts_with("0x"));
///         assert_eq!(data.len(), 66); // "0x" + 64 hex chars
///     }
/// }
/// ```
pub fn hex_bytes(len: usize) -> impl Strategy<Value = String> {
    prop::collection::vec(prop::num::u8::ANY, len).prop_map(|bytes| {
        let hex = bytes_to_hex(&bytes);
        format!("0x{hex}")
    })
}

/// Generate a valid wei amount as a decimal string.
///
/// The generated amounts range from 0 to 10^21 wei (approximately 1000 ETH),
/// which covers most realistic transaction amounts.
///
/// # Examples
///
/// ```ignore
/// use proptest::prelude::*;
/// use crate::common::wei_amount;
///
/// proptest! {
///     #[test]
///     fn test_wei_amount(amount in wei_amount()) {
///         let parsed: u128 = amount.parse().unwrap();
///         assert!(parsed <= 10u128.pow(21));
///     }
/// }
/// ```
pub fn wei_amount() -> impl Strategy<Value = String> {
    // Generate amounts from 0 to 10^21 (approximately 1000 ETH)
    (0u128..=1_000_000_000_000_000_000_000u128).prop_map(|amount| amount.to_string())
}

/// Generate a valid chain ID (1-100000 to cover most networks).
///
/// # Examples
///
/// ```ignore
/// use proptest::prelude::*;
/// use crate::common::chain_id;
///
/// proptest! {
///     #[test]
///     fn test_chain_id(id in chain_id()) {
///         assert!(id >= 1 && id <= 100000);
///     }
/// }
/// ```
pub fn chain_id() -> impl Strategy<Value = u64> {
    1u64..=100_000u64
}

/// Generate a valid nonce value.
///
/// Nonces are typically sequential and start from 0, so we generate
/// values in the range [0, 1000000] which covers most realistic scenarios.
pub fn nonce() -> impl Strategy<Value = u64> {
    0u64..=1_000_000u64
}

/// Generate a valid gas limit for Ethereum transactions.
///
/// The gas limit typically ranges from 21,000 (simple ETH transfer)
/// to 10,000,000 (complex contract interactions).
pub fn gas_limit() -> impl Strategy<Value = u64> {
    21_000u64..=10_000_000u64
}

/// Generate a valid gas price in wei (for legacy transactions).
///
/// Gas prices typically range from 1 gwei to 1000 gwei.
pub fn gas_price() -> impl Strategy<Value = String> {
    // 1 gwei to 1000 gwei
    (1_000_000_000u128..=1_000_000_000_000u128).prop_map(|price| price.to_string())
}

/// Generate a strategy for ERC-20 token transfer data.
///
/// This generates valid `transfer(address,uint256)` function call data.
pub fn erc20_transfer_data() -> impl Strategy<Value = String> {
    // ERC-20 transfer function selector: 0xa9059cbb
    // followed by: address (32 bytes, left-padded) + amount (32 bytes)
    (ethereum_address(), wei_amount()).prop_map(|(addr, amount)| {
        // Remove 0x prefix from address and left-pad to 32 bytes
        let addr_hex = addr.strip_prefix("0x").unwrap_or(&addr);
        let padded_addr = format!("{addr_hex:0>64}");

        // Convert amount to hex and left-pad to 32 bytes
        let amount_num: u128 = amount.parse().unwrap_or(0);
        let amount_hex = format!("{amount_num:064x}");

        format!("0xa9059cbb{padded_addr}{amount_hex}")
    })
}

// =============================================================================
// Test Helper Macros
// =============================================================================

/// Assert that two hex strings are equal, ignoring case.
///
/// # Examples
///
/// ```ignore
/// assert_hex_eq!("0xABCD", "0xabcd");
/// ```
#[macro_export]
macro_rules! assert_hex_eq {
    ($left:expr, $right:expr) => {
        assert_eq!(
            $left.to_lowercase(),
            $right.to_lowercase(),
            "Hex strings not equal: {} != {}",
            $left,
            $right
        );
    };
    ($left:expr, $right:expr, $($arg:tt)+) => {
        assert_eq!(
            $left.to_lowercase(),
            $right.to_lowercase(),
            $($arg)+
        );
    };
}

// Re-export the macro for use in tests
#[allow(unused_imports)]
pub use assert_hex_eq;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixtures_dir_exists() {
        let dir = fixtures_dir();
        assert!(dir.exists(), "Fixtures directory should exist: {dir:?}");
    }

    #[test]
    fn test_temp_data_dir_isolation() {
        let dir1 = temp_data_dir();
        let dir2 = temp_data_dir();

        assert_ne!(dir1.path(), dir2.path(), "Each temp dir should be unique");
    }

    proptest! {
        #[test]
        fn test_ethereum_address_format(addr in ethereum_address()) {
            prop_assert!(addr.starts_with("0x"));
            prop_assert_eq!(addr.len(), 42);
            // Verify all characters after 0x are valid hex
            for c in addr.chars().skip(2) {
                prop_assert!(c.is_ascii_hexdigit());
            }
        }

        #[test]
        fn test_hex_bytes_format(data in hex_bytes(32)) {
            prop_assert!(data.starts_with("0x"));
            prop_assert_eq!(data.len(), 66); // 2 + 32*2
        }

        #[test]
        fn test_wei_amount_parseable(amount in wei_amount()) {
            let parsed: Result<u128, _> = amount.parse();
            prop_assert!(parsed.is_ok());
        }

        #[test]
        fn test_chain_id_range(id in chain_id()) {
            prop_assert!(id >= 1);
            prop_assert!(id <= 100_000);
        }

        #[test]
        fn test_gas_limit_range(limit in gas_limit()) {
            prop_assert!(limit >= 21_000);
            prop_assert!(limit <= 10_000_000);
        }
    }
}
