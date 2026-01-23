//! RLP decoding utilities for Ethereum transaction parsing.
//!
//! This module provides helper functions that wrap `alloy-rlp` to simplify
//! Ethereum transaction decoding and improve error handling with Sello's
//! error types.
//!
//! # Overview
//!
//! While `alloy-rlp` provides comprehensive RLP encoding/decoding, this module
//! offers:
//! - Unified error handling with [`ParseError`]
//! - Transaction type detection helpers
//! - Convenient wrapper functions for common decoding patterns
//!
//! # Ethereum Transaction Types
//!
//! Ethereum has multiple transaction types:
//! - **Legacy (Type 0)**: Pre-EIP-2718, starts with RLP list prefix (0xc0-0xff)
//! - **EIP-2930 (Type 1)**: Access list transactions, prefixed with `0x01`
//! - **EIP-1559 (Type 2)**: Dynamic fee transactions, prefixed with `0x02`
//! - **EIP-4844 (Type 3)**: Blob transactions, prefixed with `0x03`
//!
//! # Example
//!
//! ```
//! use sello_chain::rlp::{detect_tx_type, is_list, typed_tx_payload};
//!
//! // EIP-1559 transaction (type 2)
//! let eip1559_tx = [0x02, 0xf8, 0x73]; // ... rest of transaction
//! assert_eq!(detect_tx_type(&eip1559_tx), Some(2));
//!
//! // Legacy transaction (starts with RLP list prefix)
//! let legacy_tx = [0xf8, 0x6c, 0x09]; // ... rest of transaction
//! assert_eq!(detect_tx_type(&legacy_tx), None);
//! assert!(is_list(&legacy_tx));
//! ```

use alloy_primitives::{Address, U256};
use alloy_rlp::{Decodable, Header, PayloadView};
use sello_core::error::ParseError;

/// Result type for RLP operations using [`ParseError`].
pub type RlpResult<T> = Result<T, ParseError>;

// ============================================================================
// Transaction Type Detection
// ============================================================================

/// Detect the transaction type from the first byte.
///
/// Ethereum typed transactions (EIP-2718) are prefixed with a type byte:
/// - `0x01` - EIP-2930 (Access List)
/// - `0x02` - EIP-1559 (Dynamic Fee)
/// - `0x03` - EIP-4844 (Blob Transaction)
///
/// Legacy transactions start with an RLP list marker (0xc0-0xff).
///
/// # Arguments
///
/// * `data` - Raw transaction bytes
///
/// # Returns
///
/// * `Some(type)` - For typed transactions (EIP-2718+)
/// * `None` - For legacy transactions or empty input
///
/// # Example
///
/// ```
/// use sello_chain::rlp::detect_tx_type;
///
/// // EIP-1559 transaction
/// let typed = [0x02, 0xf8, 0x73, 0x01];
/// assert_eq!(detect_tx_type(&typed), Some(2));
///
/// // Legacy transaction (RLP list prefix)
/// let legacy = [0xf8, 0x6c, 0x09];
/// assert_eq!(detect_tx_type(&legacy), None);
///
/// // Empty data
/// assert_eq!(detect_tx_type(&[]), None);
/// ```
#[must_use]
pub fn detect_tx_type(data: &[u8]) -> Option<u8> {
    data.first().and_then(|&b| {
        if b >= 0xc0 {
            // Legacy transaction (RLP list prefix 0xc0-0xff)
            None
        } else if b <= 0x03 {
            // Typed transaction (0x00-0x03)
            // Note: 0x00 is technically valid but rarely used
            Some(b)
        } else {
            // Unknown prefix - could be invalid or future types
            // Treat as None for safety, let the parser handle validation
            None
        }
    })
}

/// Check if data starts with an RLP list prefix.
///
/// This is useful for detecting legacy Ethereum transactions,
/// which are encoded as RLP lists without a type prefix.
///
/// # Arguments
///
/// * `data` - Raw data bytes
///
/// # Returns
///
/// * `true` if the first byte is in the range 0xc0-0xff (RLP list markers)
/// * `false` otherwise
///
/// # Example
///
/// ```
/// use sello_chain::rlp::is_list;
///
/// // RLP list prefixes
/// assert!(is_list(&[0xc0])); // Empty list
/// assert!(is_list(&[0xc8, 0x01, 0x02])); // Short list
/// assert!(is_list(&[0xf8, 0x6c])); // Long list
///
/// // Not lists
/// assert!(!is_list(&[0x02])); // Type 2 tx prefix
/// assert!(!is_list(&[0x80])); // Empty string
/// assert!(!is_list(&[])); // Empty data
/// ```
#[must_use]
pub fn is_list(data: &[u8]) -> bool {
    data.first().is_some_and(|&b| b >= 0xc0)
}

/// Get the payload of a typed transaction (skip the type byte).
///
/// For typed transactions (EIP-2718+), the first byte is the type.
/// This function returns the remaining bytes (the RLP-encoded transaction).
///
/// For legacy transactions (starting with 0xc0+), returns the data unchanged.
///
/// # Arguments
///
/// * `data` - Raw transaction bytes
///
/// # Returns
///
/// * `Ok(&[u8])` - The transaction payload (without type byte for typed txs)
/// * `Err(ParseError)` - If data is empty
///
/// # Errors
///
/// Returns [`ParseError::MalformedTransaction`] if the input data is empty.
///
/// # Example
///
/// ```
/// use sello_chain::rlp::typed_tx_payload;
///
/// // EIP-1559 transaction
/// let typed = [0x02, 0xf8, 0x73, 0x01];
/// let payload = typed_tx_payload(&typed).unwrap();
/// assert_eq!(payload, &[0xf8, 0x73, 0x01]);
///
/// // Legacy transaction (unchanged)
/// let legacy = [0xf8, 0x6c, 0x09];
/// let payload = typed_tx_payload(&legacy).unwrap();
/// assert_eq!(payload, &[0xf8, 0x6c, 0x09]);
/// ```
pub fn typed_tx_payload(data: &[u8]) -> RlpResult<&[u8]> {
    let first_byte = data
        .first()
        .ok_or_else(|| ParseError::MalformedTransaction {
            context: "Empty transaction data".to_string(),
        })?;

    // For typed transactions (type byte 0x00-0x03), skip the first byte
    if *first_byte <= 0x03 {
        Ok(data.get(1..).unwrap_or_default())
    } else {
        // Legacy transaction or other - return as-is
        Ok(data)
    }
}

// ============================================================================
// Decoding Helpers
// ============================================================================

/// Decode an RLP-encoded byte string.
///
/// This function decodes an RLP string (not a list) into raw bytes.
/// Uses `Header::decode_bytes` from alloy-rlp internally.
///
/// # Arguments
///
/// * `data` - RLP-encoded string data
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - The decoded bytes
/// * `Err(ParseError)` - If decoding fails or data is a list
///
/// # Errors
///
/// Returns [`ParseError::InvalidRlp`] if:
/// - The data is not valid RLP encoding
/// - The data encodes a list instead of a string
/// - The data is truncated
///
/// # Example
///
/// ```
/// use sello_chain::rlp::decode_bytes;
///
/// // Single byte (< 0x80) is itself
/// let data = [0x42];
/// assert_eq!(decode_bytes(&data).unwrap(), vec![0x42]);
///
/// // Empty string (0x80)
/// let empty = [0x80];
/// assert_eq!(decode_bytes(&empty).unwrap(), Vec::<u8>::new());
///
/// // Short string (0x80 + len, then bytes)
/// let short = [0x83, 0x61, 0x62, 0x63]; // "abc"
/// assert_eq!(decode_bytes(&short).unwrap(), vec![0x61, 0x62, 0x63]);
/// ```
pub fn decode_bytes(data: &[u8]) -> RlpResult<Vec<u8>> {
    let mut buf = data;
    // Use Header::decode_bytes with is_list=false to decode a string
    let bytes = Header::decode_bytes(&mut buf, false).map_err(|e| ParseError::InvalidRlp {
        context: format!("Failed to decode bytes: {e}"),
    })?;
    Ok(bytes.to_vec())
}

/// Decode an RLP-encoded list and return its items.
///
/// Each item in the returned vector is still RLP-encoded and can be
/// decoded individually using the appropriate decoder.
///
/// # Arguments
///
/// * `data` - RLP-encoded list data
///
/// # Returns
///
/// * `Ok(Vec<&[u8]>)` - Vector of RLP-encoded items
/// * `Err(ParseError)` - If decoding fails or data is not a list
///
/// # Errors
///
/// Returns [`ParseError::InvalidRlp`] if:
/// - The data is not valid RLP encoding
/// - The data encodes a string instead of a list
/// - The data is truncated
///
/// # Example
///
/// ```
/// use sello_chain::rlp::decode_list;
///
/// // Empty list (0xc0)
/// let empty_list = [0xc0];
/// assert_eq!(decode_list(&empty_list).unwrap().len(), 0);
///
/// // List with two items: [1, 2]
/// let list = [0xc2, 0x01, 0x02];
/// let items = decode_list(&list).unwrap();
/// assert_eq!(items.len(), 2);
/// assert_eq!(items[0], &[0x01]);
/// assert_eq!(items[1], &[0x02]);
/// ```
pub fn decode_list(data: &[u8]) -> RlpResult<Vec<&[u8]>> {
    let mut buf = data;
    let payload = Header::decode_raw(&mut buf).map_err(|e| ParseError::InvalidRlp {
        context: format!("Failed to decode list: {e}"),
    })?;

    match payload {
        PayloadView::List(items) => Ok(items),
        PayloadView::String(_) => Err(ParseError::InvalidRlp {
            context: "Expected list, found string".to_string(),
        }),
    }
}

/// Decode a U256 from RLP-encoded data.
///
/// # Arguments
///
/// * `data` - RLP-encoded U256
///
/// # Returns
///
/// * `Ok(U256)` - The decoded value
/// * `Err(ParseError)` - If decoding fails
///
/// # Errors
///
/// Returns [`ParseError::InvalidRlp`] if the data is not valid RLP encoding
/// or cannot be decoded as a U256.
///
/// # Example
///
/// ```
/// use sello_chain::rlp::decode_u256;
/// use alloy_primitives::U256;
///
/// // Zero (0x80 = empty string = 0)
/// let zero = [0x80];
/// assert_eq!(decode_u256(&zero).unwrap(), U256::ZERO);
///
/// // Small value (0x42 = 66)
/// let small = [0x42];
/// assert_eq!(decode_u256(&small).unwrap(), U256::from(0x42u64));
///
/// // 256 (0x82, 0x01, 0x00)
/// let medium = [0x82, 0x01, 0x00];
/// assert_eq!(decode_u256(&medium).unwrap(), U256::from(256u64));
/// ```
pub fn decode_u256(data: &[u8]) -> RlpResult<U256> {
    let mut buf = data;
    U256::decode(&mut buf).map_err(|e| ParseError::InvalidRlp {
        context: format!("Failed to decode U256: {e}"),
    })
}

/// Decode an Ethereum address from RLP-encoded data.
///
/// Ethereum addresses are 20 bytes. The RLP encoding is:
/// - `0x94` followed by 20 bytes (string of length 20)
/// - Or empty string `0x80` for null/zero address (contract creation)
///
/// # Arguments
///
/// * `data` - RLP-encoded address
///
/// # Returns
///
/// * `Ok(Address)` - The decoded address
/// * `Err(ParseError)` - If decoding fails or length is wrong
///
/// # Errors
///
/// Returns [`ParseError::InvalidRlp`] if:
/// - The data is not valid RLP encoding
/// - The decoded bytes are not exactly 20 bytes
///
/// # Example
///
/// ```
/// use sello_chain::rlp::decode_address;
///
/// // 20-byte address (0x94 = string of length 20)
/// let addr_data = [
///     0x94, // prefix for 20-byte string
///     0x35, 0x35, 0x35, 0x35, 0x35, 0x35, 0x35, 0x35, 0x35, 0x35,
///     0x35, 0x35, 0x35, 0x35, 0x35, 0x35, 0x35, 0x35, 0x35, 0x35,
/// ];
/// let addr = decode_address(&addr_data).unwrap();
/// assert_eq!(format!("{addr}"), "0x3535353535353535353535353535353535353535");
/// ```
pub fn decode_address(data: &[u8]) -> RlpResult<Address> {
    let mut buf = data;
    Address::decode(&mut buf).map_err(|e| ParseError::InvalidRlp {
        context: format!("Failed to decode address: {e}"),
    })
}

/// Decode an optional Ethereum address from RLP-encoded data.
///
/// This handles the case where the address field can be empty (contract creation).
///
/// # Arguments
///
/// * `data` - RLP-encoded address or empty string
///
/// # Returns
///
/// * `Ok(Some(Address))` - For non-empty addresses
/// * `Ok(None)` - For empty string (contract creation)
/// * `Err(ParseError)` - If decoding fails
///
/// # Errors
///
/// Returns [`ParseError::InvalidRlp`] if the non-empty data cannot be
/// decoded as a valid 20-byte address.
///
/// # Example
///
/// ```
/// use sello_chain::rlp::decode_optional_address;
///
/// // Empty address (contract creation)
/// let empty = [0x80];
/// assert!(decode_optional_address(&empty).unwrap().is_none());
///
/// // Regular address
/// let addr_data = [
///     0x94,
///     0x35, 0x35, 0x35, 0x35, 0x35, 0x35, 0x35, 0x35, 0x35, 0x35,
///     0x35, 0x35, 0x35, 0x35, 0x35, 0x35, 0x35, 0x35, 0x35, 0x35,
/// ];
/// assert!(decode_optional_address(&addr_data).unwrap().is_some());
/// ```
pub fn decode_optional_address(data: &[u8]) -> RlpResult<Option<Address>> {
    // Check for empty string (0x80)
    if data == [0x80] {
        return Ok(None);
    }

    decode_address(data).map(Some)
}

/// Decode a u64 from RLP-encoded data.
///
/// # Arguments
///
/// * `data` - RLP-encoded u64
///
/// # Returns
///
/// * `Ok(u64)` - The decoded value
/// * `Err(ParseError)` - If decoding fails or value overflows u64
///
/// # Errors
///
/// Returns [`ParseError::InvalidRlp`] if:
/// - The data is not valid RLP encoding
/// - The decoded value overflows u64
///
/// # Example
///
/// ```
/// use sello_chain::rlp::decode_u64;
///
/// // Zero
/// let zero = [0x80];
/// assert_eq!(decode_u64(&zero).unwrap(), 0);
///
/// // Small value
/// let small = [0x09];
/// assert_eq!(decode_u64(&small).unwrap(), 9);
///
/// // Larger value (21000 = 0x5208)
/// let gas = [0x82, 0x52, 0x08];
/// assert_eq!(decode_u64(&gas).unwrap(), 21000);
/// ```
pub fn decode_u64(data: &[u8]) -> RlpResult<u64> {
    let mut buf = data;
    u64::decode(&mut buf).map_err(|e| ParseError::InvalidRlp {
        context: format!("Failed to decode u64: {e}"),
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
        clippy::unreadable_literal
    )]

    use super::*;
    use alloy_primitives::hex;
    use alloy_rlp::Encodable;

    // ------------------------------------------------------------------------
    // Transaction Type Detection Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_detect_tx_type_legacy() {
        // RLP list prefixes (0xc0-0xff) indicate legacy transactions
        assert_eq!(detect_tx_type(&[0xc0]), None);
        assert_eq!(detect_tx_type(&[0xc8, 0x01, 0x02]), None);
        assert_eq!(detect_tx_type(&[0xf8, 0x6c, 0x09]), None);
        assert_eq!(detect_tx_type(&[0xff]), None);
    }

    #[test]
    fn test_detect_tx_type_typed() {
        // Type 0 (rarely used but valid)
        assert_eq!(detect_tx_type(&[0x00, 0xf8, 0x73]), Some(0));

        // Type 1 - EIP-2930
        assert_eq!(detect_tx_type(&[0x01, 0xf8, 0x73]), Some(1));

        // Type 2 - EIP-1559
        assert_eq!(detect_tx_type(&[0x02, 0xf8, 0x73]), Some(2));

        // Type 3 - EIP-4844
        assert_eq!(detect_tx_type(&[0x03, 0xf8, 0x73]), Some(3));
    }

    #[test]
    fn test_detect_tx_type_unknown() {
        // Unknown type bytes (0x04-0xbf) - not currently valid tx types
        assert_eq!(detect_tx_type(&[0x04]), None);
        assert_eq!(detect_tx_type(&[0x80]), None);
        assert_eq!(detect_tx_type(&[0xbf]), None);
    }

    #[test]
    fn test_detect_tx_type_empty() {
        assert_eq!(detect_tx_type(&[]), None);
    }

    // ------------------------------------------------------------------------
    // is_list Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_is_list() {
        // RLP list prefixes
        assert!(is_list(&[0xc0]));
        assert!(is_list(&[0xc8, 0x01, 0x02]));
        assert!(is_list(&[0xf7, 0x01]));
        assert!(is_list(&[0xf8, 0x6c]));
        assert!(is_list(&[0xff]));

        // Not lists
        assert!(!is_list(&[0x00]));
        assert!(!is_list(&[0x01]));
        assert!(!is_list(&[0x02]));
        assert!(!is_list(&[0x80])); // Empty string
        assert!(!is_list(&[0xbf])); // Max string prefix
        assert!(!is_list(&[]));
    }

    // ------------------------------------------------------------------------
    // typed_tx_payload Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_typed_tx_payload_eip1559() {
        let typed = [0x02, 0xf8, 0x73, 0x01, 0x02, 0x03];
        let payload = typed_tx_payload(&typed).unwrap();
        assert_eq!(payload, &[0xf8, 0x73, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_typed_tx_payload_legacy() {
        let legacy = [0xf8, 0x6c, 0x09, 0x84];
        let payload = typed_tx_payload(&legacy).unwrap();
        assert_eq!(payload, &[0xf8, 0x6c, 0x09, 0x84]);
    }

    #[test]
    fn test_typed_tx_payload_empty() {
        let result = typed_tx_payload(&[]);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(ParseError::MalformedTransaction { .. })
        ));
    }

    #[test]
    fn test_typed_tx_payload_type_0() {
        // Type 0 is valid but rare
        let typed = [0x00, 0xf8, 0x73];
        let payload = typed_tx_payload(&typed).unwrap();
        assert_eq!(payload, &[0xf8, 0x73]);
    }

    // ------------------------------------------------------------------------
    // decode_bytes Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_decode_bytes_single() {
        // Single byte (value < 0x80)
        assert_eq!(decode_bytes(&[0x42]).unwrap(), vec![0x42]);
        assert_eq!(decode_bytes(&[0x00]).unwrap(), vec![0x00]);
        assert_eq!(decode_bytes(&[0x7f]).unwrap(), vec![0x7f]);
    }

    #[test]
    fn test_decode_bytes_empty() {
        // Empty string is encoded as 0x80
        assert_eq!(decode_bytes(&[0x80]).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn test_decode_bytes_short_string() {
        // Short string (1-55 bytes): 0x80 + len, then bytes
        let encoded = [0x83, 0x61, 0x62, 0x63]; // "abc"
        assert_eq!(decode_bytes(&encoded).unwrap(), vec![0x61, 0x62, 0x63]);
    }

    #[test]
    fn test_decode_bytes_invalid() {
        // Invalid RLP (truncated)
        let result = decode_bytes(&[0x83, 0x61, 0x62]); // Claims 3 bytes but only has 2
        assert!(result.is_err());
    }

    // ------------------------------------------------------------------------
    // decode_list Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_decode_list_empty() {
        // Empty list is encoded as 0xc0
        let items = decode_list(&[0xc0]).unwrap();
        assert!(items.is_empty());
    }

    #[test]
    fn test_decode_list_single_item() {
        // List with single item [1]
        let items = decode_list(&[0xc1, 0x01]).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0], &[0x01]);
    }

    #[test]
    fn test_decode_list_multiple_items() {
        // List [1, 2, 3]
        let items = decode_list(&[0xc3, 0x01, 0x02, 0x03]).unwrap();
        assert_eq!(items.len(), 3);
        assert_eq!(items[0], &[0x01]);
        assert_eq!(items[1], &[0x02]);
        assert_eq!(items[2], &[0x03]);
    }

    #[test]
    fn test_decode_list_not_a_list() {
        // String instead of list
        let result = decode_list(&[0x83, 0x61, 0x62, 0x63]);
        assert!(result.is_err());
        assert!(matches!(result, Err(ParseError::InvalidRlp { .. })));
    }

    // ------------------------------------------------------------------------
    // decode_u256 Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_decode_u256_zero() {
        assert_eq!(decode_u256(&[0x80]).unwrap(), U256::ZERO);
    }

    #[test]
    fn test_decode_u256_small() {
        assert_eq!(decode_u256(&[0x01]).unwrap(), U256::from(1u64));
        assert_eq!(decode_u256(&[0x7f]).unwrap(), U256::from(127u64));
    }

    #[test]
    fn test_decode_u256_medium() {
        // 256 = 0x0100
        assert_eq!(
            decode_u256(&[0x82, 0x01, 0x00]).unwrap(),
            U256::from(256u64)
        );
    }

    #[test]
    fn test_decode_u256_1eth() {
        // 1 ETH = 10^18 = 0x0de0b6b3a7640000
        let encoded = [0x88, 0x0d, 0xe0, 0xb6, 0xb3, 0xa7, 0x64, 0x00, 0x00];
        let expected = U256::from(1_000_000_000_000_000_000u64);
        assert_eq!(decode_u256(&encoded).unwrap(), expected);
    }

    // ------------------------------------------------------------------------
    // decode_address Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_decode_address() {
        let addr_bytes = [
            0x94, // 20-byte string prefix
            0x35, 0x35, 0x35, 0x35, 0x35, 0x35, 0x35, 0x35, 0x35, 0x35, 0x35, 0x35, 0x35, 0x35,
            0x35, 0x35, 0x35, 0x35, 0x35, 0x35,
        ];

        let addr = decode_address(&addr_bytes).unwrap();
        assert_eq!(
            format!("{addr}"),
            "0x3535353535353535353535353535353535353535"
        );
    }

    #[test]
    fn test_decode_address_invalid_length() {
        // 19 bytes instead of 20
        let short = [
            0x93, // 19-byte string prefix
            0x35, 0x35, 0x35, 0x35, 0x35, 0x35, 0x35, 0x35, 0x35, 0x35, 0x35, 0x35, 0x35, 0x35,
            0x35, 0x35, 0x35, 0x35, 0x35,
        ];

        let result = decode_address(&short);
        assert!(result.is_err());
    }

    // ------------------------------------------------------------------------
    // decode_optional_address Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_decode_optional_address_empty() {
        // Empty string = contract creation
        assert!(decode_optional_address(&[0x80]).unwrap().is_none());
    }

    #[test]
    fn test_decode_optional_address_present() {
        let addr_bytes = [
            0x94, 0x35, 0x35, 0x35, 0x35, 0x35, 0x35, 0x35, 0x35, 0x35, 0x35, 0x35, 0x35, 0x35,
            0x35, 0x35, 0x35, 0x35, 0x35, 0x35, 0x35,
        ];

        let addr = decode_optional_address(&addr_bytes).unwrap();
        assert!(addr.is_some());
    }

    // ------------------------------------------------------------------------
    // decode_u64 Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_decode_u64_zero() {
        assert_eq!(decode_u64(&[0x80]).unwrap(), 0);
    }

    #[test]
    fn test_decode_u64_small() {
        assert_eq!(decode_u64(&[0x09]).unwrap(), 9);
        assert_eq!(decode_u64(&[0x7f]).unwrap(), 127);
    }

    #[test]
    fn test_decode_u64_gas_limit() {
        // 21000 = 0x5208
        assert_eq!(decode_u64(&[0x82, 0x52, 0x08]).unwrap(), 21000);
    }

    #[test]
    fn test_decode_u64_gas_price() {
        // 20 gwei = 20_000_000_000 = 0x04a817c800
        assert_eq!(
            decode_u64(&[0x85, 0x04, 0xa8, 0x17, 0xc8, 0x00]).unwrap(),
            20_000_000_000
        );
    }

    // ------------------------------------------------------------------------
    // Integration Tests with Real Transaction Data
    // ------------------------------------------------------------------------

    #[test]
    fn test_legacy_transaction_detection() {
        // Legacy transaction from fixture (starts with 0xf8 = long list)
        let raw = hex::decode(
            "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83"
        ).unwrap();

        assert_eq!(detect_tx_type(&raw), None);
        assert!(is_list(&raw));

        // Should be able to decode as a list
        let items = decode_list(&raw).unwrap();
        assert_eq!(items.len(), 9); // nonce, gasPrice, gasLimit, to, value, data, v, r, s
    }

    #[test]
    fn test_eip1559_transaction_detection() {
        // EIP-1559 transaction (type 2) - manually constructed valid structure
        // Format: 0x02 || RLP([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList, v, r, s])
        let raw = hex::decode(
            "02f8730101847735940084773594008252089495ad61b0a150d79219dcf64e1e6cc01f0b64c4ce880de0b6b3a764000080c080a0e9d9f35c8b4a8e4da5fb0f6dd3cb0e49da8d4c0b7b0e0c2c2d8c8a1e3f4a5b6c7a07f8e9d0c1b2a394857660544e3d2c1b0a99887766554433221100112233445566"
        ).unwrap();

        assert_eq!(detect_tx_type(&raw), Some(2));
        assert!(!is_list(&raw));

        // Get payload without type byte
        let payload = typed_tx_payload(&raw).unwrap();
        assert!(is_list(payload));
    }

    // ------------------------------------------------------------------------
    // Roundtrip Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_u256_encode_decode_roundtrip() {
        let values = [
            U256::ZERO,
            U256::from(1u64),
            U256::from(127u64),
            U256::from(128u64),
            U256::from(256u64),
            U256::from(1_000_000_000_000_000_000u64), // 1 ETH
            U256::MAX,
        ];

        for value in values {
            let mut encoded = Vec::new();
            value.encode(&mut encoded);
            let decoded = decode_u256(&encoded).unwrap();
            assert_eq!(decoded, value, "roundtrip failed for {value}");
        }
    }

    #[test]
    fn test_u64_encode_decode_roundtrip() {
        let values = [0u64, 1, 127, 128, 255, 256, 21000, 20_000_000_000, u64::MAX];

        for value in values {
            let mut encoded = Vec::new();
            value.encode(&mut encoded);
            let decoded = decode_u64(&encoded).unwrap();
            assert_eq!(decoded, value, "roundtrip failed for {value}");
        }
    }

    #[test]
    fn test_address_encode_decode_roundtrip() {
        let addresses = [
            Address::ZERO,
            Address::from([0x35u8; 20]),
            Address::from([0xffu8; 20]),
        ];

        for addr in addresses {
            let mut encoded = Vec::new();
            addr.encode(&mut encoded);
            let decoded = decode_address(&encoded).unwrap();
            assert_eq!(decoded, addr, "roundtrip failed for {addr}");
        }
    }

    // ------------------------------------------------------------------------
    // RLP Decoding Error Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_decode_bytes_truncated_data() {
        // Arrange: RLP claims to have more data than actually present
        // 0x85 = string of length 5, but only 3 bytes follow
        let truncated = [0x85, 0x01, 0x02, 0x03];

        // Act
        let result = decode_bytes(&truncated);

        // Assert: Should fail with InvalidRlp
        assert!(result.is_err());
        assert!(matches!(result, Err(ParseError::InvalidRlp { .. })));
    }

    #[test]
    fn test_decode_bytes_invalid_length_prefix() {
        // Arrange: Invalid RLP with malformed length prefix
        // 0xbf is the maximum single-byte string prefix, 0xc0 starts lists
        // Using an invalid sequence that doesn't follow RLP rules
        let invalid = [0xf9, 0x00]; // Long list prefix but data is too short

        // Act
        let result = decode_bytes(&invalid);

        // Assert: Should fail with InvalidRlp
        assert!(result.is_err());
        assert!(matches!(result, Err(ParseError::InvalidRlp { .. })));
    }

    #[test]
    fn test_decode_bytes_empty_input() {
        // Arrange: Empty input
        let empty: [u8; 0] = [];

        // Act
        let result = decode_bytes(&empty);

        // Assert: Should fail with InvalidRlp (no data to decode)
        assert!(result.is_err());
        assert!(matches!(result, Err(ParseError::InvalidRlp { .. })));
    }

    #[test]
    fn test_decode_list_truncated_data() {
        // Arrange: RLP list claims to have more items than present
        // 0xc3 = list of 3 bytes total payload, but only 2 bytes follow
        let truncated = [0xc3, 0x01, 0x02];

        // Act
        let result = decode_list(&truncated);

        // Assert: Should fail with InvalidRlp
        assert!(result.is_err());
        assert!(matches!(result, Err(ParseError::InvalidRlp { .. })));
    }

    #[test]
    fn test_decode_list_invalid_structure() {
        // Arrange: Malformed list structure with invalid length encoding
        // 0xf8 requires a length byte, but it's missing or invalid
        let invalid = [0xf8];

        // Act
        let result = decode_list(&invalid);

        // Assert: Should fail with InvalidRlp
        assert!(result.is_err());
        assert!(matches!(result, Err(ParseError::InvalidRlp { .. })));
    }

    #[test]
    fn test_decode_list_string_instead_of_list() {
        // Arrange: Try to decode a string as a list
        // 0x83 = string of length 3
        let string_data = [0x83, 0x61, 0x62, 0x63];

        // Act
        let result = decode_list(&string_data);

        // Assert: Should fail with InvalidRlp indicating expected list
        assert!(result.is_err());
        assert!(matches!(result, Err(ParseError::InvalidRlp { .. })));
        if let Err(ParseError::InvalidRlp { context }) = result {
            assert!(context.contains("Expected list"));
        }
    }

    #[test]
    fn test_decode_list_empty_input() {
        // Arrange: Empty input
        let empty: [u8; 0] = [];

        // Act
        let result = decode_list(&empty);

        // Assert: Should fail with InvalidRlp
        assert!(result.is_err());
        assert!(matches!(result, Err(ParseError::InvalidRlp { .. })));
    }

    #[test]
    fn test_decode_u256_invalid_encoding() {
        // Arrange: Truncated U256 encoding
        // 0x82 = string of length 2, but only 1 byte follows
        let invalid = [0x82, 0x01];

        // Act
        let result = decode_u256(&invalid);

        // Assert: Should fail with InvalidRlp
        assert!(result.is_err());
        assert!(matches!(result, Err(ParseError::InvalidRlp { .. })));
    }

    #[test]
    fn test_decode_u256_empty_input() {
        // Arrange: Empty input
        let empty: [u8; 0] = [];

        // Act
        let result = decode_u256(&empty);

        // Assert: Should fail with InvalidRlp
        assert!(result.is_err());
        assert!(matches!(result, Err(ParseError::InvalidRlp { .. })));
    }

    #[test]
    fn test_decode_u64_overflow() {
        // Arrange: Value that's too large for u64 (9 bytes)
        // 0x89 = string of length 9
        let too_large = [0x89, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

        // Act
        let result = decode_u64(&too_large);

        // Assert: Should fail with InvalidRlp
        assert!(result.is_err());
        assert!(matches!(result, Err(ParseError::InvalidRlp { .. })));
    }

    #[test]
    fn test_decode_u64_truncated() {
        // Arrange: Claims 4 bytes but only has 3
        let truncated = [0x84, 0x01, 0x02, 0x03];

        // Act
        let result = decode_u64(&truncated);

        // Assert: Should fail with InvalidRlp
        assert!(result.is_err());
        assert!(matches!(result, Err(ParseError::InvalidRlp { .. })));
    }

    #[test]
    fn test_decode_address_wrong_length() {
        // Arrange: Address with wrong length (19 bytes instead of 20)
        let wrong_length = [
            0x93, // 19-byte string prefix
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13,
        ];

        // Act
        let result = decode_address(&wrong_length);

        // Assert: Should fail with InvalidRlp
        assert!(result.is_err());
        assert!(matches!(result, Err(ParseError::InvalidRlp { .. })));
    }

    #[test]
    fn test_decode_address_truncated() {
        // Arrange: Claims 20 bytes but only has 19
        let truncated = [
            0x94, // 20-byte string prefix
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13,
        ];

        // Act
        let result = decode_address(&truncated);

        // Assert: Should fail with InvalidRlp
        assert!(result.is_err());
        assert!(matches!(result, Err(ParseError::InvalidRlp { .. })));
    }

    #[test]
    fn test_decode_address_empty_input() {
        // Arrange: Empty input
        let empty: [u8; 0] = [];

        // Act
        let result = decode_address(&empty);

        // Assert: Should fail with InvalidRlp
        assert!(result.is_err());
        assert!(matches!(result, Err(ParseError::InvalidRlp { .. })));
    }

    #[test]
    fn test_decode_optional_address_invalid_length() {
        // Arrange: Non-empty address with wrong length
        let wrong_length = [
            0x93, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
        ];

        // Act
        let result = decode_optional_address(&wrong_length);

        // Assert: Should fail with InvalidRlp
        assert!(result.is_err());
        assert!(matches!(result, Err(ParseError::InvalidRlp { .. })));
    }

    #[test]
    fn test_typed_tx_payload_boundary_type_0() {
        // Arrange: Type 0 transaction with minimal payload
        let type0 = [0x00];

        // Act
        let result = typed_tx_payload(&type0);

        // Assert: Should return empty slice after type byte
        assert!(result.is_ok());
        let payload = result.unwrap();
        assert!(payload.is_empty());
    }

    #[test]
    fn test_typed_tx_payload_boundary_type_3() {
        // Arrange: Type 3 transaction (boundary of supported types)
        let type3 = [0x03, 0xf8, 0x73];

        // Act
        let result = typed_tx_payload(&type3);

        // Assert: Should return payload without type byte
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), &[0xf8, 0x73]);
    }

    #[test]
    fn test_rlp_boundary_length_zero() {
        // Arrange: RLP string with length = 0 (should be encoded as 0x80)
        let zero_length = [0x80];

        // Act
        let result = decode_bytes(&zero_length);

        // Assert: Should decode to empty vec
        assert!(result.is_ok());
        let decoded = result.unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_rlp_boundary_length_one() {
        // Arrange: RLP with single byte (length = 1)
        // Single bytes < 0x80 are encoded as themselves
        let one_byte = [0x42];

        // Act
        let result = decode_bytes(&one_byte);

        // Assert: Should decode to vec with single byte
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![0x42]);
    }

    #[test]
    fn test_rlp_malformed_long_string_length() {
        // Arrange: Long string (0xb8+) with invalid length encoding
        // 0xb8 means the next byte specifies the length of the length field
        // But if that's malformed, it should error
        let malformed = [0xb8, 0x01, 0xff]; // Says length-of-length is 1, then 0xff bytes (but not present)

        // Act
        let result = decode_bytes(&malformed);

        // Assert: Should fail with InvalidRlp
        assert!(result.is_err());
        assert!(matches!(result, Err(ParseError::InvalidRlp { .. })));
    }

    #[test]
    fn test_rlp_malformed_long_list_length() {
        // Arrange: Long list (0xf8+) with invalid length encoding
        let malformed = [0xf8, 0x01, 0xff]; // Says length-of-length is 1, then 0xff bytes (but not present)

        // Act
        let result = decode_list(&malformed);

        // Assert: Should fail with InvalidRlp
        assert!(result.is_err());
        assert!(matches!(result, Err(ParseError::InvalidRlp { .. })));
    }
}
