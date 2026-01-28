//! ERC-20 calldata parsing module.
//!
//! This module provides functionality to detect and parse ERC-20 token function calls
//! from transaction calldata. It supports the three primary ERC-20 functions:
//!
//! - `transfer(address,uint256)` - Transfer tokens to a recipient
//! - `approve(address,uint256)` - Approve a spender to transfer tokens
//! - `transferFrom(address,address,uint256)` - Transfer tokens from one address to another
//!
//! # Function Selectors
//!
//! ERC-20 function selectors are the first 4 bytes of the keccak256 hash of the function signature:
//!
//! | Function | Selector |
//! |----------|----------|
//! | `transfer(address,uint256)` | `0xa9059cbb` |
//! | `approve(address,uint256)` | `0x095ea7b3` |
//! | `transferFrom(address,address,uint256)` | `0x23b872dd` |
//!
//! # ABI Encoding
//!
//! ERC-20 calldata follows Solidity ABI encoding:
//! - First 4 bytes: function selector
//! - Each parameter: 32 bytes (left-padded for addresses, big-endian for uint256)
//! - Addresses occupy bytes 12-32 of their 32-byte word
//!
//! # Example
//!
//! ```rust
//! use txgate_chain::erc20::{parse_erc20_call, Erc20Call};
//! use alloy_primitives::hex;
//!
//! // ERC-20 transfer calldata: transfer(0x1234...5678, 1000000)
//! let calldata = hex::decode(
//!     "a9059cbb\
//!      0000000000000000000000001234567890123456789012345678901234567890\
//!      00000000000000000000000000000000000000000000000000000000000f4240"
//! ).unwrap();
//!
//! if let Some(Erc20Call::Transfer { to, amount }) = parse_erc20_call(&calldata) {
//!     // Handle transfer
//! }
//! ```

use alloy_primitives::U256;

/// ERC-20 function selector for `transfer(address,uint256)`.
///
/// Computed as: `keccak256("transfer(address,uint256)")[:4]`
pub const TRANSFER_SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];

/// ERC-20 function selector for `approve(address,uint256)`.
///
/// Computed as: `keccak256("approve(address,uint256)")[:4]`
pub const APPROVE_SELECTOR: [u8; 4] = [0x09, 0x5e, 0xa7, 0xb3];

/// ERC-20 function selector for `transferFrom(address,address,uint256)`.
///
/// Computed as: `keccak256("transferFrom(address,address,uint256)")[:4]`
pub const TRANSFER_FROM_SELECTOR: [u8; 4] = [0x23, 0xb8, 0x72, 0xdd];

/// Minimum calldata length for a transfer or approve call (4 + 32 + 32 = 68 bytes).
const MIN_TWO_PARAM_LENGTH: usize = 68;

/// Minimum calldata length for a transferFrom call (4 + 32 + 32 + 32 = 100 bytes).
const MIN_THREE_PARAM_LENGTH: usize = 100;

/// Parsed ERC-20 function call.
///
/// Represents one of the three primary ERC-20 functions with their decoded parameters.
///
/// # Examples
///
/// ```rust
/// use txgate_chain::erc20::Erc20Call;
/// use alloy_primitives::U256;
///
/// let transfer = Erc20Call::Transfer {
///     to: [0x12; 20],
///     amount: U256::from(1_000_000u64),
/// };
///
/// let approve = Erc20Call::Approve {
///     spender: [0x34; 20],
///     amount: U256::MAX, // Unlimited approval
/// };
///
/// let transfer_from = Erc20Call::TransferFrom {
///     from: [0x12; 20],
///     to: [0x34; 20],
///     amount: U256::from(500_000u64),
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Erc20Call {
    /// ERC-20 `transfer(address to, uint256 amount)` call.
    ///
    /// Transfers `amount` tokens from the caller to `to`.
    Transfer {
        /// Recipient address (20 bytes).
        to: [u8; 20],
        /// Amount of tokens to transfer (in smallest unit).
        amount: U256,
    },

    /// ERC-20 `approve(address spender, uint256 amount)` call.
    ///
    /// Approves `spender` to transfer up to `amount` tokens on behalf of the caller.
    Approve {
        /// Spender address authorized to transfer tokens (20 bytes).
        spender: [u8; 20],
        /// Maximum amount the spender can transfer.
        amount: U256,
    },

    /// ERC-20 `transferFrom(address from, address to, uint256 amount)` call.
    ///
    /// Transfers `amount` tokens from `from` to `to`, using the caller's allowance.
    TransferFrom {
        /// Source address to transfer from (20 bytes).
        from: [u8; 20],
        /// Destination address to transfer to (20 bytes).
        to: [u8; 20],
        /// Amount of tokens to transfer (in smallest unit).
        amount: U256,
    },
}

impl Erc20Call {
    /// Returns the actual recipient address for this call.
    ///
    /// For `Transfer` and `TransferFrom`, returns the `to` address.
    /// For `Approve`, returns the `spender` address.
    #[must_use]
    pub const fn recipient(&self) -> &[u8; 20] {
        match self {
            Self::Transfer { to, .. } | Self::TransferFrom { to, .. } => to,
            Self::Approve { spender, .. } => spender,
        }
    }

    /// Returns the amount involved in this call.
    #[must_use]
    pub const fn amount(&self) -> &U256 {
        match self {
            Self::Transfer { amount, .. }
            | Self::Approve { amount, .. }
            | Self::TransferFrom { amount, .. } => amount,
        }
    }

    /// Returns `true` if this is a transfer operation (`Transfer` or `TransferFrom`).
    #[must_use]
    pub const fn is_transfer(&self) -> bool {
        matches!(self, Self::Transfer { .. } | Self::TransferFrom { .. })
    }

    /// Returns `true` if this is an approval operation.
    #[must_use]
    pub const fn is_approval(&self) -> bool {
        matches!(self, Self::Approve { .. })
    }
}

/// Parse ERC-20 function call from transaction calldata.
///
/// Analyzes the calldata to detect and decode ERC-20 function calls.
///
/// # Arguments
///
/// * `data` - Raw transaction calldata bytes
///
/// # Returns
///
/// * `Some(Erc20Call)` - If calldata matches an ERC-20 function signature and has valid length
/// * `None` - If calldata doesn't match ERC-20 signatures or is too short
///
/// # Safety
///
/// This function uses safe indexing (`.get()`) throughout to prevent panics.
/// It validates calldata length before attempting to parse parameters.
///
/// # Example
///
/// ```rust
/// use txgate_chain::erc20::{parse_erc20_call, Erc20Call};
///
/// // Empty calldata returns None
/// assert!(parse_erc20_call(&[]).is_none());
///
/// // Too short calldata returns None
/// assert!(parse_erc20_call(&[0xa9, 0x05, 0x9c, 0xbb]).is_none());
///
/// // Non-ERC20 calldata returns None
/// let other_calldata = [0x12, 0x34, 0x56, 0x78];
/// assert!(parse_erc20_call(&other_calldata).is_none());
/// ```
#[must_use]
pub fn parse_erc20_call(data: &[u8]) -> Option<Erc20Call> {
    // Need at least 4 bytes for the function selector
    let selector = data.get(0..4)?;

    // Convert selector slice to array for comparison
    let selector_arr: [u8; 4] = selector.try_into().ok()?;

    match selector_arr {
        TRANSFER_SELECTOR => parse_transfer(data),
        APPROVE_SELECTOR => parse_approve(data),
        TRANSFER_FROM_SELECTOR => parse_transfer_from(data),
        _ => None,
    }
}

/// Parse `transfer(address,uint256)` calldata.
fn parse_transfer(data: &[u8]) -> Option<Erc20Call> {
    // Validate minimum length: 4 (selector) + 32 (address) + 32 (amount) = 68 bytes
    if data.len() < MIN_TWO_PARAM_LENGTH {
        return None;
    }

    // Extract address from bytes 4-36 (32-byte word, address in last 20 bytes)
    let to = extract_address(data, 4)?;

    // Extract amount from bytes 36-68 (32-byte word, big-endian uint256)
    let amount = extract_u256(data, 36)?;

    Some(Erc20Call::Transfer { to, amount })
}

/// Parse `approve(address,uint256)` calldata.
fn parse_approve(data: &[u8]) -> Option<Erc20Call> {
    // Validate minimum length: 4 (selector) + 32 (address) + 32 (amount) = 68 bytes
    if data.len() < MIN_TWO_PARAM_LENGTH {
        return None;
    }

    // Extract spender address from bytes 4-36
    let spender = extract_address(data, 4)?;

    // Extract amount from bytes 36-68
    let amount = extract_u256(data, 36)?;

    Some(Erc20Call::Approve { spender, amount })
}

/// Parse `transferFrom(address,address,uint256)` calldata.
fn parse_transfer_from(data: &[u8]) -> Option<Erc20Call> {
    // Validate minimum length: 4 (selector) + 32 + 32 + 32 = 100 bytes
    if data.len() < MIN_THREE_PARAM_LENGTH {
        return None;
    }

    // Extract from address from bytes 4-36
    let from = extract_address(data, 4)?;

    // Extract to address from bytes 36-68
    let to = extract_address(data, 36)?;

    // Extract amount from bytes 68-100
    let amount = extract_u256(data, 68)?;

    Some(Erc20Call::TransferFrom { from, to, amount })
}

/// Extract a 20-byte address from a 32-byte ABI-encoded word.
///
/// In Solidity ABI encoding, addresses are left-padded with zeros to fill 32 bytes.
/// The actual address occupies the last 20 bytes (offset 12-32 within the word).
fn extract_address(data: &[u8], offset: usize) -> Option<[u8; 20]> {
    // Address is in bytes 12-32 of the 32-byte word (last 20 bytes)
    let addr_start = offset + 12;
    let addr_end = offset + 32;

    let addr_slice = data.get(addr_start..addr_end)?;
    let addr: [u8; 20] = addr_slice.try_into().ok()?;

    Some(addr)
}

/// Extract a U256 from a 32-byte ABI-encoded word.
///
/// In Solidity ABI encoding, uint256 values are stored as big-endian 32-byte words.
fn extract_u256(data: &[u8], offset: usize) -> Option<U256> {
    let end = offset + 32;
    let word_slice = data.get(offset..end)?;
    let word: [u8; 32] = word_slice.try_into().ok()?;

    Some(U256::from_be_bytes(word))
}

/// Check if the given calldata starts with an ERC-20 function selector.
///
/// This is a quick check without parsing the full calldata.
///
/// # Example
///
/// ```rust
/// use txgate_chain::erc20::is_erc20_selector;
///
/// // Transfer selector
/// assert!(is_erc20_selector(&[0xa9, 0x05, 0x9c, 0xbb]));
///
/// // Approve selector
/// assert!(is_erc20_selector(&[0x09, 0x5e, 0xa7, 0xb3]));
///
/// // TransferFrom selector
/// assert!(is_erc20_selector(&[0x23, 0xb8, 0x72, 0xdd]));
///
/// // Unknown selector
/// assert!(!is_erc20_selector(&[0x12, 0x34, 0x56, 0x78]));
///
/// // Too short
/// assert!(!is_erc20_selector(&[0xa9, 0x05]));
/// ```
#[must_use]
pub fn is_erc20_selector(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }

    let Some(selector) = data.get(0..4) else {
        return false;
    };

    let Ok(selector_arr): Result<[u8; 4], _> = selector.try_into() else {
        return false;
    };

    matches!(
        selector_arr,
        TRANSFER_SELECTOR | APPROVE_SELECTOR | TRANSFER_FROM_SELECTOR
    )
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
        clippy::unreadable_literal
    )]

    use super::*;
    use alloy_primitives::hex;

    // ========================================================================
    // Function Selector Tests
    // ========================================================================

    #[test]
    fn test_transfer_selector_is_correct() {
        // keccak256("transfer(address,uint256)") = 0xa9059cbb...
        assert_eq!(TRANSFER_SELECTOR, [0xa9, 0x05, 0x9c, 0xbb]);
    }

    #[test]
    fn test_approve_selector_is_correct() {
        // keccak256("approve(address,uint256)") = 0x095ea7b3...
        assert_eq!(APPROVE_SELECTOR, [0x09, 0x5e, 0xa7, 0xb3]);
    }

    #[test]
    fn test_transfer_from_selector_is_correct() {
        // keccak256("transferFrom(address,address,uint256)") = 0x23b872dd...
        assert_eq!(TRANSFER_FROM_SELECTOR, [0x23, 0xb8, 0x72, 0xdd]);
    }

    // ========================================================================
    // is_erc20_selector Tests
    // ========================================================================

    #[test]
    fn test_is_erc20_selector_transfer() {
        assert!(is_erc20_selector(&TRANSFER_SELECTOR));
    }

    #[test]
    fn test_is_erc20_selector_approve() {
        assert!(is_erc20_selector(&APPROVE_SELECTOR));
    }

    #[test]
    fn test_is_erc20_selector_transfer_from() {
        assert!(is_erc20_selector(&TRANSFER_FROM_SELECTOR));
    }

    #[test]
    fn test_is_erc20_selector_unknown() {
        assert!(!is_erc20_selector(&[0x12, 0x34, 0x56, 0x78]));
    }

    #[test]
    fn test_is_erc20_selector_too_short() {
        assert!(!is_erc20_selector(&[]));
        assert!(!is_erc20_selector(&[0xa9]));
        assert!(!is_erc20_selector(&[0xa9, 0x05]));
        assert!(!is_erc20_selector(&[0xa9, 0x05, 0x9c]));
    }

    #[test]
    fn test_is_erc20_selector_with_extra_data() {
        // Should still work with extra data after selector
        let mut data = TRANSFER_SELECTOR.to_vec();
        data.extend_from_slice(&[0x00; 64]);
        assert!(is_erc20_selector(&data));
    }

    // ========================================================================
    // parse_erc20_call Empty/Short Input Tests
    // ========================================================================

    #[test]
    fn test_parse_empty_returns_none() {
        assert!(parse_erc20_call(&[]).is_none());
    }

    #[test]
    fn test_parse_too_short_for_selector_returns_none() {
        assert!(parse_erc20_call(&[0xa9]).is_none());
        assert!(parse_erc20_call(&[0xa9, 0x05]).is_none());
        assert!(parse_erc20_call(&[0xa9, 0x05, 0x9c]).is_none());
    }

    #[test]
    fn test_parse_selector_only_returns_none() {
        // Just the selector, no parameters
        assert!(parse_erc20_call(&TRANSFER_SELECTOR).is_none());
        assert!(parse_erc20_call(&APPROVE_SELECTOR).is_none());
        assert!(parse_erc20_call(&TRANSFER_FROM_SELECTOR).is_none());
    }

    #[test]
    fn test_parse_unknown_selector_returns_none() {
        let data = hex::decode(
            "12345678\
             0000000000000000000000001234567890123456789012345678901234567890\
             0000000000000000000000000000000000000000000000000000000000000001",
        )
        .expect("valid hex");

        assert!(parse_erc20_call(&data).is_none());
    }

    // ========================================================================
    // Transfer Parsing Tests
    // ========================================================================

    #[test]
    fn test_parse_transfer_valid() {
        // transfer(0x1234567890123456789012345678901234567890, 1000000)
        let data = hex::decode(
            "a9059cbb\
             0000000000000000000000001234567890123456789012345678901234567890\
             00000000000000000000000000000000000000000000000000000000000f4240",
        )
        .expect("valid hex");

        let result = parse_erc20_call(&data);
        assert!(result.is_some());

        let call = result.expect("should parse successfully");
        match call {
            Erc20Call::Transfer { to, amount } => {
                let expected_to =
                    hex::decode("1234567890123456789012345678901234567890").expect("valid hex");
                let expected_to_arr: [u8; 20] = expected_to.try_into().expect("20 bytes");
                assert_eq!(to, expected_to_arr);
                assert_eq!(amount, U256::from(1_000_000u64));
            }
            _ => panic!("expected Transfer variant"),
        }
    }

    #[test]
    fn test_parse_transfer_zero_amount() {
        let data = hex::decode(
            "a9059cbb\
             000000000000000000000000abcdefabcdefabcdefabcdefabcdefabcdefabcd\
             0000000000000000000000000000000000000000000000000000000000000000",
        )
        .expect("valid hex");

        let result = parse_erc20_call(&data);
        assert!(result.is_some());

        if let Some(Erc20Call::Transfer { amount, .. }) = result {
            assert_eq!(amount, U256::ZERO);
        } else {
            panic!("expected Transfer variant");
        }
    }

    #[test]
    fn test_parse_transfer_max_amount() {
        let data = hex::decode(
            "a9059cbb\
             000000000000000000000000abcdefabcdefabcdefabcdefabcdefabcdefabcd\
             ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        )
        .expect("valid hex");

        let result = parse_erc20_call(&data);
        assert!(result.is_some());

        if let Some(Erc20Call::Transfer { amount, .. }) = result {
            assert_eq!(amount, U256::MAX);
        } else {
            panic!("expected Transfer variant");
        }
    }

    #[test]
    fn test_parse_transfer_too_short() {
        // Missing 1 byte from amount
        let data = hex::decode(
            "a9059cbb\
             0000000000000000000000001234567890123456789012345678901234567890\
             000000000000000000000000000000000000000000000000000000000000f4",
        )
        .expect("valid hex");

        assert!(parse_erc20_call(&data).is_none());
    }

    #[test]
    fn test_parse_transfer_with_extra_data() {
        // Extra data after valid transfer calldata should still parse
        let mut data = hex::decode(
            "a9059cbb\
             0000000000000000000000001234567890123456789012345678901234567890\
             00000000000000000000000000000000000000000000000000000000000f4240",
        )
        .expect("valid hex");
        data.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);

        let result = parse_erc20_call(&data);
        assert!(result.is_some());
        assert!(matches!(result, Some(Erc20Call::Transfer { .. })));
    }

    // ========================================================================
    // Approve Parsing Tests
    // ========================================================================

    #[test]
    fn test_parse_approve_valid() {
        // approve(0xabcdefabcdefabcdefabcdefabcdefabcdefabcd, 5000000)
        let data = hex::decode(
            "095ea7b3\
             000000000000000000000000abcdefabcdefabcdefabcdefabcdefabcdefabcd\
             00000000000000000000000000000000000000000000000000000000004c4b40",
        )
        .expect("valid hex");

        let result = parse_erc20_call(&data);
        assert!(result.is_some());

        let call = result.expect("should parse successfully");
        match call {
            Erc20Call::Approve { spender, amount } => {
                let expected_spender =
                    hex::decode("abcdefabcdefabcdefabcdefabcdefabcdefabcd").expect("valid hex");
                let expected_spender_arr: [u8; 20] = expected_spender.try_into().expect("20 bytes");
                assert_eq!(spender, expected_spender_arr);
                assert_eq!(amount, U256::from(5_000_000u64));
            }
            _ => panic!("expected Approve variant"),
        }
    }

    #[test]
    fn test_parse_approve_unlimited() {
        // Unlimited approval (max uint256)
        let data = hex::decode(
            "095ea7b3\
             000000000000000000000000abcdefabcdefabcdefabcdefabcdefabcdefabcd\
             ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        )
        .expect("valid hex");

        let result = parse_erc20_call(&data);
        assert!(result.is_some());

        if let Some(Erc20Call::Approve { amount, .. }) = result {
            assert_eq!(amount, U256::MAX);
        } else {
            panic!("expected Approve variant");
        }
    }

    #[test]
    fn test_parse_approve_too_short() {
        let data = hex::decode(
            "095ea7b3\
             000000000000000000000000abcdefabcdefabcdefabcdefabcdefabcdefab",
        )
        .expect("valid hex");

        assert!(parse_erc20_call(&data).is_none());
    }

    // ========================================================================
    // TransferFrom Parsing Tests
    // ========================================================================

    #[test]
    fn test_parse_transfer_from_valid() {
        // transferFrom(0x1111..., 0x2222..., 1000000000000000000)
        let data = hex::decode(
            "23b872dd\
             0000000000000000000000001111111111111111111111111111111111111111\
             0000000000000000000000002222222222222222222222222222222222222222\
             0000000000000000000000000000000000000000000000000de0b6b3a7640000",
        )
        .expect("valid hex");

        let result = parse_erc20_call(&data);
        assert!(result.is_some());

        let call = result.expect("should parse successfully");
        match call {
            Erc20Call::TransferFrom { from, to, amount } => {
                let expected_from =
                    hex::decode("1111111111111111111111111111111111111111").expect("valid hex");
                let expected_from_arr: [u8; 20] = expected_from.try_into().expect("20 bytes");

                let expected_to =
                    hex::decode("2222222222222222222222222222222222222222").expect("valid hex");
                let expected_to_arr: [u8; 20] = expected_to.try_into().expect("20 bytes");

                assert_eq!(from, expected_from_arr);
                assert_eq!(to, expected_to_arr);
                assert_eq!(amount, U256::from(1_000_000_000_000_000_000u64)); // 1 ETH equivalent
            }
            _ => panic!("expected TransferFrom variant"),
        }
    }

    #[test]
    fn test_parse_transfer_from_too_short() {
        // Missing the amount parameter entirely
        let data = hex::decode(
            "23b872dd\
             0000000000000000000000001111111111111111111111111111111111111111\
             0000000000000000000000002222222222222222222222222222222222222222",
        )
        .expect("valid hex");

        assert!(parse_erc20_call(&data).is_none());
    }

    #[test]
    fn test_parse_transfer_from_partial_amount() {
        // Amount is only 31 bytes instead of 32
        let data = hex::decode(
            "23b872dd\
             0000000000000000000000001111111111111111111111111111111111111111\
             0000000000000000000000002222222222222222222222222222222222222222\
             00000000000000000000000000000000000000000000000000000000000001",
        )
        .expect("valid hex");

        assert!(parse_erc20_call(&data).is_none());
    }

    // ========================================================================
    // Erc20Call Helper Method Tests
    // ========================================================================

    #[test]
    fn test_erc20call_recipient_transfer() {
        let to = [0x12; 20];
        let call = Erc20Call::Transfer {
            to,
            amount: U256::from(100u64),
        };
        assert_eq!(call.recipient(), &to);
    }

    #[test]
    fn test_erc20call_recipient_approve() {
        let spender = [0x34; 20];
        let call = Erc20Call::Approve {
            spender,
            amount: U256::from(100u64),
        };
        assert_eq!(call.recipient(), &spender);
    }

    #[test]
    fn test_erc20call_recipient_transfer_from() {
        let from = [0x12; 20];
        let to = [0x34; 20];
        let call = Erc20Call::TransferFrom {
            from,
            to,
            amount: U256::from(100u64),
        };
        assert_eq!(call.recipient(), &to);
    }

    #[test]
    fn test_erc20call_amount() {
        let amount = U256::from(12345u64);

        let transfer = Erc20Call::Transfer {
            to: [0; 20],
            amount,
        };
        assert_eq!(*transfer.amount(), amount);

        let approve = Erc20Call::Approve {
            spender: [0; 20],
            amount,
        };
        assert_eq!(*approve.amount(), amount);

        let transfer_from = Erc20Call::TransferFrom {
            from: [0; 20],
            to: [0; 20],
            amount,
        };
        assert_eq!(*transfer_from.amount(), amount);
    }

    #[test]
    fn test_erc20call_is_transfer() {
        let transfer = Erc20Call::Transfer {
            to: [0; 20],
            amount: U256::ZERO,
        };
        assert!(transfer.is_transfer());
        assert!(!transfer.is_approval());

        let transfer_from = Erc20Call::TransferFrom {
            from: [0; 20],
            to: [0; 20],
            amount: U256::ZERO,
        };
        assert!(transfer_from.is_transfer());
        assert!(!transfer_from.is_approval());

        let approve = Erc20Call::Approve {
            spender: [0; 20],
            amount: U256::ZERO,
        };
        assert!(!approve.is_transfer());
        assert!(approve.is_approval());
    }

    // ========================================================================
    // Clone and Debug Tests
    // ========================================================================

    #[test]
    fn test_erc20call_clone() {
        let call = Erc20Call::Transfer {
            to: [0x12; 20],
            amount: U256::from(100u64),
        };
        let cloned = call.clone();
        assert_eq!(call, cloned);
    }

    #[test]
    fn test_erc20call_debug() {
        let call = Erc20Call::Transfer {
            to: [0x12; 20],
            amount: U256::from(100u64),
        };
        let debug_str = format!("{call:?}");
        assert!(debug_str.contains("Transfer"));
    }

    // ========================================================================
    // Real-World Calldata Tests
    // ========================================================================

    #[test]
    fn test_parse_usdc_transfer() {
        // Real USDC transfer: transfer(0xRecipient, 1000000) = 1 USDC (6 decimals)
        let data = hex::decode(
            "a9059cbb\
             000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7\
             00000000000000000000000000000000000000000000000000000000000f4240",
        )
        .expect("valid hex");

        let result = parse_erc20_call(&data);
        assert!(result.is_some());

        if let Some(Erc20Call::Transfer { amount, .. }) = result {
            // 1 USDC = 1,000,000 (6 decimals)
            assert_eq!(amount, U256::from(1_000_000u64));
        } else {
            panic!("expected Transfer variant");
        }
    }

    #[test]
    fn test_parse_dai_approve() {
        // DAI approve with unlimited amount
        let data = hex::decode(
            "095ea7b3\
             0000000000000000000000007a250d5630b4cf539739df2c5dacb4c659f2488d\
             ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        )
        .expect("valid hex");

        let result = parse_erc20_call(&data);
        assert!(result.is_some());

        if let Some(Erc20Call::Approve { spender, amount }) = result {
            // Uniswap V2 Router address
            let expected_spender =
                hex::decode("7a250d5630b4cf539739df2c5dacb4c659f2488d").expect("valid hex");
            let expected_spender_arr: [u8; 20] = expected_spender.try_into().expect("20 bytes");
            assert_eq!(spender, expected_spender_arr);
            assert_eq!(amount, U256::MAX);
        } else {
            panic!("expected Approve variant");
        }
    }

    // ========================================================================
    // Edge Cases
    // ========================================================================

    #[test]
    fn test_address_with_leading_zeros() {
        // Address that starts with zeros
        let data = hex::decode(
            "a9059cbb\
             0000000000000000000000000000000000000000000000000000000000000001\
             0000000000000000000000000000000000000000000000000000000000000064",
        )
        .expect("valid hex");

        let result = parse_erc20_call(&data);
        assert!(result.is_some());

        if let Some(Erc20Call::Transfer { to, amount }) = result {
            // Address should be all zeros except last byte
            let expected: [u8; 20] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
            assert_eq!(to, expected);
            assert_eq!(amount, U256::from(100u64));
        } else {
            panic!("expected Transfer variant");
        }
    }

    #[test]
    fn test_exactly_minimum_length() {
        // Exactly 68 bytes for transfer
        let data = hex::decode(
            "a9059cbb\
             0000000000000000000000001234567890123456789012345678901234567890\
             0000000000000000000000000000000000000000000000000000000000000001",
        )
        .expect("valid hex");
        assert_eq!(data.len(), 68);

        let result = parse_erc20_call(&data);
        assert!(result.is_some());
    }

    #[test]
    fn test_one_byte_short() {
        // 67 bytes (one short of minimum)
        let data = hex::decode(
            "a9059cbb\
             0000000000000000000000001234567890123456789012345678901234567890\
             00000000000000000000000000000000000000000000000000000000000001",
        )
        .expect("valid hex");
        assert_eq!(data.len(), 67);

        assert!(parse_erc20_call(&data).is_none());
    }

    // ========================================================================
    // Phase 2: Truncated Calldata Edge Cases
    // ========================================================================

    #[test]
    fn should_return_none_when_transfer_calldata_has_partial_address() {
        // Arrange: Transfer selector with calldata truncated in address field (36 bytes total)
        let data = hex::decode(
            "a9059cbb\
             0000000000000000000000001234567890123456789012345678901234567890",
        )
        .expect("valid hex");
        assert_eq!(data.len(), 36); // 4 + 32, but missing amount

        // Act
        let result = parse_erc20_call(&data);

        // Assert
        assert!(
            result.is_none(),
            "Should return None for incomplete transfer calldata"
        );
    }

    #[test]
    fn should_return_none_when_transfer_calldata_missing_partial_amount() {
        // Arrange: Transfer selector with complete address but partial amount (52 bytes)
        let data = hex::decode(
            "a9059cbb\
             0000000000000000000000001234567890123456789012345678901234567890\
             00000000000000000000000000000000",
        )
        .expect("valid hex");
        assert_eq!(data.len(), 52); // 4 + 32 + 16 (partial amount)

        // Act
        let result = parse_erc20_call(&data);

        // Assert
        assert!(
            result.is_none(),
            "Should return None when amount field is truncated"
        );
    }

    #[test]
    fn should_return_none_when_approve_calldata_truncated_before_amount() {
        // Arrange: Approve selector with complete spender but missing amount (36 bytes)
        let data = hex::decode(
            "095ea7b3\
             000000000000000000000000abcdefabcdefabcdefabcdefabcdefabcdefabcd",
        )
        .expect("valid hex");
        assert_eq!(data.len(), 36); // 4 + 32, missing amount

        // Act
        let result = parse_erc20_call(&data);

        // Assert
        assert!(
            result.is_none(),
            "Should return None for approve missing amount"
        );
    }

    #[test]
    fn should_return_none_when_approve_calldata_has_partial_amount() {
        // Arrange: Approve selector with complete spender but partial amount (60 bytes)
        let data = hex::decode(
            "095ea7b3\
             000000000000000000000000abcdefabcdefabcdefabcdefabcdefabcdefabcd\
             000000000000000000000000000000000000000000000000",
        )
        .expect("valid hex");
        assert_eq!(data.len(), 60); // 4 + 32 + 24 (partial amount)

        // Act
        let result = parse_erc20_call(&data);

        // Assert
        assert!(
            result.is_none(),
            "Should return None when approve amount is truncated"
        );
    }

    #[test]
    fn should_return_none_when_transfer_from_calldata_missing_to_address() {
        // Arrange: TransferFrom selector with only 'from' address (36 bytes)
        let data = hex::decode(
            "23b872dd\
             0000000000000000000000001111111111111111111111111111111111111111",
        )
        .expect("valid hex");
        assert_eq!(data.len(), 36); // 4 + 32, missing 'to' and amount

        // Act
        let result = parse_erc20_call(&data);

        // Assert
        assert!(
            result.is_none(),
            "Should return None when transferFrom missing 'to' and amount"
        );
    }

    #[test]
    fn should_return_none_when_transfer_from_calldata_missing_amount() {
        // Arrange: TransferFrom selector with 'from' and 'to' but no amount (68 bytes)
        let data = hex::decode(
            "23b872dd\
             0000000000000000000000001111111111111111111111111111111111111111\
             0000000000000000000000002222222222222222222222222222222222222222",
        )
        .expect("valid hex");
        assert_eq!(data.len(), 68); // 4 + 32 + 32, missing amount

        // Act
        let result = parse_erc20_call(&data);

        // Assert
        assert!(
            result.is_none(),
            "Should return None when transferFrom missing amount"
        );
    }

    #[test]
    fn should_return_none_when_transfer_from_calldata_has_partial_to_address() {
        // Arrange: TransferFrom with 'from' and partial 'to' address (52 bytes)
        let data = hex::decode(
            "23b872dd\
             0000000000000000000000001111111111111111111111111111111111111111\
             00000000000000000000000000000000",
        )
        .expect("valid hex");
        assert_eq!(data.len(), 52); // 4 + 32 + 16 (partial 'to')

        // Act
        let result = parse_erc20_call(&data);

        // Assert
        assert!(
            result.is_none(),
            "Should return None when 'to' address is truncated"
        );
    }

    #[test]
    fn should_return_none_when_transfer_from_calldata_has_partial_amount() {
        // Arrange: TransferFrom with complete addresses but partial amount (84 bytes)
        let data = hex::decode(
            "23b872dd\
             0000000000000000000000001111111111111111111111111111111111111111\
             0000000000000000000000002222222222222222222222222222222222222222\
             00000000000000000000000000000000",
        )
        .expect("valid hex");
        assert_eq!(data.len(), 84); // 4 + 32 + 32 + 16 (partial amount)

        // Act
        let result = parse_erc20_call(&data);

        // Assert
        assert!(
            result.is_none(),
            "Should return None when amount is truncated"
        );
    }

    #[test]
    fn should_handle_valid_selector_with_parameter_extraction_failure() {
        // Arrange: Valid transfer selector but calldata too short for extraction
        let data = vec![0xa9, 0x05, 0x9c, 0xbb, 0x00, 0x00, 0x00, 0x00]; // 8 bytes

        // Act
        let result = parse_erc20_call(&data);

        // Assert
        assert!(
            result.is_none(),
            "Should fail gracefully when extraction impossible"
        );
    }

    #[test]
    fn should_identify_all_transfer_variants_correctly() {
        // Arrange & Act & Assert: Transfer variant
        let transfer = Erc20Call::Transfer {
            to: [0xAA; 20],
            amount: U256::from(1000u64),
        };
        assert!(transfer.is_transfer());
        assert!(!transfer.is_approval());

        // Arrange & Act & Assert: TransferFrom variant
        let transfer_from = Erc20Call::TransferFrom {
            from: [0xBB; 20],
            to: [0xCC; 20],
            amount: U256::from(2000u64),
        };
        assert!(transfer_from.is_transfer());
        assert!(!transfer_from.is_approval());

        // Arrange & Act & Assert: Approve variant (not a transfer)
        let approve = Erc20Call::Approve {
            spender: [0xDD; 20],
            amount: U256::from(3000u64),
        };
        assert!(!approve.is_transfer());
    }

    #[test]
    fn should_identify_all_approval_variants_correctly() {
        // Arrange & Act & Assert: Approve variant
        let approve = Erc20Call::Approve {
            spender: [0xEE; 20],
            amount: U256::MAX,
        };
        assert!(approve.is_approval());
        assert!(!approve.is_transfer());

        // Arrange & Act & Assert: Transfer variant (not an approval)
        let transfer = Erc20Call::Transfer {
            to: [0xFF; 20],
            amount: U256::from(500u64),
        };
        assert!(!transfer.is_approval());

        // Arrange & Act & Assert: TransferFrom variant (not an approval)
        let transfer_from = Erc20Call::TransferFrom {
            from: [0x11; 20],
            to: [0x22; 20],
            amount: U256::from(600u64),
        };
        assert!(!transfer_from.is_approval());
    }

    // ========================================================================
    // Phase 2: Debug Trait Coverage for Erc20Call
    // ========================================================================

    #[test]
    fn should_format_transfer_debug_output_correctly() {
        // Arrange: Transfer variant
        let transfer = Erc20Call::Transfer {
            to: [
                0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB,
                0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78,
            ],
            amount: U256::from(1_000_000u64),
        };

        // Act: Format with Debug
        let debug_output = format!("{transfer:?}");

        // Assert: Contains variant name and shows structure
        assert!(debug_output.contains("Transfer"));
        assert!(debug_output.contains("to"));
        assert!(debug_output.contains("amount"));
    }

    #[test]
    fn should_format_approve_debug_output_correctly() {
        // Arrange: Approve variant with max amount
        let approve = Erc20Call::Approve {
            spender: [0xFF; 20],
            amount: U256::MAX,
        };

        // Act: Format with Debug
        let debug_output = format!("{approve:?}");

        // Assert: Contains variant name and field names
        assert!(debug_output.contains("Approve"));
        assert!(debug_output.contains("spender"));
        assert!(debug_output.contains("amount"));
    }

    #[test]
    fn should_format_transfer_from_debug_output_correctly() {
        // Arrange: TransferFrom variant
        let transfer_from = Erc20Call::TransferFrom {
            from: [0xAA; 20],
            to: [0xBB; 20],
            amount: U256::from(500_000_000u64),
        };

        // Act: Format with Debug
        let debug_output = format!("{transfer_from:?}");

        // Assert: Contains variant name and all field names
        assert!(debug_output.contains("TransferFrom"));
        assert!(debug_output.contains("from"));
        assert!(debug_output.contains("to"));
        assert!(debug_output.contains("amount"));
    }

    #[test]
    fn should_format_erc20call_debug_with_zero_amount() {
        // Arrange: Transfer with zero amount
        let transfer = Erc20Call::Transfer {
            to: [0x00; 20],
            amount: U256::ZERO,
        };

        // Act: Format with Debug
        let debug_output = format!("{transfer:?}");

        // Assert: Debug output generated
        assert!(debug_output.contains("Transfer"));
        assert!(!debug_output.is_empty());
    }

    #[test]
    fn should_format_erc20call_debug_with_max_amount() {
        // Arrange: Approve with U256::MAX
        let approve = Erc20Call::Approve {
            spender: [0x00; 20],
            amount: U256::MAX,
        };

        // Act: Format with Debug
        let debug_output = format!("{approve:?}");

        // Assert: Debug output generated
        assert!(debug_output.contains("Approve"));
        assert!(!debug_output.is_empty());
    }
}
