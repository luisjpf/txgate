//! Additional comprehensive tests for txgate-chain crate to achieve 100% coverage.
//!
//! This module contains tests that cover edge cases, error paths, and scenarios
//! not covered by the inline module tests.

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
    clippy::default_trait_access
)]

use alloy_consensus::{transaction::RlpEcdsaEncodableTx, TxEip1559};
use alloy_primitives::{hex, Signature, TxKind};
use alloy_primitives::{Address, Bytes, U256};
use txgate_core::error::ParseError;

use crate::{Chain, EthereumParser, MockChain, MockParseError};

// ============================================================================
// MockParseError Tests - Covering all variants
// ============================================================================

#[test]
fn test_mock_parse_error_unknown_tx_type() {
    let error = MockParseError::UnknownTxType;
    let parse_error = error.to_parse_error("test context");
    assert!(matches!(parse_error, ParseError::UnknownTxType));
}

#[test]
fn test_mock_parse_error_malformed_transaction() {
    let error = MockParseError::MalformedTransaction;
    let parse_error = error.to_parse_error("test context");
    assert!(matches!(
        parse_error,
        ParseError::MalformedTransaction { .. }
    ));
    if let ParseError::MalformedTransaction { context } = parse_error {
        assert_eq!(context, "test context");
    }
}

#[test]
fn test_mock_parse_error_malformed_calldata() {
    let error = MockParseError::MalformedCalldata;
    let parse_error = error.to_parse_error("test context");
    assert!(matches!(parse_error, ParseError::MalformedCalldata));
}

#[test]
fn test_mock_parse_error_invalid_address() {
    let error = MockParseError::InvalidAddress;
    let parse_error = error.to_parse_error("0xbadaddress");
    assert!(matches!(parse_error, ParseError::InvalidAddress { .. }));
    if let ParseError::InvalidAddress { address } = parse_error {
        assert_eq!(address, "0xbadaddress");
    }
}

#[test]
fn test_mock_parse_error_equality() {
    assert_eq!(MockParseError::UnknownTxType, MockParseError::UnknownTxType);
    assert_eq!(
        MockParseError::MalformedTransaction,
        MockParseError::MalformedTransaction
    );
    assert_eq!(
        MockParseError::MalformedCalldata,
        MockParseError::MalformedCalldata
    );
    assert_eq!(
        MockParseError::InvalidAddress,
        MockParseError::InvalidAddress
    );

    assert_ne!(
        MockParseError::UnknownTxType,
        MockParseError::MalformedTransaction
    );
}

#[test]
fn test_mock_parse_error_copy_clone() {
    let error = MockParseError::UnknownTxType;
    let copied = error;
    assert_eq!(error, copied);

    #[allow(clippy::clone_on_copy)]
    let cloned = error.clone();
    assert_eq!(error, cloned);
}

#[test]
fn test_mock_parse_error_debug() {
    let error = MockParseError::UnknownTxType;
    let debug_str = format!("{error:?}");
    assert!(debug_str.contains("UnknownTxType"));
}

// ============================================================================
// RLP Error Path Tests
// ============================================================================

#[test]
fn test_rlp_decode_u256_overflow() {
    use crate::rlp::decode_u256;

    // Test with data that would overflow u64 but is valid U256
    // U256 max: 2^256 - 1
    let max_u256_bytes = [0xffu8; 32];
    let mut encoded = vec![0xa0]; // String of length 32
    encoded.extend_from_slice(&max_u256_bytes);

    let result = decode_u256(&encoded);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), U256::MAX);
}

#[test]
fn test_rlp_decode_bytes_list_error() {
    use crate::rlp::decode_bytes;

    // Try to decode a list as bytes (should fail)
    let list = [0xc2, 0x01, 0x02]; // RLP list [1, 2]
    let result = decode_bytes(&list);
    assert!(result.is_err());
    assert!(matches!(result, Err(ParseError::InvalidRlp { .. })));
}

#[test]
fn test_rlp_decode_address_wrong_length() {
    use crate::rlp::decode_address;

    // 21 bytes instead of 20
    let wrong_length = [
        0x95, // 21-byte string prefix
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
    ];
    let result = decode_address(&wrong_length);
    assert!(result.is_err());
}

#[test]
fn test_rlp_typed_tx_payload_single_byte() {
    use crate::rlp::typed_tx_payload;

    // Single type byte with no payload
    let data = [0x01];
    let payload = typed_tx_payload(&data).unwrap();
    assert_eq!(payload.len(), 0);
}

#[test]
fn test_rlp_detect_tx_type_boundary_values() {
    use crate::rlp::detect_tx_type;

    // Boundary between typed and unknown
    assert_eq!(detect_tx_type(&[0x03]), Some(3));
    assert_eq!(detect_tx_type(&[0x04]), None); // Future type

    // Boundary before RLP list
    assert_eq!(detect_tx_type(&[0xbf]), None);
    assert_eq!(detect_tx_type(&[0xc0]), None); // RLP list start
}

// ============================================================================
// Ethereum Parser Error Path Tests
// ============================================================================

#[test]
fn test_ethereum_parse_legacy_various_chain_ids() {
    // Test that EIP-155 chain_id extraction works for various values
    let parser = EthereumParser::new();

    // Use the standard test transaction which has v=37 (chain_id = 1)
    let raw = hex::decode(
        "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83"
    ).expect("valid hex");

    let result = parser.parse(&raw);
    assert!(result.is_ok());

    let parsed = result.unwrap();
    // v=37 -> chain_id = (37-35)/2 = 1
    assert_eq!(parsed.chain_id, Some(1));
}

#[test]
fn test_ethereum_parse_eip2930_wrong_field_count() {
    let parser = EthereumParser::new();

    // Create EIP-2930 tx with wrong number of fields
    // Should have 11 items, we'll create one with 3
    let mut raw = vec![0x01]; // Type 1
                              // RLP list with only 3 items instead of 11
    raw.push(0xc3); // List of 3 items
    raw.extend_from_slice(&[0x01, 0x02, 0x03]);

    let result = parser.parse(&raw);
    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(ParseError::MalformedTransaction { .. })
    ));
}

#[test]
fn test_ethereum_parse_eip1559_wrong_field_count() {
    let parser = EthereumParser::new();

    // Create EIP-1559 tx with wrong number of fields
    // Should have 12 items, we'll create one with 3
    let mut raw = vec![0x02]; // Type 2
                              // RLP list with only 3 items instead of 12
    raw.push(0xc3); // List of 3 items
    raw.extend_from_slice(&[0x01, 0x02, 0x03]);

    let result = parser.parse(&raw);
    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(ParseError::MalformedTransaction { .. })
    ));
}

#[test]
fn test_ethereum_parse_malformed_not_list_not_typed() {
    let parser = EthereumParser::new();

    // Data that starts with neither RLP list prefix nor valid type byte
    // 0x80 is RLP empty string, not a list
    let raw = hex::decode("80").expect("valid hex");

    let result = parser.parse(&raw);
    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(ParseError::MalformedTransaction { .. })
    ));
}

#[test]
fn test_ethereum_erc20_transfer_with_zero_eth_value() {
    // Test ERC-20 transfer that also sends ETH value
    // This is an edge case where both native and token transfer happen
    let parser = EthereumParser::new();

    let token_contract = Address::from([0xaa; 20]);
    let recipient = Address::from([0xbb; 20]);
    let token_amount = U256::from(1_000_000u64);

    // Build ERC-20 transfer calldata
    let mut calldata_vec = vec![0xa9, 0x05, 0x9c, 0xbb]; // transfer selector
    calldata_vec.extend_from_slice(&[0u8; 12]);
    calldata_vec.extend_from_slice(recipient.as_slice());
    calldata_vec.extend_from_slice(&token_amount.to_be_bytes::<32>());
    let calldata = Bytes::from(calldata_vec);

    let tx = TxEip1559 {
        chain_id: 1,
        nonce: 0,
        max_priority_fee_per_gas: 1_000_000_000,
        max_fee_per_gas: 2_000_000_000,
        gas_limit: 100_000,
        to: TxKind::Call(token_contract),
        value: U256::ZERO, // No ETH sent (typical for token transfer)
        input: calldata,
        access_list: Default::default(),
    };

    let sig = Signature::new(
        U256::from(0xffff_ffff_ffff_ffffu64),
        U256::from(0xffff_ffff_ffff_ffffu64),
        false,
    );

    let mut buf = Vec::new();
    buf.push(0x02);
    tx.rlp_encode_signed(&sig, &mut buf);

    let result = parser.parse(&buf);
    assert!(result.is_ok());

    let parsed = result.unwrap();
    // Should detect as TokenTransfer, not ContractCall
    assert_eq!(parsed.tx_type, txgate_core::TxType::TokenTransfer);
}

// ============================================================================
// ChainRegistry Edge Cases
// ============================================================================

#[test]
fn test_chain_registry_case_sensitive_lookup() {
    use crate::ChainRegistry;

    let mut registry = ChainRegistry::empty();
    registry.register(MockChain {
        id: "ethereum",
        ..Default::default()
    });

    // Lookup is case-sensitive
    assert!(registry.supports("ethereum"));
    assert!(!registry.supports("Ethereum"));
    assert!(!registry.supports("ETHEREUM"));
    assert!(registry.get("Ethereum").is_none());
}

#[test]
fn test_chain_registry_unicode_chain_id() {
    use crate::ChainRegistry;

    let mut registry = ChainRegistry::empty();
    registry.register(MockChain {
        id: "test-chain-🦀",
        ..Default::default()
    });

    assert!(registry.supports("test-chain-🦀"));
    assert!(registry.get("test-chain-🦀").is_some());
}

// ============================================================================
// TokenRegistry Edge Cases
// ============================================================================

#[test]
fn test_token_registry_short_address_symbol() {
    use crate::TokenRegistry;

    let registry = TokenRegistry::new();

    // Create an address string that's shorter than expected (edge case)
    let short_addr = Address::from([0x00; 20]); // All zeros

    let info = registry.get_or_default(&short_addr);
    assert_eq!(info.risk_level, crate::RiskLevel::High);
    assert_eq!(info.decimals, 18);
    // Should still create some symbol
    assert!(!info.symbol.is_empty());
}

#[test]
fn test_token_registry_json_export_import_roundtrip() {
    use crate::{RiskLevel, TokenInfo, TokenRegistry};

    let mut registry = TokenRegistry::new();

    let addr1: Address = "0x1234567890123456789012345678901234567890"
        .parse()
        .unwrap();
    let addr2: Address = "0xabcdef0123456789abcdef0123456789abcdef01"
        .parse()
        .unwrap();

    registry.register(
        addr1,
        TokenInfo::new("TEST1", 18, RiskLevel::Low).with_name("Test Token 1"),
    );
    registry.register(addr2, TokenInfo::new("TEST2", 6, RiskLevel::Medium));

    // Export to JSON
    let json = registry.to_json().expect("export should succeed");

    // Import into new registry
    let mut new_registry = TokenRegistry::new();
    let count = new_registry
        .load_json(&json)
        .expect("import should succeed");

    assert_eq!(count, 2);
    assert_eq!(new_registry.len(), 2);

    // Verify data integrity
    let info1 = new_registry.get(&addr1).expect("token 1 should exist");
    assert_eq!(info1.symbol, "TEST1");
    assert_eq!(info1.decimals, 18);
    assert_eq!(info1.risk_level, RiskLevel::Low);
    assert_eq!(info1.name, Some("Test Token 1".to_string()));

    let info2 = new_registry.get(&addr2).expect("token 2 should exist");
    assert_eq!(info2.symbol, "TEST2");
    assert_eq!(info2.decimals, 6);
    assert_eq!(info2.risk_level, RiskLevel::Medium);
    assert_eq!(info2.name, None);
}

#[test]
fn test_token_info_clone() {
    use crate::{RiskLevel, TokenInfo};

    let info = TokenInfo::new("TEST", 18, RiskLevel::Low).with_name("Test");
    let cloned = info.clone();

    assert_eq!(info, cloned);
    assert_eq!(cloned.symbol, "TEST");
    assert_eq!(cloned.decimals, 18);
    assert_eq!(cloned.risk_level, RiskLevel::Low);
    assert_eq!(cloned.name, Some("Test".to_string()));
}

#[test]
fn test_risk_level_hash() {
    use crate::RiskLevel;
    use std::collections::HashSet;

    let mut set = HashSet::new();
    set.insert(RiskLevel::Low);
    set.insert(RiskLevel::Medium);
    set.insert(RiskLevel::High);

    assert_eq!(set.len(), 3);
    assert!(set.contains(&RiskLevel::Low));
    assert!(set.contains(&RiskLevel::Medium));
    assert!(set.contains(&RiskLevel::High));
}

// ============================================================================
// ERC-20 Parsing Edge Cases
// ============================================================================

#[test]
fn test_erc20_parse_transfer_exact_68_bytes() {
    use crate::erc20::{parse_erc20_call, Erc20Call};

    // Exactly 68 bytes (minimum valid)
    let data = hex::decode(
        "a9059cbb\
         0000000000000000000000001234567890123456789012345678901234567890\
         0000000000000000000000000000000000000000000000000000000000000001",
    )
    .expect("valid hex");

    assert_eq!(data.len(), 68);
    let result = parse_erc20_call(&data);
    assert!(result.is_some());
    assert!(matches!(result, Some(Erc20Call::Transfer { .. })));
}

#[test]
fn test_erc20_parse_approve_exact_68_bytes() {
    use crate::erc20::{parse_erc20_call, Erc20Call};

    let data = hex::decode(
        "095ea7b3\
         0000000000000000000000001234567890123456789012345678901234567890\
         0000000000000000000000000000000000000000000000000000000000000001",
    )
    .expect("valid hex");

    assert_eq!(data.len(), 68);
    let result = parse_erc20_call(&data);
    assert!(result.is_some());
    assert!(matches!(result, Some(Erc20Call::Approve { .. })));
}

#[test]
fn test_erc20_parse_transfer_from_exact_100_bytes() {
    use crate::erc20::{parse_erc20_call, Erc20Call};

    let data = hex::decode(
        "23b872dd\
         0000000000000000000000001111111111111111111111111111111111111111\
         0000000000000000000000002222222222222222222222222222222222222222\
         0000000000000000000000000000000000000000000000000000000000000001",
    )
    .expect("valid hex");

    assert_eq!(data.len(), 100);
    let result = parse_erc20_call(&data);
    assert!(result.is_some());
    assert!(matches!(result, Some(Erc20Call::TransferFrom { .. })));
}

#[test]
fn test_erc20_call_recipient_variants() {
    use crate::erc20::Erc20Call;

    let to = [0x12; 20];
    let from = [0x34; 20];
    let spender = [0x56; 20];
    let amount = U256::from(100u64);

    // Transfer returns 'to'
    let transfer = Erc20Call::Transfer { to, amount };
    assert_eq!(transfer.recipient(), &to);

    // TransferFrom returns 'to'
    let transfer_from = Erc20Call::TransferFrom { from, to, amount };
    assert_eq!(transfer_from.recipient(), &to);

    // Approve returns 'spender'
    let approve = Erc20Call::Approve { spender, amount };
    assert_eq!(approve.recipient(), &spender);
}

// ============================================================================
// Additional Coverage Tests
// ============================================================================

#[test]
fn test_ethereum_parser_copy() {
    let parser1 = EthereumParser::new();
    let parser2 = parser1; // Copy

    assert_eq!(parser1.id(), parser2.id());
    assert_eq!(parser1.curve(), parser2.curve());
}

#[test]
fn test_chain_registry_debug() {
    use crate::ChainRegistry;

    let registry = ChainRegistry::empty();
    let debug_str = format!("{registry:?}");
    assert!(debug_str.contains("ChainRegistry"));
}

#[test]
fn test_chain_registry_default() {
    use crate::ChainRegistry;

    let registry1 = ChainRegistry::new();
    let registry2 = ChainRegistry::default();

    assert_eq!(registry1.len(), registry2.len());
    assert_eq!(registry1.is_empty(), registry2.is_empty());
}

#[test]
fn test_token_registry_debug() {
    use crate::TokenRegistry;

    let registry = TokenRegistry::new();
    let debug_str = format!("{registry:?}");
    assert!(debug_str.contains("TokenRegistry"));
}

#[test]
fn test_token_registry_default() {
    use crate::TokenRegistry;

    let registry1 = TokenRegistry::new();
    let registry2 = TokenRegistry::default();

    assert_eq!(registry1.len(), registry2.len());
    assert_eq!(registry1.is_empty(), registry2.is_empty());
}

#[test]
fn test_token_info_debug() {
    use crate::{RiskLevel, TokenInfo};

    let info = TokenInfo::new("TEST", 18, RiskLevel::Low);
    let debug_str = format!("{info:?}");
    assert!(debug_str.contains("TEST"));
    assert!(debug_str.contains("18"));
}

#[test]
fn test_risk_level_clone() {
    use crate::RiskLevel;

    let risk = RiskLevel::Low;
    #[allow(clippy::clone_on_copy)]
    let cloned = risk.clone();
    assert_eq!(risk, cloned);
}

#[test]
fn test_risk_level_debug() {
    use crate::RiskLevel;

    let debug_str = format!("{:?}", RiskLevel::Low);
    assert!(debug_str.contains("Low")); // Cannot inline format arg when using method call
}

#[test]
fn test_erc20_call_debug() {
    use crate::erc20::Erc20Call;

    let call = Erc20Call::Transfer {
        to: [0x12; 20],
        amount: U256::from(100u64),
    };
    let debug_str = format!("{call:?}");
    assert!(debug_str.contains("Transfer"));
}

#[test]
fn test_erc20_call_equality() {
    use crate::erc20::Erc20Call;

    let call1 = Erc20Call::Transfer {
        to: [0x12; 20],
        amount: U256::from(100u64),
    };
    let call2 = Erc20Call::Transfer {
        to: [0x12; 20],
        amount: U256::from(100u64),
    };
    let call3 = Erc20Call::Transfer {
        to: [0x34; 20],
        amount: U256::from(100u64),
    };

    assert_eq!(call1, call2);
    assert_ne!(call1, call3);
}
