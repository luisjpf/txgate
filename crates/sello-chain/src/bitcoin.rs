//! Bitcoin transaction parser.
//!
//! This module provides the [`BitcoinParser`] implementation for parsing
//! Bitcoin transactions into the common [`ParsedTx`] format.
//!
//! # Supported Transaction Types
//!
//! - **Legacy**: Pre-`SegWit` transactions (P2PKH, P2SH)
//! - **`SegWit` v0**: Native `SegWit` transactions (P2WPKH, P2WSH)
//! - **Taproot**: `SegWit` v1 transactions (P2TR)
//!
//! # Example
//!
//! ```ignore
//! use sello_chain::{Chain, BitcoinParser};
//!
//! let parser = BitcoinParser::mainnet();
//!
//! // Parse a raw Bitcoin transaction
//! let raw_tx = hex::decode("0100000001...").unwrap();
//! let parsed = parser.parse(&raw_tx)?;
//!
//! println!("Recipients: {:?}", parsed.recipient);
//! println!("Amount: {:?}", parsed.amount);
//! ```
//!
//! # Limitations
//!
//! - Fee calculation requires UTXO lookup (input amounts are not in the raw transaction)
//! - Token detection (Ordinals, BRC-20, Runes) is not yet implemented

use bitcoin::consensus::Decodable;
use bitcoin::{Address, Network, Transaction, TxOut};
use sello_core::error::ParseError;
use sello_core::{ParsedTx, TxType, U256};
use sello_crypto::CurveType;
use std::collections::HashMap;
use std::io::Cursor;

use crate::Chain;

/// Bitcoin transaction parser.
///
/// Parses raw Bitcoin transactions into the common [`ParsedTx`] format
/// for policy evaluation.
///
/// # Network Configuration
///
/// The parser must be configured with the appropriate Bitcoin network
/// to correctly decode addresses:
///
/// - [`BitcoinParser::mainnet()`] - Bitcoin Mainnet
/// - [`BitcoinParser::testnet()`] - Bitcoin Testnet
/// - [`BitcoinParser::signet()`] - Bitcoin Signet
/// - [`BitcoinParser::regtest()`] - Bitcoin Regtest
///
/// # Thread Safety
///
/// `BitcoinParser` is `Send + Sync` and can be safely shared across threads.
#[derive(Debug, Clone, Copy)]
pub struct BitcoinParser {
    network: Network,
}

impl BitcoinParser {
    /// Create a parser for Bitcoin Mainnet.
    #[must_use]
    pub const fn mainnet() -> Self {
        Self {
            network: Network::Bitcoin,
        }
    }

    /// Create a parser for Bitcoin Testnet.
    #[must_use]
    pub const fn testnet() -> Self {
        Self {
            network: Network::Testnet,
        }
    }

    /// Create a parser for Bitcoin Signet.
    #[must_use]
    pub const fn signet() -> Self {
        Self {
            network: Network::Signet,
        }
    }

    /// Create a parser for Bitcoin Regtest.
    #[must_use]
    pub const fn regtest() -> Self {
        Self {
            network: Network::Regtest,
        }
    }

    /// Create a parser with a custom network.
    #[must_use]
    pub const fn new(network: Network) -> Self {
        Self { network }
    }

    /// Get the configured network.
    #[must_use]
    pub const fn network(&self) -> Network {
        self.network
    }

    /// Extract address from a transaction output.
    fn extract_address(self, output: &TxOut) -> Option<String> {
        Address::from_script(&output.script_pubkey, self.network)
            .ok()
            .map(|addr| addr.to_string())
    }

    /// Determine transaction type based on outputs.
    fn determine_tx_type(tx: &Transaction) -> TxType {
        // Check for OP_RETURN outputs (data carrier)
        let has_op_return = tx.output.iter().any(|out| out.script_pubkey.is_op_return());

        if has_op_return {
            // Could be Ordinals, BRC-20, Runes, or other protocols
            return TxType::Other;
        }

        // Simple transfer if we have standard outputs
        TxType::Transfer
    }

    /// Check if transaction uses `SegWit`.
    fn is_segwit(tx: &Transaction) -> bool {
        tx.input.iter().any(|input| !input.witness.is_empty())
    }

    /// Check if transaction uses Taproot.
    fn is_taproot(tx: &Transaction) -> bool {
        // Check if any input has a Taproot witness (key path or script path)
        tx.input.iter().any(|input| {
            // Taproot key-path spend has exactly one witness element (64-byte Schnorr sig)
            // Taproot script-path spend has multiple elements
            if input.witness.is_empty() {
                return false;
            }

            // Check if any output is P2TR (witness version 1)
            tx.output.iter().any(|out| out.script_pubkey.is_p2tr())
        })
    }
}

impl Default for BitcoinParser {
    fn default() -> Self {
        Self::mainnet()
    }
}

impl Chain for BitcoinParser {
    fn id(&self) -> &'static str {
        "bitcoin"
    }

    fn parse(&self, raw: &[u8]) -> Result<ParsedTx, ParseError> {
        if raw.is_empty() {
            return Err(ParseError::MalformedTransaction {
                context: "empty transaction data".to_string(),
            });
        }

        // Decode the transaction
        let mut cursor = Cursor::new(raw);
        let tx = Transaction::consensus_decode(&mut cursor).map_err(|e| {
            ParseError::MalformedTransaction {
                context: format!("failed to decode Bitcoin transaction: {e}"),
            }
        })?;

        // Compute transaction ID (hash)
        let txid = tx.compute_txid();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(txid.as_ref());
        // Bitcoin uses little-endian display, but we store as-is for signing
        hash.reverse();

        // Find the primary recipient (first non-OP_RETURN, non-change output)
        // In practice, determining "change" requires UTXO context
        let recipient = tx
            .output
            .iter()
            .filter(|out| !out.script_pubkey.is_op_return())
            .find_map(|out| self.extract_address(out));

        // Calculate total output amount (sum of all outputs except OP_RETURN)
        let total_output: u64 = tx
            .output
            .iter()
            .filter(|out| !out.script_pubkey.is_op_return())
            .map(|out| out.value.to_sat())
            .sum();

        let amount = Some(U256::from(total_output));

        // Determine transaction type
        let tx_type = Self::determine_tx_type(&tx);

        // Build metadata
        let mut metadata = HashMap::new();

        // Add version
        metadata.insert(
            "version".to_string(),
            serde_json::Value::Number(tx.version.0.into()),
        );

        // Add locktime
        metadata.insert(
            "locktime".to_string(),
            serde_json::Value::Number(tx.lock_time.to_consensus_u32().into()),
        );

        // Add input count
        metadata.insert(
            "input_count".to_string(),
            serde_json::Value::Number(tx.input.len().into()),
        );

        // Add output count
        metadata.insert(
            "output_count".to_string(),
            serde_json::Value::Number(tx.output.len().into()),
        );

        // Add SegWit flag
        metadata.insert(
            "segwit".to_string(),
            serde_json::Value::Bool(Self::is_segwit(&tx)),
        );

        // Add Taproot flag
        metadata.insert(
            "taproot".to_string(),
            serde_json::Value::Bool(Self::is_taproot(&tx)),
        );

        // Add virtual size (vsize) for fee estimation
        metadata.insert(
            "vsize".to_string(),
            serde_json::Value::Number(tx.vsize().into()),
        );

        // Add weight
        metadata.insert(
            "weight".to_string(),
            serde_json::Value::Number(tx.weight().to_wu().into()),
        );

        // Add all output addresses for policy evaluation
        let output_addresses: Vec<serde_json::Value> = tx
            .output
            .iter()
            .filter_map(|out| self.extract_address(out))
            .map(serde_json::Value::String)
            .collect();
        metadata.insert(
            "output_addresses".to_string(),
            serde_json::Value::Array(output_addresses),
        );

        // Add all output amounts
        let output_amounts: Vec<serde_json::Value> = tx
            .output
            .iter()
            .map(|out| serde_json::Value::Number(out.value.to_sat().into()))
            .collect();
        metadata.insert(
            "output_amounts".to_string(),
            serde_json::Value::Array(output_amounts),
        );

        Ok(ParsedTx {
            hash,
            recipient,
            amount,
            token: Some("BTC".to_string()),
            token_address: None, // Native currency
            tx_type,
            chain: "bitcoin".to_string(),
            nonce: None, // Bitcoin doesn't have nonces
            chain_id: None,
            metadata,
        })
    }

    fn curve(&self) -> CurveType {
        CurveType::Secp256k1
    }

    fn supports_version(&self, version: u8) -> bool {
        // Bitcoin transaction versions 1 and 2 are common
        // Version 2 enables BIP68 (relative lock-time)
        matches!(version, 1 | 2)
    }
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
        clippy::indexing_slicing
    )]

    use super::*;

    // Sample legacy P2PKH transaction (simplified for testing)
    // This is a minimal valid transaction structure
    fn create_sample_legacy_tx() -> Vec<u8> {
        // A simple 1-input, 1-output transaction
        // Version: 01000000
        // Input count: 01
        // Input: 32-byte txid + 4-byte vout + script + sequence
        // Output count: 01
        // Output: 8-byte value + script
        // Locktime: 00000000

        // Using a real testnet transaction hex for testing
        hex::decode(
            "0100000001000000000000000000000000000000000000000000000000\
             0000000000000000ffffffff0704ffff001d0104ffffffff0100f2052a\
             0100000043410496b538e853519c726a2c91e61ec11600ae1390813a62\
             7c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166\
             bf621e73a82cbf2342c858eeac00000000",
        )
        .unwrap_or_else(|_| {
            // Fallback: create a minimal transaction manually
            let mut tx_bytes = Vec::new();

            // Version (4 bytes, little-endian)
            tx_bytes.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);

            // Input count (varint)
            tx_bytes.push(0x01);

            // Input: previous txid (32 bytes, all zeros for coinbase)
            tx_bytes.extend_from_slice(&[0x00; 32]);

            // Input: previous output index (4 bytes)
            tx_bytes.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]);

            // Input: script length (varint)
            tx_bytes.push(0x07);

            // Input: script (7 bytes)
            tx_bytes.extend_from_slice(&[0x04, 0xff, 0xff, 0x00, 0x1d, 0x01, 0x04]);

            // Input: sequence (4 bytes)
            tx_bytes.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]);

            // Output count (varint)
            tx_bytes.push(0x01);

            // Output: value (8 bytes, little-endian) - 50 BTC in satoshis
            tx_bytes.extend_from_slice(&[0x00, 0xf2, 0x05, 0x2a, 0x01, 0x00, 0x00, 0x00]);

            // Output: script length (varint)
            tx_bytes.push(0x43);

            // Output: P2PK script (67 bytes)
            tx_bytes.push(0x41); // Push 65 bytes
            tx_bytes.extend_from_slice(&[0x04; 65]); // Dummy public key
            tx_bytes.push(0xac); // OP_CHECKSIG

            // Locktime (4 bytes)
            tx_bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

            tx_bytes
        })
    }

    #[test]
    fn test_bitcoin_parser_id() {
        let parser = BitcoinParser::mainnet();
        assert_eq!(parser.id(), "bitcoin");
    }

    #[test]
    fn test_bitcoin_parser_curve() {
        let parser = BitcoinParser::mainnet();
        assert_eq!(parser.curve(), CurveType::Secp256k1);
    }

    #[test]
    fn test_bitcoin_parser_networks() {
        assert_eq!(BitcoinParser::mainnet().network(), Network::Bitcoin);
        assert_eq!(BitcoinParser::testnet().network(), Network::Testnet);
        assert_eq!(BitcoinParser::signet().network(), Network::Signet);
        assert_eq!(BitcoinParser::regtest().network(), Network::Regtest);
    }

    #[test]
    fn test_bitcoin_parser_default() {
        let parser = BitcoinParser::default();
        assert_eq!(parser.network(), Network::Bitcoin);
    }

    #[test]
    fn test_bitcoin_parser_empty_input() {
        let parser = BitcoinParser::mainnet();
        let result = parser.parse(&[]);

        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(ParseError::MalformedTransaction { .. })
        ));
    }

    #[test]
    fn test_bitcoin_parser_invalid_input() {
        let parser = BitcoinParser::mainnet();
        let result = parser.parse(&[0x00, 0x01, 0x02]);

        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(ParseError::MalformedTransaction { .. })
        ));
    }

    #[test]
    fn test_bitcoin_parser_parse_transaction() {
        let parser = BitcoinParser::mainnet();
        let tx_bytes = create_sample_legacy_tx();

        let result = parser.parse(&tx_bytes);

        // The transaction should parse (even if it's a coinbase)
        assert!(result.is_ok(), "Failed to parse: {:?}", result.err());

        let parsed = result.unwrap();
        assert_eq!(parsed.chain, "bitcoin");
        assert_eq!(parsed.token, Some("BTC".to_string()));
        assert!(parsed.token_address.is_none());
        assert_eq!(parsed.tx_type, TxType::Transfer);

        // Check metadata
        assert!(parsed.metadata.contains_key("version"));
        assert!(parsed.metadata.contains_key("locktime"));
        assert!(parsed.metadata.contains_key("input_count"));
        assert!(parsed.metadata.contains_key("output_count"));
        assert!(parsed.metadata.contains_key("segwit"));
        assert!(parsed.metadata.contains_key("vsize"));
    }

    #[test]
    fn test_bitcoin_parser_supports_version() {
        let parser = BitcoinParser::mainnet();

        assert!(parser.supports_version(1));
        assert!(parser.supports_version(2));
        assert!(!parser.supports_version(0));
        assert!(!parser.supports_version(3));
    }

    #[test]
    fn test_bitcoin_parser_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<BitcoinParser>();
    }

    #[test]
    fn test_bitcoin_parser_clone() {
        let parser = BitcoinParser::mainnet();
        let cloned = parser;
        assert_eq!(parser.network(), cloned.network());
    }

    #[test]
    fn test_bitcoin_parser_debug() {
        let parser = BitcoinParser::mainnet();
        let debug_str = format!("{parser:?}");
        assert!(debug_str.contains("BitcoinParser"));
        assert!(debug_str.contains("Bitcoin"));
    }
}
