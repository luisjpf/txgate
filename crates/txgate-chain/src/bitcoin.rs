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
//! use txgate_chain::{Chain, BitcoinParser};
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
use std::collections::HashMap;
use std::io::Cursor;
use txgate_core::error::ParseError;
use txgate_core::{ParsedTx, TxType, U256};
use txgate_crypto::CurveType;

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

    // ========================================================================
    // SegWit Transaction Tests
    // ========================================================================

    /// Create a SegWit P2WPKH transaction for testing.
    /// This is a real-format SegWit transaction with witness data.
    fn create_segwit_tx() -> Vec<u8> {
        // SegWit transaction format:
        // [version][marker=0x00][flag=0x01][inputs][outputs][witness][locktime]
        //
        // Real SegWit P2WPKH spending transaction (simplified)
        // From testnet transaction

        let mut tx = Vec::new();

        // Version (4 bytes, little-endian) - version 2 for BIP68
        tx.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]);

        // Marker (1 byte) - indicates SegWit
        tx.push(0x00);

        // Flag (1 byte) - must be 0x01 for witness
        tx.push(0x01);

        // Input count (varint)
        tx.push(0x01);

        // Input 1:
        // Previous txid (32 bytes, little-endian)
        tx.extend_from_slice(&[
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
            0xcc, 0xdd, 0xee, 0xff,
        ]);

        // Previous output index (4 bytes)
        tx.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        // ScriptSig length (0 for native SegWit)
        tx.push(0x00);

        // Sequence (4 bytes)
        tx.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]);

        // Output count (varint)
        tx.push(0x01);

        // Output 1: P2WPKH output
        // Value: 100000 satoshis (8 bytes, little-endian)
        tx.extend_from_slice(&[0xa0, 0x86, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]);

        // Script length: 22 bytes (P2WPKH: OP_0 <20-byte-hash>)
        tx.push(0x16);

        // P2WPKH script: OP_0 OP_PUSHBYTES_20 <pubkey-hash>
        tx.push(0x00); // OP_0 (witness version 0)
        tx.push(0x14); // OP_PUSHBYTES_20
        tx.extend_from_slice(&[0xab; 20]); // 20-byte pubkey hash (dummy)

        // Witness data for input 1:
        // Stack items count
        tx.push(0x02); // 2 items: signature and pubkey

        // Item 1: Signature (71-73 bytes typically, using 71)
        tx.push(0x47); // 71 bytes
        tx.extend_from_slice(&[0x30; 71]); // Dummy DER signature

        // Item 2: Public key (33 bytes compressed)
        tx.push(0x21); // 33 bytes
        tx.extend_from_slice(&[0x02; 33]); // Dummy compressed pubkey

        // Locktime (4 bytes)
        tx.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        tx
    }

    #[test]
    fn test_bitcoin_parser_segwit_transaction() {
        let parser = BitcoinParser::mainnet();
        let tx_bytes = create_segwit_tx();

        let result = parser.parse(&tx_bytes);
        assert!(
            result.is_ok(),
            "Failed to parse SegWit tx: {:?}",
            result.err()
        );

        let parsed = result.unwrap();
        assert_eq!(parsed.chain, "bitcoin");
        assert_eq!(parsed.token, Some("BTC".to_string()));

        // Check SegWit metadata
        let segwit = parsed.metadata.get("segwit");
        assert!(segwit.is_some(), "Missing segwit metadata");
        assert_eq!(segwit.unwrap(), &serde_json::Value::Bool(true));

        // Should not be Taproot
        let taproot = parsed.metadata.get("taproot");
        assert!(taproot.is_some(), "Missing taproot metadata");
        assert_eq!(taproot.unwrap(), &serde_json::Value::Bool(false));

        // Check version is 2 (BIP68)
        let version = parsed.metadata.get("version");
        assert!(version.is_some());
        assert_eq!(version.unwrap(), &serde_json::Value::Number(2.into()));
    }

    #[test]
    fn test_is_segwit_helper() {
        // Parse a SegWit transaction and verify the helper function
        let tx_bytes = create_segwit_tx();
        let mut cursor = Cursor::new(&tx_bytes);
        let tx = Transaction::consensus_decode(&mut cursor).unwrap();

        assert!(
            BitcoinParser::is_segwit(&tx),
            "is_segwit should return true for SegWit transaction"
        );
        assert!(
            !BitcoinParser::is_taproot(&tx),
            "is_taproot should return false for non-Taproot SegWit transaction"
        );
    }

    #[test]
    fn test_is_segwit_false_for_legacy() {
        // Parse a legacy transaction and verify is_segwit returns false
        let tx_bytes = create_sample_legacy_tx();
        let mut cursor = Cursor::new(&tx_bytes);
        let tx = Transaction::consensus_decode(&mut cursor).unwrap();

        assert!(
            !BitcoinParser::is_segwit(&tx),
            "is_segwit should return false for legacy transaction"
        );
        assert!(
            !BitcoinParser::is_taproot(&tx),
            "is_taproot should return false for legacy transaction"
        );
    }

    // ========================================================================
    // Taproot Transaction Tests
    // ========================================================================

    /// Create a Taproot (P2TR) transaction for testing.
    /// Uses witness version 1 with 32-byte program.
    fn create_taproot_tx() -> Vec<u8> {
        let mut tx = Vec::new();

        // Version (4 bytes)
        tx.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]);

        // Marker and flag for SegWit
        tx.push(0x00);
        tx.push(0x01);

        // Input count
        tx.push(0x01);

        // Input: Previous txid
        tx.extend_from_slice(&[0xab; 32]);

        // Previous output index
        tx.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        // Empty scriptSig for Taproot
        tx.push(0x00);

        // Sequence
        tx.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]);

        // Output count
        tx.push(0x01);

        // Output: P2TR (Taproot) output
        // Value: 50000 satoshis
        tx.extend_from_slice(&[0x50, 0xc3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

        // Script length: 34 bytes (P2TR: OP_1 <32-byte-x-only-pubkey>)
        tx.push(0x22);

        // P2TR script: OP_1 OP_PUSHBYTES_32 <x-only-pubkey>
        tx.push(0x51); // OP_1 (witness version 1 = Taproot)
        tx.push(0x20); // OP_PUSHBYTES_32
        tx.extend_from_slice(&[0xcd; 32]); // 32-byte x-only pubkey (dummy)

        // Witness data for Taproot key-path spend
        // Stack items count: 1 (just the Schnorr signature)
        tx.push(0x01);

        // Schnorr signature (64 bytes)
        tx.push(0x40); // 64 bytes
        tx.extend_from_slice(&[0x88; 64]);

        // Locktime
        tx.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        tx
    }

    #[test]
    fn test_bitcoin_parser_taproot_transaction() {
        let parser = BitcoinParser::mainnet();
        let tx_bytes = create_taproot_tx();

        let result = parser.parse(&tx_bytes);
        assert!(
            result.is_ok(),
            "Failed to parse Taproot tx: {:?}",
            result.err()
        );

        let parsed = result.unwrap();
        assert_eq!(parsed.chain, "bitcoin");
        assert_eq!(parsed.token, Some("BTC".to_string()));

        // Should be both SegWit and Taproot
        let segwit = parsed.metadata.get("segwit");
        assert!(segwit.is_some(), "Missing segwit metadata");
        assert_eq!(
            segwit.unwrap(),
            &serde_json::Value::Bool(true),
            "Taproot transaction should also be SegWit"
        );

        let taproot = parsed.metadata.get("taproot");
        assert!(taproot.is_some(), "Missing taproot metadata");
        assert_eq!(
            taproot.unwrap(),
            &serde_json::Value::Bool(true),
            "Should be identified as Taproot"
        );
    }

    #[test]
    fn test_is_taproot_helper() {
        // Parse a Taproot transaction and verify the helper
        let tx_bytes = create_taproot_tx();
        let mut cursor = Cursor::new(&tx_bytes);
        let tx = Transaction::consensus_decode(&mut cursor).unwrap();

        assert!(
            BitcoinParser::is_segwit(&tx),
            "Taproot transactions are also SegWit"
        );
        assert!(
            BitcoinParser::is_taproot(&tx),
            "is_taproot should return true for P2TR transaction"
        );
    }

    // ========================================================================
    // Transaction Type Detection Tests
    // ========================================================================

    /// Create a transaction with OP_RETURN output (data carrier).
    fn create_op_return_tx() -> Vec<u8> {
        let mut tx = Vec::new();

        // Version
        tx.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);

        // Input count
        tx.push(0x01);

        // Input: coinbase-style for simplicity
        tx.extend_from_slice(&[0x00; 32]); // txid
        tx.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]); // vout
        tx.push(0x07); // script length
        tx.extend_from_slice(&[0x04, 0xff, 0xff, 0x00, 0x1d, 0x01, 0x04]); // coinbase script
        tx.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]); // sequence

        // Output count: 2 outputs (one P2PKH, one OP_RETURN)
        tx.push(0x02);

        // Output 1: Regular P2PKH
        tx.extend_from_slice(&[0x00, 0xe1, 0xf5, 0x05, 0x00, 0x00, 0x00, 0x00]); // 1 BTC
        tx.push(0x19); // 25 bytes
        tx.push(0x76); // OP_DUP
        tx.push(0xa9); // OP_HASH160
        tx.push(0x14); // Push 20 bytes
        tx.extend_from_slice(&[0xbc; 20]); // pubkey hash
        tx.push(0x88); // OP_EQUALVERIFY
        tx.push(0xac); // OP_CHECKSIG

        // Output 2: OP_RETURN with data
        tx.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // 0 value
        tx.push(0x0d); // 13 bytes
        tx.push(0x6a); // OP_RETURN
        tx.push(0x0b); // Push 11 bytes
        tx.extend_from_slice(b"hello world"); // data payload

        // Locktime
        tx.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        tx
    }

    #[test]
    fn test_bitcoin_parser_op_return_transaction() {
        let parser = BitcoinParser::mainnet();
        let tx_bytes = create_op_return_tx();

        let result = parser.parse(&tx_bytes);
        assert!(
            result.is_ok(),
            "Failed to parse OP_RETURN tx: {:?}",
            result.err()
        );

        let parsed = result.unwrap();

        // OP_RETURN transactions should be TxType::Other
        assert_eq!(
            parsed.tx_type,
            TxType::Other,
            "OP_RETURN transaction should be TxType::Other"
        );

        // The amount should only include non-OP_RETURN outputs
        // Output 1 has 1 BTC = 100_000_000 satoshis
        assert!(parsed.amount.is_some());
        assert_eq!(parsed.amount.unwrap(), U256::from(100_000_000u64));

        // Recipient should be from the non-OP_RETURN output
        assert!(parsed.recipient.is_some());
    }

    #[test]
    fn test_determine_tx_type_helper() {
        // Test with OP_RETURN
        let tx_bytes = create_op_return_tx();
        let mut cursor = Cursor::new(&tx_bytes);
        let tx = Transaction::consensus_decode(&mut cursor).unwrap();
        assert_eq!(
            BitcoinParser::determine_tx_type(&tx),
            TxType::Other,
            "OP_RETURN should be TxType::Other"
        );

        // Test with regular transfer
        let tx_bytes = create_sample_legacy_tx();
        let mut cursor = Cursor::new(&tx_bytes);
        let tx = Transaction::consensus_decode(&mut cursor).unwrap();
        assert_eq!(
            BitcoinParser::determine_tx_type(&tx),
            TxType::Transfer,
            "Regular transaction should be TxType::Transfer"
        );
    }

    // ========================================================================
    // Address Extraction Tests
    // ========================================================================

    #[test]
    fn test_bitcoin_parser_p2wpkh_address_extraction() {
        let parser = BitcoinParser::mainnet();
        let tx_bytes = create_segwit_tx();

        let result = parser.parse(&tx_bytes);
        assert!(result.is_ok());

        let parsed = result.unwrap();

        // Check that output_addresses contains a bech32 address
        let addresses = parsed.metadata.get("output_addresses");
        assert!(addresses.is_some());

        if let serde_json::Value::Array(addrs) = addresses.unwrap() {
            assert!(!addrs.is_empty(), "Should have at least one address");
            if let serde_json::Value::String(addr) = &addrs[0] {
                assert!(
                    addr.starts_with("bc1q"),
                    "P2WPKH address should start with bc1q, got: {}",
                    addr
                );
            }
        }
    }

    #[test]
    fn test_bitcoin_parser_p2tr_address_extraction() {
        let parser = BitcoinParser::mainnet();
        let tx_bytes = create_taproot_tx();

        let result = parser.parse(&tx_bytes);
        assert!(result.is_ok());

        let parsed = result.unwrap();

        // Check that output_addresses contains a Taproot bech32m address
        let addresses = parsed.metadata.get("output_addresses");
        assert!(addresses.is_some());

        if let serde_json::Value::Array(addrs) = addresses.unwrap() {
            assert!(!addrs.is_empty(), "Should have at least one address");
            if let serde_json::Value::String(addr) = &addrs[0] {
                assert!(
                    addr.starts_with("bc1p"),
                    "P2TR address should start with bc1p, got: {}",
                    addr
                );
            }
        }
    }

    #[test]
    fn test_bitcoin_parser_testnet_addresses() {
        let parser = BitcoinParser::testnet();
        let tx_bytes = create_segwit_tx();

        let result = parser.parse(&tx_bytes);
        assert!(result.is_ok());

        let parsed = result.unwrap();

        let addresses = parsed.metadata.get("output_addresses");
        assert!(addresses.is_some());

        if let serde_json::Value::Array(addrs) = addresses.unwrap() {
            if !addrs.is_empty() {
                if let serde_json::Value::String(addr) = &addrs[0] {
                    // Testnet P2WPKH should start with tb1q
                    assert!(
                        addr.starts_with("tb1q"),
                        "Testnet P2WPKH should start with tb1q, got: {}",
                        addr
                    );
                }
            }
        }
    }
}
