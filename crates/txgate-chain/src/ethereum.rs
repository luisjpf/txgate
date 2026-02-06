//! Ethereum transaction parser implementation.
//!
//! This module provides the [`EthereumParser`] struct that implements the [`Chain`]
//! trait for parsing Ethereum transactions.
//!
//! # Supported Transaction Types
//!
//! - **Legacy (Type 0)**: Pre-EIP-2718 transactions, RLP-encoded directly
//! - **EIP-2930 (Type 1)**: Access list transactions, prefixed with `0x01`
//! - **EIP-1559 (Type 2)**: Dynamic fee transactions, prefixed with `0x02`
//!
//! # Example
//!
//! ```
//! use txgate_chain::{Chain, EthereumParser};
//!
//! let parser = EthereumParser::new();
//! assert_eq!(parser.id(), "ethereum");
//!
//! // Parse a raw transaction (hex-decoded bytes)
//! // let parsed = parser.parse(&raw_tx_bytes)?;
//! ```
//!
//! # Transaction Hash
//!
//! The transaction hash is computed as the Keccak-256 hash of the raw transaction bytes.
//! This includes the type prefix for typed transactions (EIP-2718+).
//!
//! # Chain ID Extraction
//!
//! - For typed transactions (EIP-2930, EIP-1559): Chain ID is explicitly in the transaction
//! - For legacy transactions with EIP-155: `chain_id = (v - 35) / 2`
//! - For pre-EIP-155 legacy transactions (v = 27 or 28): Assumes mainnet (`chain_id` = 1)

use alloy_primitives::{keccak256, Address, U256};
use txgate_core::{error::ParseError, ParsedTx, TxType};
use txgate_crypto::CurveType;

use crate::erc20::{parse_erc20_call, Erc20Call};
use crate::rlp::{
    decode_bytes, decode_list, decode_optional_address, decode_u256, decode_u64, detect_tx_type,
    typed_tx_payload,
};
use crate::Chain;

/// Ethereum transaction parser.
///
/// This struct implements the [`Chain`] trait for parsing Ethereum transactions
/// into the unified [`ParsedTx`] format.
///
/// # Supported Transaction Types
///
/// - Legacy transactions (type 0 or no type prefix)
/// - EIP-2930 transactions (type 1)
/// - EIP-1559 transactions (type 2)
///
/// # Example
///
/// ```
/// use txgate_chain::{Chain, EthereumParser};
///
/// let parser = EthereumParser::new();
///
/// // Check chain ID and curve
/// assert_eq!(parser.id(), "ethereum");
/// assert_eq!(parser.curve(), txgate_crypto::CurveType::Secp256k1);
///
/// // Check supported versions
/// assert!(parser.supports_version(0));
/// assert!(parser.supports_version(1));
/// assert!(parser.supports_version(2));
/// assert!(!parser.supports_version(3)); // EIP-4844 not yet supported
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct EthereumParser;

impl EthereumParser {
    /// Create a new Ethereum parser instance.
    ///
    /// # Example
    ///
    /// ```
    /// use txgate_chain::EthereumParser;
    ///
    /// let parser = EthereumParser::new();
    /// ```
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Parse a legacy transaction (type 0 or no type prefix).
    ///
    /// Legacy transactions are RLP-encoded as:
    /// `[nonce, gasPrice, gasLimit, to, value, data, v, r, s]`
    ///
    /// # Chain ID Extraction (EIP-155)
    ///
    /// - If `v >= 35`: `chain_id = (v - 35) / 2`
    /// - If `v = 27` or `v = 28`: Pre-EIP-155, assumes mainnet (`chain_id` = 1)
    fn parse_legacy(raw: &[u8]) -> Result<ParsedTx, ParseError> {
        // For true legacy transactions, the hash source is the same as the RLP payload
        Self::parse_legacy_with_hash_source(raw, raw)
    }

    /// Parse a legacy transaction with a separate hash source.
    ///
    /// This is used for type 0 transactions where the hash must be computed
    /// over the full raw bytes (including type prefix), but the RLP payload
    /// is without the type prefix.
    ///
    /// # Arguments
    ///
    /// * `hash_source` - The bytes to compute the transaction hash from (full raw for typed txs)
    /// * `rlp_payload` - The RLP-encoded transaction data (without type prefix for typed txs)
    fn parse_legacy_with_hash_source(
        hash_source: &[u8],
        rlp_payload: &[u8],
    ) -> Result<ParsedTx, ParseError> {
        // Decode the RLP list from the payload
        let items = decode_list(rlp_payload)?;

        // Legacy transaction:
        // - Signed: 9 items [nonce, gasPrice, gasLimit, to, value, data, v, r, s]
        // - Unsigned pre-EIP-155: 6 items [nonce, gasPrice, gasLimit, to, value, data]
        // - Unsigned EIP-155: 9 items [nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0]
        let is_unsigned = items.len() == 6;
        if items.len() != 9 && items.len() != 6 {
            return Err(ParseError::MalformedTransaction {
                context: format!(
                    "legacy transaction expected 6 or 9 items, got {}",
                    items.len()
                ),
            });
        }

        // Extract fields using safe indexing
        let nonce_bytes = items
            .first()
            .ok_or_else(|| ParseError::MalformedTransaction {
                context: "missing nonce field".to_string(),
            })?;
        let to_bytes = items
            .get(3)
            .ok_or_else(|| ParseError::MalformedTransaction {
                context: "missing to field".to_string(),
            })?;
        let value_bytes = items
            .get(4)
            .ok_or_else(|| ParseError::MalformedTransaction {
                context: "missing value field".to_string(),
            })?;
        let data_bytes = items
            .get(5)
            .ok_or_else(|| ParseError::MalformedTransaction {
                context: "missing data field".to_string(),
            })?;

        // Decode nonce
        let nonce = decode_u64(nonce_bytes)?;

        // Decode recipient (can be empty for contract deployments)
        let recipient = decode_optional_address(to_bytes)?;

        // Decode value
        let amount = decode_u256(value_bytes)?;

        // Decode data
        let data = decode_bytes(data_bytes)?;

        // Extract chain_id: from v field (signed) or default to 1 (unsigned pre-EIP-155)
        let chain_id = if is_unsigned {
            // Unsigned pre-EIP-155: no chain_id available, default to mainnet
            1
        } else {
            let v_bytes = items
                .get(6)
                .ok_or_else(|| ParseError::MalformedTransaction {
                    context: "missing v field".to_string(),
                })?;
            let v = decode_u64(v_bytes)?;

            if v >= 35 {
                // EIP-155: chain_id = (v - 35) / 2
                (v - 35) / 2
            } else if v == 27 || v == 28 {
                // Pre-EIP-155: assume mainnet
                1
            } else {
                // Could be EIP-155 unsigned where v == chain_id
                // (items[6] = chain_id, items[7] = 0, items[8] = 0)
                v
            }
        };

        // Check for ERC-20 token call
        let erc20_info = recipient
            .as_ref()
            .and_then(|addr| Self::analyze_erc20(addr, &data));

        // Determine transaction type (ERC-20 detection takes precedence)
        let (final_tx_type, final_recipient, final_amount, token_address) =
            erc20_info.as_ref().map_or_else(
                || {
                    (
                        Self::determine_tx_type(recipient.as_ref(), &data, &amount),
                        recipient.map(|addr| format!("{addr}")),
                        Some(amount),
                        None,
                    )
                },
                |info| {
                    (
                        info.tx_type,
                        Some(format!("{}", info.recipient)),
                        Some(info.amount),
                        Some(format!("{}", info.token_address)),
                    )
                },
            );

        // Compute transaction hash from the hash source (includes type prefix for typed txs)
        let hash = keccak256(hash_source);

        let mut metadata = std::collections::HashMap::new();
        if is_unsigned {
            metadata.insert("unsigned".to_string(), serde_json::Value::Bool(true));
        }

        Ok(ParsedTx {
            hash: hash.into(),
            recipient: final_recipient,
            amount: final_amount,
            token: None, // Token symbol lookup not implemented yet
            token_address,
            tx_type: final_tx_type,
            chain: "ethereum".to_string(),
            nonce: Some(nonce),
            chain_id: Some(chain_id),
            metadata,
        })
    }

    /// Parse an EIP-2930 transaction (type 1).
    ///
    /// EIP-2930 transactions are encoded as:
    /// `0x01 || RLP([chainId, nonce, gasPrice, gasLimit, to, value, data, accessList, signatureYParity, signatureR, signatureS])`
    fn parse_eip2930(raw: &[u8], payload: &[u8]) -> Result<ParsedTx, ParseError> {
        // Decode the RLP list from the payload (without type byte)
        let items = decode_list(payload)?;

        // EIP-2930: signed has 11 items, unsigned has 8 items
        let is_unsigned = items.len() == 8;
        if items.len() != 11 && items.len() != 8 {
            return Err(ParseError::MalformedTransaction {
                context: format!(
                    "EIP-2930 transaction expected 8 or 11 items, got {}",
                    items.len()
                ),
            });
        }

        // Extract fields using safe indexing
        let chain_id_bytes = items
            .first()
            .ok_or_else(|| ParseError::MalformedTransaction {
                context: "missing chainId field".to_string(),
            })?;
        let nonce_bytes = items
            .get(1)
            .ok_or_else(|| ParseError::MalformedTransaction {
                context: "missing nonce field".to_string(),
            })?;
        let to_bytes = items
            .get(4)
            .ok_or_else(|| ParseError::MalformedTransaction {
                context: "missing to field".to_string(),
            })?;
        let value_bytes = items
            .get(5)
            .ok_or_else(|| ParseError::MalformedTransaction {
                context: "missing value field".to_string(),
            })?;
        let data_bytes = items
            .get(6)
            .ok_or_else(|| ParseError::MalformedTransaction {
                context: "missing data field".to_string(),
            })?;

        // Decode fields
        let chain_id = decode_u64(chain_id_bytes)?;
        let nonce = decode_u64(nonce_bytes)?;
        let recipient = decode_optional_address(to_bytes)?;
        let amount = decode_u256(value_bytes)?;
        let data = decode_bytes(data_bytes)?;

        // Check for ERC-20 token call
        let erc20_info = recipient
            .as_ref()
            .and_then(|addr| Self::analyze_erc20(addr, &data));

        // Determine transaction type (ERC-20 detection takes precedence)
        let (final_tx_type, final_recipient, final_amount, token_address) =
            erc20_info.as_ref().map_or_else(
                || {
                    (
                        Self::determine_tx_type(recipient.as_ref(), &data, &amount),
                        recipient.map(|addr| format!("{addr}")),
                        Some(amount),
                        None,
                    )
                },
                |info| {
                    (
                        info.tx_type,
                        Some(format!("{}", info.recipient)),
                        Some(info.amount),
                        Some(format!("{}", info.token_address)),
                    )
                },
            );

        // Compute transaction hash (includes type byte)
        let hash = keccak256(raw);

        Ok(ParsedTx {
            hash: hash.into(),
            recipient: final_recipient,
            amount: final_amount,
            token: None, // Token symbol lookup not implemented yet
            token_address,
            tx_type: final_tx_type,
            chain: "ethereum".to_string(),
            nonce: Some(nonce),
            chain_id: Some(chain_id),
            metadata: {
                let mut m = std::collections::HashMap::new();
                if is_unsigned {
                    m.insert("unsigned".to_string(), serde_json::Value::Bool(true));
                }
                m
            },
        })
    }

    /// Parse an EIP-1559 transaction (type 2).
    ///
    /// EIP-1559 transactions are encoded as:
    /// `0x02 || RLP([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, destination, amount, data, access_list, signature_y_parity, signature_r, signature_s])`
    fn parse_eip1559(raw: &[u8], payload: &[u8]) -> Result<ParsedTx, ParseError> {
        // Decode the RLP list from the payload (without type byte)
        let items = decode_list(payload)?;

        // EIP-1559: signed has 12 items, unsigned has 9 items
        let is_unsigned = items.len() == 9;
        if items.len() != 12 && items.len() != 9 {
            return Err(ParseError::MalformedTransaction {
                context: format!(
                    "EIP-1559 transaction expected 9 or 12 items, got {}",
                    items.len()
                ),
            });
        }

        // Extract fields using safe indexing
        let chain_id_bytes = items
            .first()
            .ok_or_else(|| ParseError::MalformedTransaction {
                context: "missing chainId field".to_string(),
            })?;
        let nonce_bytes = items
            .get(1)
            .ok_or_else(|| ParseError::MalformedTransaction {
                context: "missing nonce field".to_string(),
            })?;
        let to_bytes = items
            .get(5)
            .ok_or_else(|| ParseError::MalformedTransaction {
                context: "missing to field".to_string(),
            })?;
        let value_bytes = items
            .get(6)
            .ok_or_else(|| ParseError::MalformedTransaction {
                context: "missing value field".to_string(),
            })?;
        let data_bytes = items
            .get(7)
            .ok_or_else(|| ParseError::MalformedTransaction {
                context: "missing data field".to_string(),
            })?;

        // Decode fields
        let chain_id = decode_u64(chain_id_bytes)?;
        let nonce = decode_u64(nonce_bytes)?;
        let recipient = decode_optional_address(to_bytes)?;
        let amount = decode_u256(value_bytes)?;
        let data = decode_bytes(data_bytes)?;

        // Check for ERC-20 token call
        let erc20_info = recipient
            .as_ref()
            .and_then(|addr| Self::analyze_erc20(addr, &data));

        // Determine transaction type (ERC-20 detection takes precedence)
        let (final_tx_type, final_recipient, final_amount, token_address) =
            erc20_info.as_ref().map_or_else(
                || {
                    (
                        Self::determine_tx_type(recipient.as_ref(), &data, &amount),
                        recipient.map(|addr| format!("{addr}")),
                        Some(amount),
                        None,
                    )
                },
                |info| {
                    (
                        info.tx_type,
                        Some(format!("{}", info.recipient)),
                        Some(info.amount),
                        Some(format!("{}", info.token_address)),
                    )
                },
            );

        // Compute transaction hash (includes type byte)
        let hash = keccak256(raw);

        Ok(ParsedTx {
            hash: hash.into(),
            recipient: final_recipient,
            amount: final_amount,
            token: None, // Token symbol lookup not implemented yet
            token_address,
            tx_type: final_tx_type,
            chain: "ethereum".to_string(),
            nonce: Some(nonce),
            chain_id: Some(chain_id),
            metadata: {
                let mut m = std::collections::HashMap::new();
                if is_unsigned {
                    m.insert("unsigned".to_string(), serde_json::Value::Bool(true));
                }
                m
            },
        })
    }

    /// Determine the transaction type based on recipient, data, and amount.
    ///
    /// - `Deployment`: No recipient (contract creation)
    /// - `ContractCall`: Has data (non-empty calldata)
    /// - `Transfer`: Simple ETH transfer (has recipient, no data)
    const fn determine_tx_type(
        recipient: Option<&alloy_primitives::Address>,
        data: &[u8],
        _amount: &U256,
    ) -> TxType {
        if recipient.is_none() {
            // No recipient = contract deployment
            TxType::Deployment
        } else if !data.is_empty() {
            // Has data = contract call
            TxType::ContractCall
        } else {
            // Simple ETH transfer
            TxType::Transfer
        }
    }

    /// Analyze transaction data and return ERC-20 specific information if applicable.
    ///
    /// This function checks if the transaction is an ERC-20 token call and extracts
    /// the relevant information for enriching the `ParsedTx`.
    ///
    /// # Arguments
    ///
    /// * `contract_address` - The address of the contract being called (the token contract)
    /// * `data` - The transaction calldata
    ///
    /// # Returns
    ///
    /// Returns `Some(Erc20Info)` if this is an ERC-20 call, `None` otherwise.
    fn analyze_erc20(contract_address: &Address, data: &[u8]) -> Option<Erc20Info> {
        let erc20_call = parse_erc20_call(data)?;

        let (tx_type, recipient_addr) = match &erc20_call {
            Erc20Call::Transfer { to, .. } | Erc20Call::TransferFrom { to, .. } => {
                (TxType::TokenTransfer, Address::from_slice(to))
            }
            Erc20Call::Approve { spender, .. } => {
                (TxType::TokenApproval, Address::from_slice(spender))
            }
        };

        Some(Erc20Info {
            tx_type,
            token_address: *contract_address,
            recipient: recipient_addr,
            amount: *erc20_call.amount(),
        })
    }

    /// Assemble a fully signed transaction from raw bytes and a 65-byte signature.
    ///
    /// Takes the original raw transaction bytes (signed or unsigned) and the
    /// signature (`r[32] || s[32] || v[1]`) and returns the RLP-encoded signed
    /// transaction ready for broadcast.
    ///
    /// # Arguments
    ///
    /// * `raw` - The raw transaction bytes (as originally passed to `parse()`)
    /// * `signature` - 65-byte signature: `r(32) || s(32) || recovery_id(1)`
    ///
    /// # Returns
    ///
    /// The fully assembled, RLP-encoded signed transaction bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::AssemblyFailed`] if:
    /// - The signature is not exactly 65 bytes
    /// - The transaction cannot be decoded
    /// - RLP encoding of the signed transaction fails
    pub fn assemble_signed(raw: &[u8], signature: &[u8]) -> Result<Vec<u8>, ParseError> {
        use alloy_primitives::Signature;

        if signature.len() != 65 {
            return Err(ParseError::assembly_failed(format!(
                "expected 65-byte signature, got {}",
                signature.len()
            )));
        }

        // Extract signature components
        let r = U256::from_be_slice(
            signature
                .get(0..32)
                .ok_or_else(|| ParseError::assembly_failed("signature too short for r"))?,
        );
        let s = U256::from_be_slice(
            signature
                .get(32..64)
                .ok_or_else(|| ParseError::assembly_failed("signature too short for s"))?,
        );
        let v_parity = signature
            .get(64)
            .ok_or_else(|| ParseError::assembly_failed("signature too short for v"))?
            != &0;

        let sig = Signature::new(r, s, v_parity);

        // Detect tx type and assemble
        match detect_tx_type(raw) {
            None => {
                // Legacy transaction
                if !crate::rlp::is_list(raw) {
                    return Err(ParseError::assembly_failed("not a valid RLP list"));
                }
                Self::assemble_legacy(raw, raw, &sig, None)
            }
            Some(0x00) => {
                // Typed legacy (type 0)
                let payload = typed_tx_payload(raw)?;
                Self::assemble_legacy(raw, payload, &sig, None)
            }
            Some(0x01) => {
                // EIP-2930
                let payload = typed_tx_payload(raw)?;
                Self::assemble_eip2930(payload, &sig)
            }
            Some(0x02) => {
                // EIP-1559
                let payload = typed_tx_payload(raw)?;
                Self::assemble_eip1559(payload, &sig)
            }
            Some(ty) => Err(ParseError::assembly_failed(format!(
                "unsupported transaction type: 0x{ty:02x}"
            ))),
        }
    }

    /// Assemble a signed legacy transaction.
    fn assemble_legacy(
        _raw: &[u8],
        rlp_payload: &[u8],
        sig: &alloy_primitives::Signature,
        _type_prefix: Option<u8>,
    ) -> Result<Vec<u8>, ParseError> {
        use alloy_consensus::transaction::RlpEcdsaEncodableTx;
        use alloy_consensus::TxLegacy;
        use alloy_primitives::{Bytes, TxKind};

        let items = decode_list(rlp_payload)?;

        // Accept 6 (unsigned pre-EIP-155) or 9 (signed / unsigned EIP-155)
        if items.len() != 6 && items.len() != 9 {
            return Err(ParseError::assembly_failed(format!(
                "legacy tx expected 6 or 9 items, got {}",
                items.len()
            )));
        }

        let nonce = decode_u64(
            items
                .first()
                .ok_or_else(|| ParseError::assembly_failed("missing nonce"))?,
        )?;

        let gas_price_u256 = decode_u256(
            items
                .get(1)
                .ok_or_else(|| ParseError::assembly_failed("missing gasPrice"))?,
        )?;
        let gas_price: u128 = gas_price_u256
            .try_into()
            .map_err(|_| ParseError::assembly_failed("gasPrice overflow"))?;

        let gas_limit = decode_u64(
            items
                .get(2)
                .ok_or_else(|| ParseError::assembly_failed("missing gasLimit"))?,
        )?;

        let to_addr = decode_optional_address(
            items
                .get(3)
                .ok_or_else(|| ParseError::assembly_failed("missing to"))?,
        )?;

        let value = decode_u256(
            items
                .get(4)
                .ok_or_else(|| ParseError::assembly_failed("missing value"))?,
        )?;

        let data = decode_bytes(
            items
                .get(5)
                .ok_or_else(|| ParseError::assembly_failed("missing data"))?,
        )?;

        // Extract chain_id
        let chain_id = if items.len() == 9 {
            let v = decode_u64(
                items
                    .get(6)
                    .ok_or_else(|| ParseError::assembly_failed("missing v"))?,
            )?;
            if v >= 35 {
                Some((v - 35) / 2)
            } else if v == 27 || v == 28 {
                None // pre-EIP-155
            } else {
                // EIP-155 unsigned: v == chain_id
                Some(v)
            }
        } else {
            None // 6-item unsigned: no chain_id
        };

        let tx = TxLegacy {
            chain_id,
            nonce,
            gas_price,
            gas_limit,
            to: to_addr.map_or(TxKind::Create, TxKind::Call),
            value,
            input: Bytes::from(data),
        };

        let mut buf = Vec::new();
        tx.rlp_encode_signed(sig, &mut buf);
        Ok(buf)
    }

    /// Assemble a signed EIP-2930 transaction.
    fn assemble_eip2930(
        payload: &[u8],
        sig: &alloy_primitives::Signature,
    ) -> Result<Vec<u8>, ParseError> {
        use alloy_consensus::transaction::RlpEcdsaEncodableTx;
        use alloy_consensus::TxEip2930;
        use alloy_eips::eip2930::AccessList;
        use alloy_primitives::{Bytes, TxKind};
        use alloy_rlp::Decodable;

        let items = decode_list(payload)?;

        // Accept 8 (unsigned) or 11 (signed)
        if items.len() != 8 && items.len() != 11 {
            return Err(ParseError::assembly_failed(format!(
                "EIP-2930 tx expected 8 or 11 items, got {}",
                items.len()
            )));
        }

        let chain_id = decode_u64(
            items
                .first()
                .ok_or_else(|| ParseError::assembly_failed("missing chainId"))?,
        )?;

        let nonce = decode_u64(
            items
                .get(1)
                .ok_or_else(|| ParseError::assembly_failed("missing nonce"))?,
        )?;

        let gas_price_u256 = decode_u256(
            items
                .get(2)
                .ok_or_else(|| ParseError::assembly_failed("missing gasPrice"))?,
        )?;
        let gas_price: u128 = gas_price_u256
            .try_into()
            .map_err(|_| ParseError::assembly_failed("gasPrice overflow"))?;

        let gas_limit = decode_u64(
            items
                .get(3)
                .ok_or_else(|| ParseError::assembly_failed("missing gasLimit"))?,
        )?;

        let to_addr = decode_optional_address(
            items
                .get(4)
                .ok_or_else(|| ParseError::assembly_failed("missing to"))?,
        )?;

        let value = decode_u256(
            items
                .get(5)
                .ok_or_else(|| ParseError::assembly_failed("missing value"))?,
        )?;

        let data = decode_bytes(
            items
                .get(6)
                .ok_or_else(|| ParseError::assembly_failed("missing data"))?,
        )?;

        let access_list_bytes = items
            .get(7)
            .ok_or_else(|| ParseError::assembly_failed("missing accessList"))?;
        let mut access_list_buf = *access_list_bytes;
        let access_list = AccessList::decode(&mut access_list_buf).map_err(|e| {
            ParseError::assembly_failed(format!("failed to decode access list: {e}"))
        })?;

        let tx = TxEip2930 {
            chain_id,
            nonce,
            gas_price,
            gas_limit,
            to: to_addr.map_or(TxKind::Create, TxKind::Call),
            value,
            input: Bytes::from(data),
            access_list,
        };

        let mut buf = vec![0x01]; // EIP-2930 type prefix
        tx.rlp_encode_signed(sig, &mut buf);
        Ok(buf)
    }

    /// Assemble a signed EIP-1559 transaction.
    fn assemble_eip1559(
        payload: &[u8],
        sig: &alloy_primitives::Signature,
    ) -> Result<Vec<u8>, ParseError> {
        use alloy_consensus::transaction::RlpEcdsaEncodableTx;
        use alloy_consensus::TxEip1559;
        use alloy_eips::eip2930::AccessList;
        use alloy_primitives::{Bytes, TxKind};
        use alloy_rlp::Decodable;

        let items = decode_list(payload)?;

        // Accept 9 (unsigned) or 12 (signed)
        if items.len() != 9 && items.len() != 12 {
            return Err(ParseError::assembly_failed(format!(
                "EIP-1559 tx expected 9 or 12 items, got {}",
                items.len()
            )));
        }

        let chain_id = decode_u64(
            items
                .first()
                .ok_or_else(|| ParseError::assembly_failed("missing chainId"))?,
        )?;

        let nonce = decode_u64(
            items
                .get(1)
                .ok_or_else(|| ParseError::assembly_failed("missing nonce"))?,
        )?;

        let max_priority_fee_u256 = decode_u256(
            items
                .get(2)
                .ok_or_else(|| ParseError::assembly_failed("missing maxPriorityFeePerGas"))?,
        )?;
        let max_priority_fee_per_gas: u128 = max_priority_fee_u256
            .try_into()
            .map_err(|_| ParseError::assembly_failed("maxPriorityFeePerGas overflow"))?;

        let max_fee_u256 = decode_u256(
            items
                .get(3)
                .ok_or_else(|| ParseError::assembly_failed("missing maxFeePerGas"))?,
        )?;
        let max_fee_per_gas: u128 = max_fee_u256
            .try_into()
            .map_err(|_| ParseError::assembly_failed("maxFeePerGas overflow"))?;

        let gas_limit = decode_u64(
            items
                .get(4)
                .ok_or_else(|| ParseError::assembly_failed("missing gasLimit"))?,
        )?;

        let to_addr = decode_optional_address(
            items
                .get(5)
                .ok_or_else(|| ParseError::assembly_failed("missing to"))?,
        )?;

        let value = decode_u256(
            items
                .get(6)
                .ok_or_else(|| ParseError::assembly_failed("missing value"))?,
        )?;

        let data = decode_bytes(
            items
                .get(7)
                .ok_or_else(|| ParseError::assembly_failed("missing data"))?,
        )?;

        let access_list_bytes = items
            .get(8)
            .ok_or_else(|| ParseError::assembly_failed("missing accessList"))?;
        let mut access_list_buf = *access_list_bytes;
        let access_list = AccessList::decode(&mut access_list_buf).map_err(|e| {
            ParseError::assembly_failed(format!("failed to decode access list: {e}"))
        })?;

        let tx = TxEip1559 {
            chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            to: to_addr.map_or(TxKind::Create, TxKind::Call),
            value,
            input: Bytes::from(data),
            access_list,
        };

        let mut buf = vec![0x02]; // EIP-1559 type prefix
        tx.rlp_encode_signed(sig, &mut buf);
        Ok(buf)
    }
}

/// Information extracted from an ERC-20 function call.
///
/// Used internally to enrich `ParsedTx` with token-specific data.
struct Erc20Info {
    /// The transaction type (`TokenTransfer` or `TokenApproval`).
    tx_type: TxType,
    /// The token contract address.
    token_address: Address,
    /// The actual recipient/spender address from the ERC-20 call.
    recipient: Address,
    /// The token amount from the ERC-20 call.
    amount: U256,
}

impl Chain for EthereumParser {
    /// Returns the chain identifier.
    ///
    /// # Returns
    ///
    /// Always returns `"ethereum"`.
    fn id(&self) -> &'static str {
        "ethereum"
    }

    /// Parse raw transaction bytes into a [`ParsedTx`].
    ///
    /// This method detects the transaction type and delegates to the
    /// appropriate parser:
    ///
    /// - Legacy transactions (no type prefix or type 0)
    /// - EIP-2930 transactions (type 1)
    /// - EIP-1559 transactions (type 2)
    ///
    /// # Arguments
    ///
    /// * `raw` - The raw transaction bytes
    ///
    /// # Returns
    ///
    /// * `Ok(ParsedTx)` - Successfully parsed transaction
    /// * `Err(ParseError)` - Parsing failed
    ///
    /// # Errors
    ///
    /// Returns a [`ParseError`] if:
    /// - The transaction type is not supported
    /// - The RLP encoding is invalid
    /// - Required fields are missing or malformed
    fn parse(&self, raw: &[u8]) -> Result<ParsedTx, ParseError> {
        if raw.is_empty() {
            return Err(ParseError::MalformedTransaction {
                context: "empty transaction data".to_string(),
            });
        }

        // Detect transaction type
        match detect_tx_type(raw) {
            None => {
                // Legacy transaction (starts with RLP list prefix 0xc0-0xff)
                // or potentially invalid data
                if crate::rlp::is_list(raw) {
                    Self::parse_legacy(raw)
                } else {
                    Err(ParseError::MalformedTransaction {
                        context:
                            "invalid transaction format: not a valid RLP list or typed transaction"
                                .to_string(),
                    })
                }
            }
            Some(0) => {
                // Type 0 - treat as legacy but skip the type byte for RLP parsing
                // Hash must be computed over full raw bytes including type prefix
                let payload = typed_tx_payload(raw)?;
                Self::parse_legacy_with_hash_source(raw, payload)
            }
            Some(1) => {
                // EIP-2930 (Access List)
                let payload = typed_tx_payload(raw)?;
                Self::parse_eip2930(raw, payload)
            }
            Some(2) => {
                // EIP-1559 (Dynamic Fee)
                let payload = typed_tx_payload(raw)?;
                Self::parse_eip1559(raw, payload)
            }
            Some(_) => Err(ParseError::UnknownTxType),
        }
    }

    /// Returns the elliptic curve used by Ethereum.
    ///
    /// # Returns
    ///
    /// Always returns [`CurveType::Secp256k1`].
    fn curve(&self) -> CurveType {
        CurveType::Secp256k1
    }

    /// Check if this parser supports a specific transaction version.
    ///
    /// # Arguments
    ///
    /// * `version` - The transaction type byte
    ///
    /// # Returns
    ///
    /// * `true` for versions 0, 1, 2 (Legacy, EIP-2930, EIP-1559)
    /// * `false` for other versions (e.g., EIP-4844 blob transactions)
    fn supports_version(&self, version: u8) -> bool {
        matches!(version, 0..=2)
    }

    fn assemble_signed(&self, raw: &[u8], signature: &[u8]) -> Result<Vec<u8>, ParseError> {
        Self::assemble_signed(raw, signature)
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
        clippy::indexing_slicing,
        clippy::similar_names,
        clippy::redundant_clone,
        clippy::manual_string_new,
        clippy::needless_raw_string_hashes,
        clippy::needless_collect,
        clippy::unreadable_literal,
        clippy::default_trait_access,
        clippy::too_many_arguments,
        clippy::default_constructed_unit_structs
    )]

    use super::*;
    use alloy_consensus::{transaction::RlpEcdsaEncodableTx, TxEip1559, TxEip2930, TxLegacy};
    use alloy_primitives::{hex, Address, Bytes, Signature, TxKind};

    /// Helper to encode a legacy transaction with a fake signature
    fn encode_legacy_tx(
        nonce: u64,
        gas_price: u128,
        gas_limit: u64,
        to: Option<Address>,
        value: U256,
        data: Bytes,
        chain_id: Option<u64>,
    ) -> Vec<u8> {
        let tx = TxLegacy {
            chain_id,
            nonce,
            gas_price,
            gas_limit,
            to: to.map_or(TxKind::Create, TxKind::Call),
            value,
            input: data,
        };

        // Create a fake signature
        let sig = Signature::new(
            U256::from(0xffff_ffff_ffff_ffffu64),
            U256::from(0xffff_ffff_ffff_ffffu64),
            false,
        );

        let mut buf = Vec::new();
        tx.rlp_encode_signed(&sig, &mut buf);
        buf
    }

    /// Helper to encode an EIP-2930 transaction with a fake signature
    fn encode_eip2930_tx(
        chain_id: u64,
        nonce: u64,
        gas_price: u128,
        gas_limit: u64,
        to: Option<Address>,
        value: U256,
        data: Bytes,
    ) -> Vec<u8> {
        let tx = TxEip2930 {
            chain_id,
            nonce,
            gas_price,
            gas_limit,
            to: to.map_or(TxKind::Create, TxKind::Call),
            value,
            input: data,
            access_list: Default::default(),
        };

        // Create a fake signature
        let sig = Signature::new(
            U256::from(0xffff_ffff_ffff_ffffu64),
            U256::from(0xffff_ffff_ffff_ffffu64),
            false,
        );

        // Build buffer with type prefix
        let mut buf = Vec::new();
        buf.push(0x01); // EIP-2930 type prefix
        tx.rlp_encode_signed(&sig, &mut buf);
        buf
    }

    /// Helper to encode an EIP-1559 transaction with a fake signature
    fn encode_eip1559_tx(
        chain_id: u64,
        nonce: u64,
        max_priority_fee_per_gas: u128,
        max_fee_per_gas: u128,
        gas_limit: u64,
        to: Option<Address>,
        value: U256,
        data: Bytes,
    ) -> Vec<u8> {
        let tx = TxEip1559 {
            chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            to: to.map_or(TxKind::Create, TxKind::Call),
            value,
            input: data,
            access_list: Default::default(),
        };

        // Create a fake signature
        let sig = Signature::new(
            U256::from(0xffff_ffff_ffff_ffffu64),
            U256::from(0xffff_ffff_ffff_ffffu64),
            false,
        );

        // Build buffer with type prefix
        let mut buf = Vec::new();
        buf.push(0x02); // EIP-1559 type prefix
        tx.rlp_encode_signed(&sig, &mut buf);
        buf
    }

    // ------------------------------------------------------------------------
    // Constructor and Basic Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_ethereum_parser_new() {
        let parser = EthereumParser::new();
        assert_eq!(parser.id(), "ethereum");
    }

    #[test]
    fn test_ethereum_parser_default() {
        let parser = EthereumParser::default();
        assert_eq!(parser.id(), "ethereum");
    }

    #[test]
    fn test_ethereum_parser_clone() {
        let parser = EthereumParser::new();
        let cloned = parser;
        assert_eq!(cloned.id(), "ethereum");
    }

    #[test]
    fn test_ethereum_parser_debug() {
        let parser = EthereumParser::new();
        let debug_str = format!("{parser:?}");
        assert!(debug_str.contains("EthereumParser"));
    }

    // ------------------------------------------------------------------------
    // Chain Trait Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_chain_id() {
        let parser = EthereumParser::new();
        assert_eq!(parser.id(), "ethereum");
    }

    #[test]
    fn test_chain_curve() {
        let parser = EthereumParser::new();
        assert_eq!(parser.curve(), CurveType::Secp256k1);
    }

    #[test]
    fn test_supports_version() {
        let parser = EthereumParser::new();

        // Supported versions
        assert!(parser.supports_version(0)); // Legacy
        assert!(parser.supports_version(1)); // EIP-2930
        assert!(parser.supports_version(2)); // EIP-1559

        // Unsupported versions
        assert!(!parser.supports_version(3)); // EIP-4844 (blobs)
        assert!(!parser.supports_version(4));
        assert!(!parser.supports_version(255));
    }

    // ------------------------------------------------------------------------
    // Empty Input Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_parse_empty_input() {
        let parser = EthereumParser::new();
        let result = parser.parse(&[]);

        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(ParseError::MalformedTransaction { .. })
        ));
    }

    // ------------------------------------------------------------------------
    // Legacy Transaction Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_parse_legacy_transaction() {
        let parser = EthereumParser::new();

        // Real legacy transaction from Ethereum mainnet
        // This is a simple ETH transfer
        // nonce=9, gasPrice=20gwei, gasLimit=21000, to=0x3535..., value=1ETH, data=empty
        let raw = hex::decode(
            "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83"
        ).expect("valid hex");

        let result = parser.parse(&raw);
        assert!(result.is_ok(), "parsing failed: {result:?}");

        let parsed = result.expect("should parse successfully");

        // Verify fields
        assert_eq!(parsed.chain, "ethereum");
        assert_eq!(parsed.nonce, Some(9));
        assert_eq!(parsed.tx_type, TxType::Transfer);
        assert!(parsed.recipient.is_some());
        assert_eq!(
            parsed.recipient.as_ref().map(|s| s.to_lowercase()),
            Some("0x3535353535353535353535353535353535353535".to_string())
        );

        // Verify amount is 1 ETH (10^18 wei)
        let expected_amount = U256::from(1_000_000_000_000_000_000u64);
        assert_eq!(parsed.amount, Some(expected_amount));

        // Verify chain_id extraction from v=37 -> chain_id = (37-35)/2 = 1
        assert_eq!(parsed.chain_id, Some(1));

        // Verify hash is computed
        assert_ne!(parsed.hash, [0u8; 32]);
    }

    #[test]
    fn test_parse_legacy_transaction_pre_eip155() {
        let parser = EthereumParser::new();

        // Legacy transaction without chain_id (pre-EIP-155)
        let to_addr = Address::from([0x12; 20]);
        let raw = encode_legacy_tx(
            0,                // nonce
            1_000_000_000,    // gas_price (1 gwei)
            21000,            // gas_limit
            Some(to_addr),    // to
            U256::ZERO,       // value
            Bytes::default(), // data
            None,             // chain_id (None = pre-EIP-155)
        );

        let result = parser.parse(&raw);
        assert!(result.is_ok(), "parsing failed: {result:?}");

        let parsed = result.expect("should parse successfully");
        // Pre-EIP-155 defaults to mainnet (chain_id = 1)
        assert_eq!(parsed.chain_id, Some(1));
    }

    #[test]
    fn test_parse_legacy_contract_deployment() {
        let parser = EthereumParser::new();

        // Contract deployment: to field is None (Create)
        let raw = encode_legacy_tx(
            0,                                         // nonce
            1_000_000_000,                             // gas_price
            100000,                                    // gas_limit
            None,                                      // to = None for deployment
            U256::ZERO,                                // value
            Bytes::from(vec![0x60, 0x80, 0x60, 0x40]), // data (some bytecode)
            Some(1),                                   // chain_id
        );

        let result = parser.parse(&raw);
        assert!(result.is_ok(), "parsing failed: {result:?}");

        let parsed = result.expect("should parse successfully");
        assert_eq!(parsed.tx_type, TxType::Deployment);
        assert!(parsed.recipient.is_none());
    }

    #[test]
    fn test_parse_legacy_contract_call() {
        let parser = EthereumParser::new();

        // Contract call: has recipient and non-empty data
        let to_addr = Address::from([0x12; 20]);
        let raw = encode_legacy_tx(
            1,                                         // nonce
            1_000_000_000,                             // gas_price
            100000,                                    // gas_limit
            Some(to_addr),                             // to
            U256::ZERO,                                // value
            Bytes::from(vec![0xa9, 0x05, 0x9c, 0xbb]), // data (transfer selector)
            Some(1),                                   // chain_id
        );

        let result = parser.parse(&raw);
        assert!(result.is_ok(), "parsing failed: {result:?}");

        let parsed = result.expect("should parse successfully");
        assert_eq!(parsed.tx_type, TxType::ContractCall);
        assert!(parsed.recipient.is_some());
    }

    // ------------------------------------------------------------------------
    // EIP-2930 Transaction Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_parse_eip2930_transaction() {
        let parser = EthereumParser::new();

        // EIP-2930 transaction (type 1)
        let to_addr = Address::from([0x12; 20]);
        let raw = encode_eip2930_tx(
            1,                // chain_id
            0,                // nonce
            1_000_000_000,    // gas_price
            21000,            // gas_limit
            Some(to_addr),    // to
            U256::ZERO,       // value
            Bytes::default(), // data
        );

        let result = parser.parse(&raw);
        assert!(result.is_ok(), "parsing failed: {result:?}");

        let parsed = result.expect("should parse successfully");

        assert_eq!(parsed.chain, "ethereum");
        assert_eq!(parsed.chain_id, Some(1));
        assert_eq!(parsed.nonce, Some(0));
        assert_eq!(parsed.tx_type, TxType::Transfer);
        assert!(parsed.recipient.is_some());
    }

    #[test]
    fn test_parse_eip2930_contract_deployment() {
        let parser = EthereumParser::new();

        // EIP-2930 contract deployment (to=None)
        let raw = encode_eip2930_tx(
            1,                                         // chain_id
            0,                                         // nonce
            1_000_000_000,                             // gas_price
            100000,                                    // gas_limit
            None,                                      // to = None for deployment
            U256::ZERO,                                // value
            Bytes::from(vec![0x60, 0x80, 0x60, 0x40]), // data
        );

        let result = parser.parse(&raw);
        assert!(result.is_ok(), "parsing failed: {result:?}");

        let parsed = result.expect("should parse successfully");
        assert_eq!(parsed.tx_type, TxType::Deployment);
        assert!(parsed.recipient.is_none());
    }

    // ------------------------------------------------------------------------
    // EIP-1559 Transaction Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_parse_eip1559_transaction() {
        let parser = EthereumParser::new();

        // EIP-1559 transaction (type 2)
        let to_addr = Address::from([0x12; 20]);
        let raw = encode_eip1559_tx(
            1,                // chain_id
            0,                // nonce
            1_000_000_000,    // max_priority_fee_per_gas
            2_000_000_000,    // max_fee_per_gas
            21000,            // gas_limit
            Some(to_addr),    // to
            U256::ZERO,       // value
            Bytes::default(), // data
        );

        let result = parser.parse(&raw);
        assert!(result.is_ok(), "parsing failed: {result:?}");

        let parsed = result.expect("should parse successfully");

        assert_eq!(parsed.chain, "ethereum");
        assert_eq!(parsed.chain_id, Some(1));
        assert_eq!(parsed.nonce, Some(0));
        assert_eq!(parsed.tx_type, TxType::Transfer);
        assert!(parsed.recipient.is_some());
    }

    #[test]
    fn test_parse_eip1559_with_value() {
        let parser = EthereumParser::new();

        // EIP-1559 transaction with value
        let to_addr = Address::from([0x12; 20]);
        let value = U256::from(1_000_000_000_000_000_000u64); // 1 ETH
        let raw = encode_eip1559_tx(
            1,                // chain_id
            5,                // nonce
            1_000_000_000,    // max_priority_fee_per_gas
            100_000_000_000,  // max_fee_per_gas
            21000,            // gas_limit
            Some(to_addr),    // to
            value,            // value
            Bytes::default(), // data
        );

        let result = parser.parse(&raw);
        assert!(result.is_ok(), "parsing failed: {result:?}");

        let parsed = result.expect("should parse successfully");

        assert_eq!(parsed.chain, "ethereum");
        assert_eq!(parsed.chain_id, Some(1));
        assert_eq!(parsed.nonce, Some(5));
        assert_eq!(parsed.tx_type, TxType::Transfer);
        assert_eq!(parsed.amount, Some(value));
    }

    #[test]
    fn test_parse_eip1559_contract_deployment() {
        let parser = EthereumParser::new();

        // EIP-1559 contract deployment (to=None)
        let raw = encode_eip1559_tx(
            1,                                         // chain_id
            0,                                         // nonce
            1_000_000_000,                             // max_priority_fee_per_gas
            2_000_000_000,                             // max_fee_per_gas
            100000,                                    // gas_limit
            None,                                      // to = None for deployment
            U256::ZERO,                                // value
            Bytes::from(vec![0x60, 0x80, 0x60, 0x40]), // data
        );

        let result = parser.parse(&raw);
        assert!(result.is_ok(), "parsing failed: {result:?}");

        let parsed = result.expect("should parse successfully");
        assert_eq!(parsed.tx_type, TxType::Deployment);
        assert!(parsed.recipient.is_none());
    }

    #[test]
    fn test_parse_eip1559_contract_call() {
        let parser = EthereumParser::new();

        // EIP-1559 contract call (has data)
        let to_addr = Address::from([0x12; 20]);
        let raw = encode_eip1559_tx(
            1,                                         // chain_id
            0,                                         // nonce
            1_000_000_000,                             // max_priority_fee_per_gas
            2_000_000_000,                             // max_fee_per_gas
            100000,                                    // gas_limit
            Some(to_addr),                             // to
            U256::ZERO,                                // value
            Bytes::from(vec![0xa9, 0x05, 0x9c, 0xbb]), // data (transfer selector)
        );

        let result = parser.parse(&raw);
        assert!(result.is_ok(), "parsing failed: {result:?}");

        let parsed = result.expect("should parse successfully");
        assert_eq!(parsed.tx_type, TxType::ContractCall);
        assert!(parsed.recipient.is_some());
    }

    // ------------------------------------------------------------------------
    // Hash Computation Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_hash_is_correctly_computed() {
        let parser = EthereumParser::new();

        let raw = hex::decode(
            "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83"
        ).expect("valid hex");

        let result = parser.parse(&raw);
        assert!(result.is_ok());

        let parsed = result.expect("should parse");

        // Compute expected hash
        let expected_hash = keccak256(&raw);

        assert_eq!(parsed.hash, *expected_hash);
    }

    #[test]
    fn test_eip1559_hash_includes_type_prefix() {
        let parser = EthereumParser::new();

        let to_addr = Address::from([0x12; 20]);
        let raw = encode_eip1559_tx(
            1,                // chain_id
            0,                // nonce
            1_000_000_000,    // max_priority_fee_per_gas
            2_000_000_000,    // max_fee_per_gas
            21000,            // gas_limit
            Some(to_addr),    // to
            U256::ZERO,       // value
            Bytes::default(), // data
        );

        let result = parser.parse(&raw);
        assert!(result.is_ok());

        let parsed = result.expect("should parse");

        // Hash should be of the entire raw bytes (including type prefix)
        let expected_hash = keccak256(&raw);
        assert_eq!(parsed.hash, *expected_hash);
    }

    #[test]
    fn test_type0_hash_includes_type_prefix() {
        let parser = EthereumParser::new();

        // Create a legacy transaction and then prefix it with 0x00 (type 0)
        let to_addr = Address::from([0x12; 20]);
        let legacy_raw = encode_legacy_tx(
            0,                // nonce
            1_000_000_000,    // gas_price (1 gwei)
            21000,            // gas_limit
            Some(to_addr),    // to
            U256::ZERO,       // value
            Bytes::default(), // data
            Some(1),          // chain_id
        );

        // Create type 0 transaction by prefixing with 0x00
        let mut type0_raw = vec![0x00];
        type0_raw.extend_from_slice(&legacy_raw);

        let result = parser.parse(&type0_raw);
        assert!(result.is_ok(), "parsing failed: {result:?}");

        let parsed = result.expect("should parse");

        // Hash MUST be computed over the full raw bytes INCLUDING the type prefix
        let expected_hash = keccak256(&type0_raw);
        assert_eq!(
            parsed.hash, *expected_hash,
            "type 0 hash should include type prefix"
        );

        // Verify it's NOT the hash of just the payload (without type byte)
        let wrong_hash = keccak256(&legacy_raw);
        assert_ne!(
            parsed.hash, *wrong_hash,
            "hash should NOT be computed without type prefix"
        );
    }

    #[test]
    fn test_type0_vs_legacy_same_content_different_hash() {
        let parser = EthereumParser::new();

        // Create a legacy transaction
        let to_addr = Address::from([0x12; 20]);
        let legacy_raw = encode_legacy_tx(
            5,                                        // nonce
            2_000_000_000,                            // gas_price (2 gwei)
            21000,                                    // gas_limit
            Some(to_addr),                            // to
            U256::from(1_000_000_000_000_000_000u64), // 1 ETH
            Bytes::default(),                         // data
            Some(1),                                  // chain_id
        );

        // Parse as pure legacy (no type prefix)
        let legacy_result = parser.parse(&legacy_raw);
        assert!(legacy_result.is_ok());
        let legacy_parsed = legacy_result.expect("should parse legacy");

        // Create type 0 version (same content, with 0x00 prefix)
        let mut type0_raw = vec![0x00];
        type0_raw.extend_from_slice(&legacy_raw);

        // Parse as type 0
        let type0_result = parser.parse(&type0_raw);
        assert!(type0_result.is_ok());
        let type0_parsed = type0_result.expect("should parse type 0");

        // Both should have the same transaction data
        assert_eq!(legacy_parsed.nonce, type0_parsed.nonce);
        assert_eq!(legacy_parsed.recipient, type0_parsed.recipient);
        assert_eq!(legacy_parsed.amount, type0_parsed.amount);
        assert_eq!(legacy_parsed.chain_id, type0_parsed.chain_id);

        // But the hashes MUST be different because type 0 includes the prefix
        assert_ne!(
            legacy_parsed.hash, type0_parsed.hash,
            "legacy and type 0 hashes should differ due to type prefix"
        );
    }

    // ------------------------------------------------------------------------
    // Error Handling Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_parse_unsupported_tx_type() {
        let parser = EthereumParser::new();

        // Type 3 (EIP-4844 blob tx) - not supported
        let raw = hex::decode("03f8c0").expect("valid hex");

        let result = parser.parse(&raw);
        assert!(result.is_err());
        assert!(matches!(result, Err(ParseError::UnknownTxType)));
    }

    #[test]
    fn test_parse_malformed_legacy_too_few_items() {
        let parser = EthereumParser::new();

        // List with only 3 items instead of 9
        let raw = hex::decode("c3010203").expect("valid hex");

        let result = parser.parse(&raw);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(ParseError::MalformedTransaction { .. })
        ));
    }

    #[test]
    fn test_parse_invalid_rlp() {
        let parser = EthereumParser::new();

        // Invalid RLP (claims to be a list but truncated)
        let raw = hex::decode("f8ff").expect("valid hex");

        let result = parser.parse(&raw);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_not_list_not_typed() {
        let parser = EthereumParser::new();

        // Single byte that's not a valid type prefix (0x04-0xbf range)
        // and not an RLP list (0xc0+)
        let raw = hex::decode("80").expect("valid hex");

        let result = parser.parse(&raw);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(ParseError::MalformedTransaction { .. })
        ));
    }

    // ------------------------------------------------------------------------
    // Different Chain IDs Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_parse_eip1559_polygon() {
        let parser = EthereumParser::new();

        // EIP-1559 on Polygon (chainId=137)
        let to_addr = Address::from([0x12; 20]);
        let raw = encode_eip1559_tx(
            137,              // chain_id (Polygon)
            0,                // nonce
            1_000_000_000,    // max_priority_fee_per_gas
            2_000_000_000,    // max_fee_per_gas
            21000,            // gas_limit
            Some(to_addr),    // to
            U256::ZERO,       // value
            Bytes::default(), // data
        );

        let result = parser.parse(&raw);
        assert!(result.is_ok(), "parsing failed: {result:?}");

        let parsed = result.expect("should parse");
        assert_eq!(parsed.chain_id, Some(137));
    }

    #[test]
    fn test_parse_legacy_with_high_chain_id() {
        let parser = EthereumParser::new();

        // Legacy transaction with BSC chain_id (56)
        let to_addr = Address::from([0x12; 20]);
        let raw = encode_legacy_tx(
            9,                                        // nonce
            20_000_000_000,                           // gas_price (20 gwei)
            21000,                                    // gas_limit
            Some(to_addr),                            // to
            U256::from(1_000_000_000_000_000_000u64), // value (1 ETH equivalent)
            Bytes::default(),                         // data
            Some(56),                                 // chain_id (BSC)
        );

        let result = parser.parse(&raw);
        assert!(result.is_ok(), "parsing failed: {result:?}");

        let parsed = result.expect("should parse");
        assert_eq!(parsed.chain_id, Some(56));
    }

    // ------------------------------------------------------------------------
    // Thread Safety Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_parser_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<EthereumParser>();
    }

    #[test]
    fn test_parser_is_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<EthereumParser>();
    }

    // ------------------------------------------------------------------------
    // Integration with Chain Registry
    // ------------------------------------------------------------------------

    #[test]
    fn test_parser_as_trait_object() {
        let parser = EthereumParser::new();
        let chain: Box<dyn Chain> = Box::new(parser);

        assert_eq!(chain.id(), "ethereum");
        assert_eq!(chain.curve(), CurveType::Secp256k1);
        assert!(chain.supports_version(0));
        assert!(chain.supports_version(1));
        assert!(chain.supports_version(2));
    }

    // ------------------------------------------------------------------------
    // ERC-20 Detection Integration Tests
    // ------------------------------------------------------------------------

    /// Helper to create ERC-20 transfer calldata
    fn erc20_transfer_calldata(to: Address, amount: U256) -> Bytes {
        let mut data = vec![0xa9, 0x05, 0x9c, 0xbb]; // transfer selector
                                                     // Address (32 bytes, left-padded)
        data.extend_from_slice(&[0u8; 12]);
        data.extend_from_slice(to.as_slice());
        // Amount (32 bytes, big-endian)
        data.extend_from_slice(&amount.to_be_bytes::<32>());
        Bytes::from(data)
    }

    /// Helper to create ERC-20 approve calldata
    fn erc20_approve_calldata(spender: Address, amount: U256) -> Bytes {
        let mut data = vec![0x09, 0x5e, 0xa7, 0xb3]; // approve selector
                                                     // Spender address (32 bytes, left-padded)
        data.extend_from_slice(&[0u8; 12]);
        data.extend_from_slice(spender.as_slice());
        // Amount (32 bytes, big-endian)
        data.extend_from_slice(&amount.to_be_bytes::<32>());
        Bytes::from(data)
    }

    /// Helper to create ERC-20 transferFrom calldata
    fn erc20_transfer_from_calldata(from: Address, to: Address, amount: U256) -> Bytes {
        let mut data = vec![0x23, 0xb8, 0x72, 0xdd]; // transferFrom selector
                                                     // From address (32 bytes, left-padded)
        data.extend_from_slice(&[0u8; 12]);
        data.extend_from_slice(from.as_slice());
        // To address (32 bytes, left-padded)
        data.extend_from_slice(&[0u8; 12]);
        data.extend_from_slice(to.as_slice());
        // Amount (32 bytes, big-endian)
        data.extend_from_slice(&amount.to_be_bytes::<32>());
        Bytes::from(data)
    }

    #[test]
    fn test_erc20_transfer_detection_eip1559() {
        let parser = EthereumParser::new();

        let token_contract = Address::from([0xaa; 20]); // Token contract address
        let recipient = Address::from([0xbb; 20]); // Actual recipient
        let token_amount = U256::from(1_000_000u64); // 1 USDC (6 decimals)

        let calldata = erc20_transfer_calldata(recipient, token_amount);

        let raw = encode_eip1559_tx(
            1,                    // chain_id
            0,                    // nonce
            1_000_000_000,        // max_priority_fee_per_gas
            2_000_000_000,        // max_fee_per_gas
            100_000,              // gas_limit
            Some(token_contract), // to (token contract)
            U256::ZERO,           // value (no ETH sent)
            calldata,             // data (ERC-20 transfer)
        );

        let result = parser.parse(&raw);
        assert!(result.is_ok(), "parsing failed: {result:?}");

        let parsed = result.expect("should parse");

        // Should be detected as TokenTransfer
        assert_eq!(parsed.tx_type, TxType::TokenTransfer);

        // Recipient should be the actual token recipient, not the contract
        assert_eq!(parsed.recipient, Some(format!("{recipient}")));

        // Amount should be the token amount
        assert_eq!(parsed.amount, Some(token_amount));

        // Token address should be set
        assert_eq!(parsed.token_address, Some(format!("{token_contract}")));
    }

    #[test]
    fn test_erc20_approve_detection_eip1559() {
        let parser = EthereumParser::new();

        let token_contract = Address::from([0xaa; 20]);
        let spender = Address::from([0xcc; 20]); // Spender (e.g., DEX router)
        let approval_amount = U256::MAX; // Unlimited approval

        let calldata = erc20_approve_calldata(spender, approval_amount);

        let raw = encode_eip1559_tx(
            1,                    // chain_id
            1,                    // nonce
            1_000_000_000,        // max_priority_fee_per_gas
            2_000_000_000,        // max_fee_per_gas
            60_000,               // gas_limit
            Some(token_contract), // to (token contract)
            U256::ZERO,           // value
            calldata,             // data (ERC-20 approve)
        );

        let result = parser.parse(&raw);
        assert!(result.is_ok(), "parsing failed: {result:?}");

        let parsed = result.expect("should parse");

        // Should be detected as TokenApproval
        assert_eq!(parsed.tx_type, TxType::TokenApproval);

        // Recipient should be the spender
        assert_eq!(parsed.recipient, Some(format!("{spender}")));

        // Amount should be the approval amount
        assert_eq!(parsed.amount, Some(approval_amount));

        // Token address should be set
        assert_eq!(parsed.token_address, Some(format!("{token_contract}")));
    }

    #[test]
    fn test_erc20_transfer_from_detection_eip1559() {
        let parser = EthereumParser::new();

        let token_contract = Address::from([0xaa; 20]);
        let from_addr = Address::from([0xdd; 20]); // Token owner
        let to_addr = Address::from([0xee; 20]); // Token recipient
        let token_amount = U256::from(500_000_000_000_000_000u64); // 0.5 tokens (18 decimals)

        let calldata = erc20_transfer_from_calldata(from_addr, to_addr, token_amount);

        let raw = encode_eip1559_tx(
            1,                    // chain_id
            2,                    // nonce
            1_000_000_000,        // max_priority_fee_per_gas
            2_000_000_000,        // max_fee_per_gas
            100_000,              // gas_limit
            Some(token_contract), // to (token contract)
            U256::ZERO,           // value
            calldata,             // data (ERC-20 transferFrom)
        );

        let result = parser.parse(&raw);
        assert!(result.is_ok(), "parsing failed: {result:?}");

        let parsed = result.expect("should parse");

        // Should be detected as TokenTransfer
        assert_eq!(parsed.tx_type, TxType::TokenTransfer);

        // Recipient should be the actual token recipient (to_addr)
        assert_eq!(parsed.recipient, Some(format!("{to_addr}")));

        // Amount should be the token amount
        assert_eq!(parsed.amount, Some(token_amount));

        // Token address should be set
        assert_eq!(parsed.token_address, Some(format!("{token_contract}")));
    }

    #[test]
    fn test_erc20_transfer_detection_legacy() {
        let parser = EthereumParser::new();

        let token_contract = Address::from([0xaa; 20]);
        let recipient = Address::from([0xbb; 20]);
        let token_amount = U256::from(2_000_000u64);

        let calldata = erc20_transfer_calldata(recipient, token_amount);

        let raw = encode_legacy_tx(
            5,                    // nonce
            20_000_000_000,       // gas_price (20 gwei)
            100_000,              // gas_limit
            Some(token_contract), // to (token contract)
            U256::ZERO,           // value
            calldata,             // data
            Some(1),              // chain_id
        );

        let result = parser.parse(&raw);
        assert!(result.is_ok(), "parsing failed: {result:?}");

        let parsed = result.expect("should parse");

        assert_eq!(parsed.tx_type, TxType::TokenTransfer);
        assert_eq!(parsed.recipient, Some(format!("{recipient}")));
        assert_eq!(parsed.amount, Some(token_amount));
        assert_eq!(parsed.token_address, Some(format!("{token_contract}")));
    }

    #[test]
    fn test_erc20_detection_eip2930() {
        let parser = EthereumParser::new();

        let token_contract = Address::from([0xaa; 20]);
        let spender = Address::from([0xcc; 20]);
        let approval_amount = U256::from(1_000_000_000_000u64);

        let calldata = erc20_approve_calldata(spender, approval_amount);

        let raw = encode_eip2930_tx(
            1,                    // chain_id
            3,                    // nonce
            10_000_000_000,       // gas_price
            80_000,               // gas_limit
            Some(token_contract), // to (token contract)
            U256::ZERO,           // value
            calldata,             // data
        );

        let result = parser.parse(&raw);
        assert!(result.is_ok(), "parsing failed: {result:?}");

        let parsed = result.expect("should parse");

        assert_eq!(parsed.tx_type, TxType::TokenApproval);
        assert_eq!(parsed.recipient, Some(format!("{spender}")));
        assert_eq!(parsed.amount, Some(approval_amount));
        assert_eq!(parsed.token_address, Some(format!("{token_contract}")));
    }

    #[test]
    fn test_non_erc20_contract_call_unchanged() {
        let parser = EthereumParser::new();

        let contract = Address::from([0x12; 20]);
        // Unknown function selector (not ERC-20)
        let calldata = Bytes::from(vec![0x12, 0x34, 0x56, 0x78, 0xab, 0xcd, 0xef, 0x00]);

        let raw = encode_eip1559_tx(
            1,              // chain_id
            0,              // nonce
            1_000_000_000,  // max_priority_fee_per_gas
            2_000_000_000,  // max_fee_per_gas
            100_000,        // gas_limit
            Some(contract), // to
            U256::ZERO,     // value
            calldata,       // data (not ERC-20)
        );

        let result = parser.parse(&raw);
        assert!(result.is_ok(), "parsing failed: {result:?}");

        let parsed = result.expect("should parse");

        // Should be a generic ContractCall
        assert_eq!(parsed.tx_type, TxType::ContractCall);

        // Recipient should be the contract address
        assert_eq!(parsed.recipient, Some(format!("{contract}")));

        // Token address should NOT be set
        assert!(parsed.token_address.is_none());
    }

    #[test]
    fn test_simple_eth_transfer_unchanged() {
        let parser = EthereumParser::new();

        let recipient = Address::from([0x12; 20]);
        let eth_amount = U256::from(1_000_000_000_000_000_000u64); // 1 ETH

        let raw = encode_eip1559_tx(
            1,                // chain_id
            0,                // nonce
            1_000_000_000,    // max_priority_fee_per_gas
            2_000_000_000,    // max_fee_per_gas
            21_000,           // gas_limit
            Some(recipient),  // to
            eth_amount,       // value
            Bytes::default(), // data (empty)
        );

        let result = parser.parse(&raw);
        assert!(result.is_ok(), "parsing failed: {result:?}");

        let parsed = result.expect("should parse");

        // Should be a simple Transfer
        assert_eq!(parsed.tx_type, TxType::Transfer);

        // Recipient should be the ETH recipient
        assert_eq!(parsed.recipient, Some(format!("{recipient}")));

        // Amount should be the ETH amount
        assert_eq!(parsed.amount, Some(eth_amount));

        // Token address should NOT be set (native transfer)
        assert!(parsed.token_address.is_none());
    }

    #[test]
    fn test_erc20_with_eth_value() {
        // Some exotic cases might send ETH value along with ERC-20 call
        // (e.g., WETH deposit with data, or payable token functions)
        let parser = EthereumParser::new();

        let token_contract = Address::from([0xaa; 20]);
        let recipient = Address::from([0xbb; 20]);
        let token_amount = U256::from(1_000_000u64);
        let eth_value = U256::from(100_000_000_000_000_000u64); // 0.1 ETH

        let calldata = erc20_transfer_calldata(recipient, token_amount);

        let raw = encode_eip1559_tx(
            1,                    // chain_id
            0,                    // nonce
            1_000_000_000,        // max_priority_fee_per_gas
            2_000_000_000,        // max_fee_per_gas
            100_000,              // gas_limit
            Some(token_contract), // to (token contract)
            eth_value,            // value (some ETH too!)
            calldata,             // data (ERC-20 transfer)
        );

        let result = parser.parse(&raw);
        assert!(result.is_ok(), "parsing failed: {result:?}");

        let parsed = result.expect("should parse");

        // Should still detect as TokenTransfer
        assert_eq!(parsed.tx_type, TxType::TokenTransfer);

        // Amount should be the token amount (not ETH value)
        assert_eq!(parsed.amount, Some(token_amount));

        // Token address should be set
        assert!(parsed.token_address.is_some());
    }

    #[test]
    fn test_erc20_zero_amount() {
        let parser = EthereumParser::new();

        let token_contract = Address::from([0xaa; 20]);
        let recipient = Address::from([0xbb; 20]);
        let token_amount = U256::ZERO;

        let calldata = erc20_transfer_calldata(recipient, token_amount);

        let raw = encode_eip1559_tx(
            1,                    // chain_id
            0,                    // nonce
            1_000_000_000,        // max_priority_fee_per_gas
            2_000_000_000,        // max_fee_per_gas
            60_000,               // gas_limit
            Some(token_contract), // to
            U256::ZERO,           // value
            calldata,             // data
        );

        let result = parser.parse(&raw);
        assert!(result.is_ok(), "parsing failed: {result:?}");

        let parsed = result.expect("should parse");

        // Should still be detected as TokenTransfer
        assert_eq!(parsed.tx_type, TxType::TokenTransfer);
        assert_eq!(parsed.amount, Some(U256::ZERO));
    }

    #[test]
    fn test_erc20_approve_zero_revoke() {
        // Approve with zero amount is a "revoke" pattern
        let parser = EthereumParser::new();

        let token_contract = Address::from([0xaa; 20]);
        let spender = Address::from([0xcc; 20]);
        let approval_amount = U256::ZERO; // Revoke approval

        let calldata = erc20_approve_calldata(spender, approval_amount);

        let raw = encode_eip1559_tx(
            1,                    // chain_id
            0,                    // nonce
            1_000_000_000,        // max_priority_fee_per_gas
            2_000_000_000,        // max_fee_per_gas
            50_000,               // gas_limit
            Some(token_contract), // to
            U256::ZERO,           // value
            calldata,             // data
        );

        let result = parser.parse(&raw);
        assert!(result.is_ok(), "parsing failed: {result:?}");

        let parsed = result.expect("should parse");

        // Should still be TokenApproval
        assert_eq!(parsed.tx_type, TxType::TokenApproval);
        assert_eq!(parsed.amount, Some(U256::ZERO));
    }

    // ------------------------------------------------------------------------
    // Missing Field Error Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_legacy_tx_truncated_data() {
        // Arrange: Create a truncated legacy transaction by encoding normally then truncating
        let parser = EthereumParser::new();

        // First create a valid legacy transaction
        let valid_raw = encode_legacy_tx(
            9,
            20_000_000_000,
            21000,
            Some(Address::from([0x35; 20])),
            U256::from(1_000_000_000_000_000_000u64),
            Bytes::new(),
            Some(1),
        );

        // Truncate it to simulate missing fields
        let truncated = &valid_raw[..valid_raw.len() / 2];

        // Act
        let result = parser.parse(truncated);

        // Assert: Should fail with InvalidRlp or MalformedTransaction
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(ParseError::InvalidRlp { .. } | ParseError::MalformedTransaction { .. })
        ));
    }

    #[test]
    fn test_eip1559_tx_truncated_data() {
        // Arrange: Create a truncated EIP-1559 transaction
        let parser = EthereumParser::new();

        // First create a valid EIP-1559 transaction
        let valid_raw = encode_eip1559_tx(
            1,                               // chain_id
            0,                               // nonce
            1_000_000_000,                   // max_priority_fee_per_gas
            2_000_000_000,                   // max_fee_per_gas
            21000,                           // gas_limit
            Some(Address::from([0x35; 20])), // to
            U256::ZERO,                      // value
            Bytes::new(),                    // data
        );

        // Truncate it to simulate missing fields
        let truncated = &valid_raw[..valid_raw.len() / 2];

        // Act
        let result = parser.parse(truncated);

        // Assert: Should fail with InvalidRlp or MalformedTransaction
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(ParseError::InvalidRlp { .. } | ParseError::MalformedTransaction { .. })
        ));
    }

    #[test]
    fn test_eip2930_tx_truncated_data() {
        // Arrange: Create a truncated EIP-2930 transaction
        let parser = EthereumParser::new();

        // First create a valid EIP-2930 transaction
        let valid_raw = encode_eip2930_tx(
            1,                               // chain_id
            0,                               // nonce
            1_000_000_000,                   // gas_price
            21000,                           // gas_limit
            Some(Address::from([0x35; 20])), // to
            U256::ZERO,                      // value
            Bytes::new(),                    // data
        );

        // Truncate it to simulate missing fields
        let truncated = &valid_raw[..valid_raw.len() / 2];

        // Act
        let result = parser.parse(truncated);

        // Assert: Should fail with InvalidRlp or MalformedTransaction
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(ParseError::InvalidRlp { .. } | ParseError::MalformedTransaction { .. })
        ));
    }

    #[test]
    fn test_legacy_tx_invalid_rlp_structure() {
        // Arrange: Create invalid RLP data that doesn't represent a valid transaction
        let parser = EthereumParser::new();

        // Invalid RLP: claim to be a long list but provide insufficient data
        let invalid_rlp = vec![0xf8, 0xff, 0x01, 0x02, 0x03];

        // Act
        let result = parser.parse(&invalid_rlp);

        // Assert: Should fail with InvalidRlp or MalformedTransaction
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(ParseError::InvalidRlp { .. } | ParseError::MalformedTransaction { .. })
        ));
    }

    #[test]
    fn test_eip1559_tx_invalid_rlp_structure() {
        // Arrange: Create invalid EIP-1559 transaction with malformed RLP
        let parser = EthereumParser::new();

        // Type 2 transaction with invalid RLP payload
        let invalid = vec![0x02, 0xf8, 0xff, 0x01, 0x02, 0x03];

        // Act
        let result = parser.parse(&invalid);

        // Assert: Should fail with InvalidRlp or MalformedTransaction
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(ParseError::InvalidRlp { .. } | ParseError::MalformedTransaction { .. })
        ));
    }

    #[test]
    fn test_analyze_erc20_returns_none_for_non_erc20() {
        // This test exercises the None return path in analyze_erc20
        // by providing invalid ERC-20 calldata
        let parser = EthereumParser::new();

        let contract = Address::from([0xaa; 20]);
        // Calldata with unknown selector (not ERC-20)
        let invalid_calldata = Bytes::from(vec![0x12, 0x34, 0x56, 0x78]);

        let raw = encode_eip1559_tx(
            1,                // chain_id
            0,                // nonce
            1_000_000_000,    // max_priority_fee_per_gas
            2_000_000_000,    // max_fee_per_gas
            100_000,          // gas_limit
            Some(contract),   // to
            U256::ZERO,       // value
            invalid_calldata, // data (invalid ERC-20)
        );

        let result = parser.parse(&raw);
        assert!(result.is_ok());

        let parsed = result.unwrap();

        // Should be ContractCall, not TokenTransfer/TokenApproval
        assert_eq!(parsed.tx_type, TxType::ContractCall);
        // Token address should NOT be set
        assert!(parsed.token_address.is_none());
    }

    // ------------------------------------------------------------------------
    // Unsigned Transaction Parsing Tests
    // ------------------------------------------------------------------------

    /// Helper to encode an unsigned EIP-1559 tx (9 items, no signature)
    fn encode_unsigned_eip1559_tx(
        chain_id: u64,
        nonce: u64,
        max_priority_fee_per_gas: u128,
        max_fee_per_gas: u128,
        gas_limit: u64,
        to: Option<Address>,
        value: U256,
        data: Bytes,
    ) -> Vec<u8> {
        use alloy_consensus::TxEip1559;
        use alloy_rlp::Encodable;

        let tx = TxEip1559 {
            chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            to: to.map_or(TxKind::Create, TxKind::Call),
            value,
            input: data,
            access_list: Default::default(),
        };

        let mut payload = Vec::new();
        tx.encode(&mut payload);

        let mut buf = vec![0x02]; // EIP-1559 type prefix
        buf.extend_from_slice(&payload);
        buf
    }

    /// Helper to encode an unsigned EIP-2930 tx (8 items, no signature)
    fn encode_unsigned_eip2930_tx(
        chain_id: u64,
        nonce: u64,
        gas_price: u128,
        gas_limit: u64,
        to: Option<Address>,
        value: U256,
        data: Bytes,
    ) -> Vec<u8> {
        use alloy_consensus::TxEip2930;
        use alloy_rlp::Encodable;

        let tx = TxEip2930 {
            chain_id,
            nonce,
            gas_price,
            gas_limit,
            to: to.map_or(TxKind::Create, TxKind::Call),
            value,
            input: data,
            access_list: Default::default(),
        };

        let mut payload = Vec::new();
        tx.encode(&mut payload);

        let mut buf = vec![0x01]; // EIP-2930 type prefix
        buf.extend_from_slice(&payload);
        buf
    }

    /// Helper to encode an unsigned legacy tx (6 items, no signature)
    fn encode_unsigned_legacy_tx(
        nonce: u64,
        gas_price: u128,
        gas_limit: u64,
        to: Option<Address>,
        value: U256,
        data: Bytes,
    ) -> Vec<u8> {
        use alloy_consensus::TxLegacy;
        use alloy_rlp::Encodable;

        let tx = TxLegacy {
            chain_id: None, // pre-EIP-155 unsigned: 6 items
            nonce,
            gas_price,
            gas_limit,
            to: to.map_or(TxKind::Create, TxKind::Call),
            value,
            input: data,
        };

        let mut buf = Vec::new();
        tx.encode(&mut buf);
        buf
    }

    #[test]
    fn test_parse_unsigned_eip1559() {
        let parser = EthereumParser::new();
        let recipient = Address::from(hex!("d8dA6BF26964aF9D7eEd9e03E53415D37aA96045"));
        let raw = encode_unsigned_eip1559_tx(
            1,
            0,
            1_000_000_000,
            2_000_000_000,
            21000,
            Some(recipient),
            U256::from(1_000_000_000_000_000_000u64),
            Bytes::new(),
        );

        let result = parser.parse(&raw);
        assert!(
            result.is_ok(),
            "Should parse unsigned EIP-1559: {:?}",
            result.err()
        );
        let parsed = result.unwrap();
        assert_eq!(parsed.chain_id, Some(1));
        assert_eq!(parsed.nonce, Some(0));
        assert_eq!(
            parsed.metadata.get("unsigned"),
            Some(&serde_json::Value::Bool(true))
        );
    }

    #[test]
    fn test_parse_unsigned_eip2930() {
        let parser = EthereumParser::new();
        let recipient = Address::from(hex!("d8dA6BF26964aF9D7eEd9e03E53415D37aA96045"));
        let raw = encode_unsigned_eip2930_tx(
            1,
            0,
            1_000_000_000,
            21000,
            Some(recipient),
            U256::from(1_000_000_000_000_000_000u64),
            Bytes::new(),
        );

        let result = parser.parse(&raw);
        assert!(
            result.is_ok(),
            "Should parse unsigned EIP-2930: {:?}",
            result.err()
        );
        let parsed = result.unwrap();
        assert_eq!(parsed.chain_id, Some(1));
        assert_eq!(
            parsed.metadata.get("unsigned"),
            Some(&serde_json::Value::Bool(true))
        );
    }

    #[test]
    fn test_parse_unsigned_legacy_pre_eip155() {
        let parser = EthereumParser::new();
        let recipient = Address::from(hex!("d8dA6BF26964aF9D7eEd9e03E53415D37aA96045"));
        let raw = encode_unsigned_legacy_tx(
            0,
            20_000_000_000,
            21000,
            Some(recipient),
            U256::from(1_000_000_000_000_000_000u64),
            Bytes::new(),
        );

        let result = parser.parse(&raw);
        assert!(
            result.is_ok(),
            "Should parse unsigned legacy: {:?}",
            result.err()
        );
        let parsed = result.unwrap();
        assert_eq!(parsed.chain_id, Some(1)); // defaults to mainnet
        assert_eq!(
            parsed.metadata.get("unsigned"),
            Some(&serde_json::Value::Bool(true))
        );
    }

    // ------------------------------------------------------------------------
    // assemble_signed() Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_assemble_signed_legacy_roundtrip() {
        let recipient = Address::from(hex!("d8dA6BF26964aF9D7eEd9e03E53415D37aA96045"));
        let sig = Signature::new(
            U256::from(0xdeadbeef_u64),
            U256::from(0xcafebabe_u64),
            false,
        );

        let tx = alloy_consensus::TxLegacy {
            chain_id: Some(1),
            nonce: 42,
            gas_price: 20_000_000_000,
            gas_limit: 21000,
            to: TxKind::Call(recipient),
            value: U256::from(1_000_000_000_000_000_000u64),
            input: Bytes::new(),
        };

        // Encode the signed tx
        let mut expected = Vec::new();
        alloy_consensus::transaction::RlpEcdsaEncodableTx::rlp_encode_signed(
            &tx,
            &sig,
            &mut expected,
        );

        // Now assemble from the same signed bytes (which is the input) + our signature
        // Build a 65-byte signature: r(32) || s(32) || v(1)
        let mut sig_bytes = [0u8; 65];
        sig.r()
            .to_be_bytes::<32>()
            .iter()
            .enumerate()
            .for_each(|(i, b)| sig_bytes[i] = *b);
        sig.s()
            .to_be_bytes::<32>()
            .iter()
            .enumerate()
            .for_each(|(i, b)| sig_bytes[32 + i] = *b);
        sig_bytes[64] = u8::from(sig.v());

        let assembled = EthereumParser::assemble_signed(&expected, &sig_bytes);
        assert!(assembled.is_ok(), "Assembly failed: {:?}", assembled.err());
        assert_eq!(assembled.unwrap(), expected);
    }

    #[test]
    fn test_assemble_signed_eip1559_roundtrip() {
        let recipient = Address::from(hex!("d8dA6BF26964aF9D7eEd9e03E53415D37aA96045"));
        let sig = Signature::new(U256::from(0xdeadbeef_u64), U256::from(0xcafebabe_u64), true);

        let tx = alloy_consensus::TxEip1559 {
            chain_id: 1,
            nonce: 10,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 2_000_000_000,
            gas_limit: 21000,
            to: TxKind::Call(recipient),
            value: U256::from(500_000_000_000_000_000u64),
            input: Bytes::new(),
            access_list: Default::default(),
        };

        let mut expected = vec![0x02];
        alloy_consensus::transaction::RlpEcdsaEncodableTx::rlp_encode_signed(
            &tx,
            &sig,
            &mut expected,
        );

        let mut sig_bytes = [0u8; 65];
        sig.r()
            .to_be_bytes::<32>()
            .iter()
            .enumerate()
            .for_each(|(i, b)| sig_bytes[i] = *b);
        sig.s()
            .to_be_bytes::<32>()
            .iter()
            .enumerate()
            .for_each(|(i, b)| sig_bytes[32 + i] = *b);
        sig_bytes[64] = u8::from(sig.v());

        let assembled = EthereumParser::assemble_signed(&expected, &sig_bytes);
        assert!(assembled.is_ok(), "Assembly failed: {:?}", assembled.err());
        assert_eq!(assembled.unwrap(), expected);
    }

    #[test]
    fn test_assemble_signed_eip2930_roundtrip() {
        let recipient = Address::from(hex!("d8dA6BF26964aF9D7eEd9e03E53415D37aA96045"));
        let sig = Signature::new(
            U256::from(0xdeadbeef_u64),
            U256::from(0xcafebabe_u64),
            false,
        );

        let tx = alloy_consensus::TxEip2930 {
            chain_id: 1,
            nonce: 5,
            gas_price: 20_000_000_000,
            gas_limit: 21000,
            to: TxKind::Call(recipient),
            value: U256::from(1_000_000_000_000_000_000u64),
            input: Bytes::new(),
            access_list: Default::default(),
        };

        let mut expected = vec![0x01];
        alloy_consensus::transaction::RlpEcdsaEncodableTx::rlp_encode_signed(
            &tx,
            &sig,
            &mut expected,
        );

        let mut sig_bytes = [0u8; 65];
        sig.r()
            .to_be_bytes::<32>()
            .iter()
            .enumerate()
            .for_each(|(i, b)| sig_bytes[i] = *b);
        sig.s()
            .to_be_bytes::<32>()
            .iter()
            .enumerate()
            .for_each(|(i, b)| sig_bytes[32 + i] = *b);
        sig_bytes[64] = u8::from(sig.v());

        let assembled = EthereumParser::assemble_signed(&expected, &sig_bytes);
        assert!(assembled.is_ok(), "Assembly failed: {:?}", assembled.err());
        assert_eq!(assembled.unwrap(), expected);
    }

    #[test]
    fn test_assemble_signed_from_unsigned_eip1559() {
        let recipient = Address::from(hex!("d8dA6BF26964aF9D7eEd9e03E53415D37aA96045"));
        let sig = Signature::new(
            U256::from(0xdeadbeef_u64),
            U256::from(0xcafebabe_u64),
            false,
        );

        let tx = alloy_consensus::TxEip1559 {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 2_000_000_000,
            gas_limit: 21000,
            to: TxKind::Call(recipient),
            value: U256::from(1_000_000_000_000_000_000u64),
            input: Bytes::new(),
            access_list: Default::default(),
        };

        // Create unsigned raw bytes
        let unsigned_raw = encode_unsigned_eip1559_tx(
            1,
            0,
            1_000_000_000,
            2_000_000_000,
            21000,
            Some(recipient),
            U256::from(1_000_000_000_000_000_000u64),
            Bytes::new(),
        );

        // Build expected signed output
        let mut expected = vec![0x02];
        alloy_consensus::transaction::RlpEcdsaEncodableTx::rlp_encode_signed(
            &tx,
            &sig,
            &mut expected,
        );

        let mut sig_bytes = [0u8; 65];
        sig.r()
            .to_be_bytes::<32>()
            .iter()
            .enumerate()
            .for_each(|(i, b)| sig_bytes[i] = *b);
        sig.s()
            .to_be_bytes::<32>()
            .iter()
            .enumerate()
            .for_each(|(i, b)| sig_bytes[32 + i] = *b);
        sig_bytes[64] = u8::from(sig.v());

        let assembled = EthereumParser::assemble_signed(&unsigned_raw, &sig_bytes);
        assert!(
            assembled.is_ok(),
            "Assembly from unsigned failed: {:?}",
            assembled.err()
        );
        assert_eq!(assembled.unwrap(), expected);
    }

    #[test]
    fn test_assemble_signed_invalid_signature_length() {
        let raw = encode_eip1559_tx(
            1,
            0,
            1_000_000_000,
            2_000_000_000,
            21000,
            Some(Address::ZERO),
            U256::ZERO,
            Bytes::new(),
        );

        let short_sig = [0u8; 32]; // too short
        let result = EthereumParser::assemble_signed(&raw, &short_sig);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("expected 65-byte signature"));
    }
}
