//! Core types for the `TxGate` signing service.
//!
//! This module provides the foundational types used across all `TxGate` crates:
//!
//! - [`ParsedTx`] - Unified transaction context produced by chain parsers
//! - [`TxType`] - Classification of transaction types
//! - [`PolicyResult`] - Result of policy evaluation
//!
//! # Examples
//!
//! ```
//! use txgate_core::types::{ParsedTx, TxType, PolicyResult};
//! use alloy_primitives::U256;
//! use std::collections::HashMap;
//!
//! // Create a native ETH transfer
//! let tx = ParsedTx {
//!     hash: [0u8; 32],
//!     recipient: Some("0x742d35Cc6634C0532925a3b844Bc454e7595f...".to_string()),
//!     amount: Some(U256::from(1_500_000_000_000_000_000u64)), // 1.5 ETH
//!     token: Some("ETH".to_string()),
//!     token_address: None,
//!     tx_type: TxType::Transfer,
//!     chain: "ethereum".to_string(),
//!     nonce: Some(42),
//!     chain_id: Some(1),
//!     metadata: HashMap::new(),
//! };
//!
//! assert!(tx.is_native_transfer());
//! assert!(!tx.is_token_transfer());
//! ```

use alloy_primitives::U256;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Unified transaction context produced by all chain parsers.
///
/// This struct provides a normalized view of transactions across different blockchain
/// networks. Each chain parser transforms chain-specific transaction formats into
/// this common representation for policy evaluation.
///
/// # Fields
///
/// - `hash`: The transaction hash used for signing (32 bytes)
/// - `recipient`: The destination address in chain-native format
/// - `amount`: Transfer amount in the smallest unit (wei, satoshi, lamport)
/// - `token`: Token symbol (ETH, BTC, SOL, USDC, etc.)
/// - `token_address`: Contract address for token transfers
/// - `tx_type`: Classification of the transaction type
/// - `chain`: Chain identifier (e.g., "ethereum", "bitcoin")
/// - `nonce`: Transaction nonce for replay protection
/// - `chain_id`: Network identifier (EIP-155 for Ethereum)
/// - `metadata`: Chain-specific additional data
///
/// # Security Considerations
///
/// - The `hash` field contains the signing hash, not necessarily the transaction ID
/// - The `nonce` and `chain_id` fields are critical for replay protection
/// - Token transfers require validation of both `recipient` and `token_address`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedTx {
    /// Transaction hash (for signing).
    ///
    /// This is the 32-byte hash that will be signed by the cryptographic
    /// signing operation. For Ethereum, this is the RLP-encoded transaction
    /// hash according to EIP-155.
    #[serde(with = "hex_bytes")]
    pub hash: [u8; 32],

    /// Recipient address (chain-native format).
    ///
    /// For native transfers, this is the destination address.
    /// For token transfers, this is the actual recipient (not the token contract).
    /// `None` for contract deployments.
    pub recipient: Option<String>,

    /// Transfer amount in smallest unit (wei, satoshi, lamport).
    ///
    /// Uses `U256` to support large values across all chains.
    /// For token transfers, this represents the token amount (in token's smallest unit).
    /// `None` for contract calls that don't transfer value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<U256>,

    /// Token symbol (ETH, BTC, SOL, USDC, etc.).
    ///
    /// For native transfers, this is the chain's native currency symbol.
    /// For token transfers, this is the token's symbol.
    pub token: Option<String>,

    /// Token contract address (for token transfers).
    ///
    /// `None` for native currency transfers.
    /// For ERC-20/SPL/TRC-20 transfers, this is the token contract address.
    pub token_address: Option<String>,

    /// Transaction type classification.
    ///
    /// Determines how the policy engine should evaluate this transaction.
    pub tx_type: TxType,

    /// Chain identifier (e.g., "ethereum", "bitcoin").
    ///
    /// Used to select the appropriate parser and signer.
    pub chain: String,

    /// Transaction nonce (critical for replay protection).
    ///
    /// Required for Ethereum (prevents replay attacks).
    /// Optional for other chains with different replay protection mechanisms.
    pub nonce: Option<u64>,

    /// Chain ID (EIP-155 for Ethereum, network identifier for others).
    ///
    /// Critical for cross-chain replay protection.
    /// For Ethereum: 1 = mainnet, 137 = Polygon, etc.
    pub chain_id: Option<u64>,

    /// Chain-specific metadata.
    ///
    /// Stores additional chain-specific data that doesn't fit into the
    /// common fields. Examples: gas parameters, fee estimates, memo fields.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, serde_json::Value>,
}

impl ParsedTx {
    /// Returns `true` if this is a token transfer (ERC-20, SPL, TRC-20, etc.).
    ///
    /// A token transfer has a `token_address` set, indicating the transaction
    /// interacts with a token contract to transfer tokens.
    ///
    /// # Examples
    ///
    /// ```
    /// use txgate_core::types::{ParsedTx, TxType};
    ///
    /// let tx = ParsedTx {
    ///     tx_type: TxType::TokenTransfer,
    ///     token_address: Some("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string()),
    ///     ..Default::default()
    /// };
    /// assert!(tx.is_token_transfer());
    /// ```
    #[must_use]
    pub fn is_token_transfer(&self) -> bool {
        self.token_address.is_some() && self.tx_type == TxType::TokenTransfer
    }

    /// Returns `true` if this is a native currency transfer (ETH, BTC, SOL, etc.).
    ///
    /// A native transfer has no `token_address` and is classified as `TxType::Transfer`.
    ///
    /// # Examples
    ///
    /// ```
    /// use txgate_core::types::{ParsedTx, TxType};
    ///
    /// let tx = ParsedTx {
    ///     tx_type: TxType::Transfer,
    ///     token_address: None,
    ///     ..Default::default()
    /// };
    /// assert!(tx.is_native_transfer());
    /// ```
    #[must_use]
    pub fn is_native_transfer(&self) -> bool {
        self.token_address.is_none() && self.tx_type == TxType::Transfer
    }

    /// Returns `true` if this transaction has a recipient address.
    #[must_use]
    pub const fn has_recipient(&self) -> bool {
        self.recipient.is_some()
    }

    /// Returns `true` if this transaction transfers value (native or token).
    #[must_use]
    pub fn transfers_value(&self) -> bool {
        self.amount.is_some() && self.amount != Some(U256::ZERO)
    }

    /// Returns `true` if this is a contract deployment.
    #[must_use]
    pub fn is_deployment(&self) -> bool {
        self.tx_type == TxType::Deployment
    }

    /// Returns `true` if this is a token approval operation.
    #[must_use]
    pub fn is_token_approval(&self) -> bool {
        self.tx_type == TxType::TokenApproval
    }
}

impl Default for ParsedTx {
    fn default() -> Self {
        Self {
            hash: [0u8; 32],
            recipient: None,
            amount: None,
            token: None,
            token_address: None,
            tx_type: TxType::Other,
            chain: String::new(),
            nonce: None,
            chain_id: None,
            metadata: HashMap::new(),
        }
    }
}

/// Transaction type classification.
///
/// Categorizes transactions by their primary operation to enable
/// type-specific policy rules (e.g., stricter limits on approvals).
///
/// # Variants
///
/// - `Transfer` - Native currency transfer (ETH, BTC, SOL)
/// - `TokenTransfer` - Token transfer (ERC-20, SPL, TRC-20)
/// - `TokenApproval` - Token allowance grant (ERC-20 approve)
/// - `ContractCall` - Generic smart contract interaction
/// - `Deployment` - Contract deployment
/// - `Other` - Staking, governance, or unclassified operations
///
/// # Examples
///
/// ```
/// use txgate_core::types::TxType;
///
/// let tx_type = TxType::Transfer;
/// assert_eq!(tx_type.to_string(), "transfer");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TxType {
    /// Native currency transfer (ETH, BTC, SOL, etc.).
    ///
    /// Direct transfer of the chain's native currency to a recipient address.
    Transfer,

    /// Token transfer (ERC-20 transfer/transferFrom, SPL, TRC-20, etc.).
    ///
    /// Transfer of tokens via a token contract. Includes both direct
    /// `transfer()` calls and `transferFrom()` with prior approval.
    TokenTransfer,

    /// Token approval (ERC-20 approve, allowance grants).
    ///
    /// Grants a spender permission to transfer tokens on behalf of the owner.
    /// These operations require careful policy evaluation as they can
    /// authorize significant value transfers.
    TokenApproval,

    /// Generic contract interaction.
    ///
    /// Any smart contract call that doesn't fit other categories.
    /// May include `DeFi` operations, NFT interactions, etc.
    ContractCall,

    /// Contract deployment.
    ///
    /// Creation of a new smart contract. The `recipient` field is `None`
    /// for these transactions.
    Deployment,

    /// Other operations (staking, governance, etc.).
    ///
    /// Catch-all for operations not classified above.
    /// Includes staking, delegation, governance votes, etc.
    #[default]
    Other,
}

impl TxType {
    /// Returns the string representation of this transaction type.
    ///
    /// # Examples
    ///
    /// ```
    /// use txgate_core::types::TxType;
    ///
    /// assert_eq!(TxType::Transfer.as_str(), "transfer");
    /// assert_eq!(TxType::TokenTransfer.as_str(), "token_transfer");
    /// ```
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Transfer => "transfer",
            Self::TokenTransfer => "token_transfer",
            Self::TokenApproval => "token_approval",
            Self::ContractCall => "contract_call",
            Self::Deployment => "deployment",
            Self::Other => "other",
        }
    }

    /// Returns `true` if this transaction type involves token operations.
    #[must_use]
    pub const fn is_token_operation(&self) -> bool {
        matches!(self, Self::TokenTransfer | Self::TokenApproval)
    }

    /// Returns `true` if this transaction type involves value transfer.
    #[must_use]
    pub const fn involves_value_transfer(&self) -> bool {
        matches!(self, Self::Transfer | Self::TokenTransfer)
    }
}

impl fmt::Display for TxType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Policy evaluation result.
///
/// Returned by the policy engine after evaluating a transaction against
/// configured rules. If denied, includes the specific rule that triggered
/// the denial and a human-readable reason.
///
/// # Examples
///
/// ```
/// use txgate_core::types::PolicyResult;
///
/// let allowed = PolicyResult::Allowed;
/// assert!(allowed.is_allowed());
///
/// let denied = PolicyResult::Denied {
///     rule: "whitelist".to_string(),
///     reason: "recipient not in whitelist".to_string(),
/// };
/// assert!(denied.is_denied());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "status", rename_all = "snake_case")]
#[non_exhaustive]
pub enum PolicyResult {
    /// Transaction is allowed by all policy rules.
    #[default]
    Allowed,

    /// Transaction is denied by a policy rule.
    Denied {
        /// The name of the rule that denied the transaction.
        ///
        /// Common values: `blacklist`, `whitelist`, `tx_limit`, `daily_limit`
        rule: String,

        /// Human-readable explanation of why the transaction was denied.
        reason: String,
    },
}

impl PolicyResult {
    /// Returns `true` if the policy allows this transaction.
    ///
    /// # Examples
    ///
    /// ```
    /// use txgate_core::types::PolicyResult;
    ///
    /// assert!(PolicyResult::Allowed.is_allowed());
    /// assert!(!PolicyResult::Denied {
    ///     rule: "test".to_string(),
    ///     reason: "test".to_string(),
    /// }.is_allowed());
    /// ```
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed)
    }

    /// Returns `true` if the policy denies this transaction.
    ///
    /// # Examples
    ///
    /// ```
    /// use txgate_core::types::PolicyResult;
    ///
    /// assert!(!PolicyResult::Allowed.is_denied());
    /// assert!(PolicyResult::Denied {
    ///     rule: "blacklist".to_string(),
    ///     reason: "address is blacklisted".to_string(),
    /// }.is_denied());
    /// ```
    #[must_use]
    pub const fn is_denied(&self) -> bool {
        matches!(self, Self::Denied { .. })
    }

    /// Creates a new denied result.
    ///
    /// # Examples
    ///
    /// ```
    /// use txgate_core::types::PolicyResult;
    ///
    /// let result = PolicyResult::denied("whitelist", "recipient not in whitelist");
    /// assert!(result.is_denied());
    /// ```
    #[must_use]
    pub fn denied(rule: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::Denied {
            rule: rule.into(),
            reason: reason.into(),
        }
    }

    /// Returns the denial rule and reason if denied, or `None` if allowed.
    #[must_use]
    pub fn denial_info(&self) -> Option<(&str, &str)> {
        match self {
            Self::Allowed => None,
            Self::Denied { rule, reason } => Some((rule.as_str(), reason.as_str())),
        }
    }
}

impl fmt::Display for PolicyResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allowed => write!(f, "allowed"),
            Self::Denied { rule, reason } => write!(f, "denied by {rule}: {reason}"),
        }
    }
}

/// Helper module for serializing/deserializing `[u8; 32]` as hex strings.
mod hex_bytes {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex_string = format!("0x{}", hex::encode(bytes));
        serializer.serialize_str(&hex_string)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let s = s.strip_prefix("0x").unwrap_or(&s);

        let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;

        if bytes.len() != 32 {
            return Err(serde::de::Error::custom(format!(
                "expected 32 bytes, got {}",
                bytes.len()
            )));
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic, clippy::items_after_statements)]

    use super::*;

    mod tx_type_tests {
        use super::*;

        #[test]
        fn test_tx_type_display() {
            assert_eq!(TxType::Transfer.to_string(), "transfer");
            assert_eq!(TxType::TokenTransfer.to_string(), "token_transfer");
            assert_eq!(TxType::TokenApproval.to_string(), "token_approval");
            assert_eq!(TxType::ContractCall.to_string(), "contract_call");
            assert_eq!(TxType::Deployment.to_string(), "deployment");
            assert_eq!(TxType::Other.to_string(), "other");
        }

        #[test]
        fn test_tx_type_as_str() {
            assert_eq!(TxType::Transfer.as_str(), "transfer");
            assert_eq!(TxType::TokenTransfer.as_str(), "token_transfer");
            assert_eq!(TxType::TokenApproval.as_str(), "token_approval");
            assert_eq!(TxType::ContractCall.as_str(), "contract_call");
            assert_eq!(TxType::Deployment.as_str(), "deployment");
            assert_eq!(TxType::Other.as_str(), "other");
        }

        #[test]
        fn test_tx_type_default() {
            assert_eq!(TxType::default(), TxType::Other);
        }

        #[test]
        fn test_tx_type_is_token_operation() {
            assert!(!TxType::Transfer.is_token_operation());
            assert!(TxType::TokenTransfer.is_token_operation());
            assert!(TxType::TokenApproval.is_token_operation());
            assert!(!TxType::ContractCall.is_token_operation());
            assert!(!TxType::Deployment.is_token_operation());
            assert!(!TxType::Other.is_token_operation());
        }

        #[test]
        fn test_tx_type_involves_value_transfer() {
            assert!(TxType::Transfer.involves_value_transfer());
            assert!(TxType::TokenTransfer.involves_value_transfer());
            assert!(!TxType::TokenApproval.involves_value_transfer());
            assert!(!TxType::ContractCall.involves_value_transfer());
            assert!(!TxType::Deployment.involves_value_transfer());
            assert!(!TxType::Other.involves_value_transfer());
        }

        #[test]
        fn test_tx_type_serialization_roundtrip() {
            for tx_type in [
                TxType::Transfer,
                TxType::TokenTransfer,
                TxType::TokenApproval,
                TxType::ContractCall,
                TxType::Deployment,
                TxType::Other,
            ] {
                let json = serde_json::to_string(&tx_type).expect("serialization failed");
                let deserialized: TxType =
                    serde_json::from_str(&json).expect("deserialization failed");
                assert_eq!(tx_type, deserialized);
            }
        }

        #[test]
        fn test_tx_type_serde_format() {
            // Verify snake_case serialization
            assert_eq!(
                serde_json::to_string(&TxType::TokenTransfer).expect("serialization failed"),
                "\"token_transfer\""
            );
            assert_eq!(
                serde_json::to_string(&TxType::TokenApproval).expect("serialization failed"),
                "\"token_approval\""
            );
        }
    }

    mod policy_result_tests {
        use super::*;

        #[test]
        fn test_policy_result_is_allowed() {
            assert!(PolicyResult::Allowed.is_allowed());
            assert!(!PolicyResult::Denied {
                rule: "test".to_string(),
                reason: "test".to_string()
            }
            .is_allowed());
        }

        #[test]
        fn test_policy_result_is_denied() {
            assert!(!PolicyResult::Allowed.is_denied());
            assert!(PolicyResult::Denied {
                rule: "test".to_string(),
                reason: "test".to_string()
            }
            .is_denied());
        }

        #[test]
        fn test_policy_result_denied_constructor() {
            let result = PolicyResult::denied("whitelist", "not in list");
            assert!(result.is_denied());
            match result {
                PolicyResult::Denied { rule, reason } => {
                    assert_eq!(rule, "whitelist");
                    assert_eq!(reason, "not in list");
                }
                _ => panic!("expected Denied variant"),
            }
        }

        #[test]
        fn test_policy_result_denial_info() {
            assert!(PolicyResult::Allowed.denial_info().is_none());

            let denied = PolicyResult::Denied {
                rule: "blacklist".to_string(),
                reason: "address blocked".to_string(),
            };
            let info = denied.denial_info();
            assert!(info.is_some());
            let (rule, reason) = info.expect("should have denial info");
            assert_eq!(rule, "blacklist");
            assert_eq!(reason, "address blocked");
        }

        #[test]
        fn test_policy_result_default() {
            assert_eq!(PolicyResult::default(), PolicyResult::Allowed);
        }

        #[test]
        fn test_policy_result_display() {
            assert_eq!(PolicyResult::Allowed.to_string(), "allowed");
            assert_eq!(
                PolicyResult::Denied {
                    rule: "whitelist".to_string(),
                    reason: "not in list".to_string()
                }
                .to_string(),
                "denied by whitelist: not in list"
            );
        }

        #[test]
        fn test_policy_result_serialization_roundtrip() {
            let allowed = PolicyResult::Allowed;
            let json = serde_json::to_string(&allowed).expect("serialization failed");
            let deserialized: PolicyResult =
                serde_json::from_str(&json).expect("deserialization failed");
            assert_eq!(allowed, deserialized);

            let denied = PolicyResult::Denied {
                rule: "tx_limit".to_string(),
                reason: "exceeds 5 ETH limit".to_string(),
            };
            let json = serde_json::to_string(&denied).expect("serialization failed");
            let deserialized: PolicyResult =
                serde_json::from_str(&json).expect("deserialization failed");
            assert_eq!(denied, deserialized);
        }

        #[test]
        fn test_policy_result_serde_format() {
            // Check tagged format
            let json = serde_json::to_string(&PolicyResult::Allowed).expect("serialization failed");
            assert!(json.contains("\"status\":\"allowed\""));

            let denied = PolicyResult::Denied {
                rule: "test".to_string(),
                reason: "test reason".to_string(),
            };
            let json = serde_json::to_string(&denied).expect("serialization failed");
            assert!(json.contains("\"status\":\"denied\""));
            assert!(json.contains("\"rule\":\"test\""));
            assert!(json.contains("\"reason\":\"test reason\""));
        }
    }

    mod parsed_tx_tests {
        use super::*;

        fn sample_tx() -> ParsedTx {
            ParsedTx {
                hash: [0xab; 32],
                recipient: Some("0x742d35Cc6634C0532925a3b844Bc454e7595f".to_string()),
                amount: Some(U256::from(1_500_000_000_000_000_000u64)),
                token: Some("ETH".to_string()),
                token_address: None,
                tx_type: TxType::Transfer,
                chain: "ethereum".to_string(),
                nonce: Some(42),
                chain_id: Some(1),
                metadata: HashMap::new(),
            }
        }

        fn sample_token_tx() -> ParsedTx {
            ParsedTx {
                hash: [0xcd; 32],
                recipient: Some("0x742d35Cc6634C0532925a3b844Bc454e7595f".to_string()),
                amount: Some(U256::from(1_000_000u64)), // 1 USDC (6 decimals)
                token: Some("USDC".to_string()),
                token_address: Some("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string()),
                tx_type: TxType::TokenTransfer,
                chain: "ethereum".to_string(),
                nonce: Some(43),
                chain_id: Some(1),
                metadata: HashMap::new(),
            }
        }

        #[test]
        fn test_parsed_tx_is_native_transfer() {
            let tx = sample_tx();
            assert!(tx.is_native_transfer());
            assert!(!tx.is_token_transfer());
        }

        #[test]
        fn test_parsed_tx_is_token_transfer() {
            let tx = sample_token_tx();
            assert!(tx.is_token_transfer());
            assert!(!tx.is_native_transfer());
        }

        #[test]
        fn test_parsed_tx_has_recipient() {
            let tx = sample_tx();
            assert!(tx.has_recipient());

            let deployment = ParsedTx {
                tx_type: TxType::Deployment,
                recipient: None,
                ..Default::default()
            };
            assert!(!deployment.has_recipient());
        }

        #[test]
        fn test_parsed_tx_transfers_value() {
            let tx = sample_tx();
            assert!(tx.transfers_value());

            let no_value = ParsedTx {
                amount: None,
                ..Default::default()
            };
            assert!(!no_value.transfers_value());

            let zero_value = ParsedTx {
                amount: Some(U256::ZERO),
                ..Default::default()
            };
            assert!(!zero_value.transfers_value());
        }

        #[test]
        fn test_parsed_tx_is_deployment() {
            let deployment = ParsedTx {
                tx_type: TxType::Deployment,
                ..Default::default()
            };
            assert!(deployment.is_deployment());
            assert!(!sample_tx().is_deployment());
        }

        #[test]
        fn test_parsed_tx_is_token_approval() {
            let approval = ParsedTx {
                tx_type: TxType::TokenApproval,
                ..Default::default()
            };
            assert!(approval.is_token_approval());
            assert!(!sample_tx().is_token_approval());
        }

        #[test]
        fn test_parsed_tx_default() {
            let tx = ParsedTx::default();
            assert_eq!(tx.hash, [0u8; 32]);
            assert!(tx.recipient.is_none());
            assert!(tx.amount.is_none());
            assert!(tx.token.is_none());
            assert!(tx.token_address.is_none());
            assert_eq!(tx.tx_type, TxType::Other);
            assert!(tx.chain.is_empty());
            assert!(tx.nonce.is_none());
            assert!(tx.chain_id.is_none());
            assert!(tx.metadata.is_empty());
        }

        #[test]
        fn test_parsed_tx_serialization_roundtrip() {
            let tx = sample_tx();
            let json = serde_json::to_string(&tx).expect("serialization failed");
            let deserialized: ParsedTx =
                serde_json::from_str(&json).expect("deserialization failed");
            assert_eq!(tx, deserialized);
        }

        #[test]
        fn test_parsed_tx_token_serialization_roundtrip() {
            let tx = sample_token_tx();
            let json = serde_json::to_string(&tx).expect("serialization failed");
            let deserialized: ParsedTx =
                serde_json::from_str(&json).expect("deserialization failed");
            assert_eq!(tx, deserialized);
        }

        #[test]
        fn test_parsed_tx_with_metadata() {
            let mut tx = sample_tx();
            tx.metadata.insert(
                "gas_price".to_string(),
                serde_json::Value::String("50000000000".to_string()),
            );
            tx.metadata.insert(
                "gas_limit".to_string(),
                serde_json::Value::Number(21000.into()),
            );

            let json = serde_json::to_string(&tx).expect("serialization failed");
            let deserialized: ParsedTx =
                serde_json::from_str(&json).expect("deserialization failed");
            assert_eq!(tx, deserialized);
        }

        #[test]
        fn test_parsed_tx_hash_hex_serialization() {
            let tx = sample_tx();
            let json = serde_json::to_string(&tx).expect("serialization failed");

            // Verify hash is serialized as hex with 0x prefix
            assert!(json.contains("\"hash\":\"0x"));

            // Verify roundtrip
            let deserialized: ParsedTx =
                serde_json::from_str(&json).expect("deserialization failed");
            assert_eq!(tx.hash, deserialized.hash);
        }

        #[test]
        fn test_parsed_tx_hash_deserialization_with_prefix() {
            let json = r#"{
                "hash": "0xabababababababababababababababababababababababababababababababab",
                "recipient": null,
                "token": null,
                "token_address": null,
                "tx_type": "other",
                "chain": "ethereum"
            }"#;
            let tx: ParsedTx = serde_json::from_str(json).expect("deserialization failed");
            assert_eq!(tx.hash, [0xab; 32]);
        }

        #[test]
        fn test_parsed_tx_hash_deserialization_without_prefix() {
            let json = r#"{
                "hash": "abababababababababababababababababababababababababababababababab",
                "recipient": null,
                "token": null,
                "token_address": null,
                "tx_type": "other",
                "chain": "ethereum"
            }"#;
            let tx: ParsedTx = serde_json::from_str(json).expect("deserialization failed");
            assert_eq!(tx.hash, [0xab; 32]);
        }

        #[test]
        fn test_parsed_tx_u256_serialization() {
            let tx = sample_tx();
            let json = serde_json::to_string(&tx).expect("serialization failed");

            // U256 should be serialized (alloy_primitives handles this)
            let deserialized: ParsedTx =
                serde_json::from_str(&json).expect("deserialization failed");
            assert_eq!(tx.amount, deserialized.amount);
        }

        #[test]
        fn test_parsed_tx_clone() {
            let tx = sample_tx();
            let cloned = tx.clone();
            assert_eq!(tx, cloned);
        }

        #[test]
        fn test_parsed_tx_debug() {
            let tx = sample_tx();
            let debug_str = format!("{tx:?}");
            assert!(debug_str.contains("ParsedTx"));
            assert!(debug_str.contains("ethereum"));
        }
    }

    mod hex_bytes_tests {
        use super::*;

        #[test]
        fn test_hex_serialize_deserialize() {
            // Create a 32-byte array with a repeating pattern
            let arr = [0x12u8; 32];

            // Create a wrapper struct for testing
            #[derive(Serialize, Deserialize, PartialEq, Debug)]
            struct TestStruct {
                #[serde(with = "hex_bytes")]
                data: [u8; 32],
            }

            let test = TestStruct { data: arr };
            let json = serde_json::to_string(&test).expect("serialization failed");
            let deserialized: TestStruct =
                serde_json::from_str(&json).expect("deserialization failed");
            assert_eq!(test, deserialized);
        }

        #[test]
        fn test_hex_invalid_length() {
            let json = r#"{"hash": "0xabcd"}"#;
            #[derive(Deserialize)]
            struct TestStruct {
                #[serde(with = "hex_bytes")]
                #[allow(dead_code)]
                hash: [u8; 32],
            }
            let result: Result<TestStruct, _> = serde_json::from_str(json);
            assert!(result.is_err());
        }

        #[test]
        fn test_hex_invalid_characters() {
            let json =
                r#"{"hash": "0xGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG"}"#;
            #[derive(Deserialize)]
            struct TestStruct {
                #[serde(with = "hex_bytes")]
                #[allow(dead_code)]
                hash: [u8; 32],
            }
            let result: Result<TestStruct, _> = serde_json::from_str(json);
            assert!(result.is_err());
        }
    }
}
