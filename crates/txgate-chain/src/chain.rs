//! Chain trait for blockchain transaction parsers.
//!
//! This module defines the [`Chain`] trait that all blockchain parsers must implement.
//! The trait provides a unified interface for parsing raw transaction bytes into
//! a common [`ParsedTx`] structure that can be evaluated by the policy engine.
//!
//! # Design Philosophy
//!
//! The `Chain` trait is designed to:
//! - Provide a minimal, focused interface for transaction parsing
//! - Be thread-safe (`Send + Sync`) for concurrent parsing in async runtimes
//! - Support multiple transaction versions through the `supports_version` method
//! - Enable runtime chain selection through trait objects (`Box<dyn Chain>`)
//!
//! # Version Handling Strategy
//!
//! Different blockchains have different versioning schemes:
//!
//! ## Ethereum
//! - Legacy transactions (type 0): No version byte, RLP-encoded
//! - EIP-2930 (type 1): Access list transactions
//! - EIP-1559 (type 2): Dynamic fee transactions
//! - EIP-4844 (type 3): Blob transactions
//!
//! The version byte is the first byte of the raw transaction data for typed
//! transactions. Legacy transactions start with an RLP list marker (0xc0-0xff).
//!
//! ## Bitcoin
//! - Version field in transaction header (typically 1 or 2)
//! - `SegWit` transactions have a marker/flag after version
//!
//! ## Solana
//! - Message version in the first byte (0 for legacy, 128+ for versioned)
//!
//! Parsers should use `supports_version` to indicate which versions they handle
//! and return `ParseError::UnknownTxType` for unsupported versions.
//!
//! # Example Implementation
//!
//! ```ignore
//! use txgate_chain::Chain;
//! use txgate_core::{ParsedTx, error::ParseError};
//! use txgate_crypto::CurveType;
//!
//! struct EthereumParser;
//!
//! impl Chain for EthereumParser {
//!     fn id(&self) -> &'static str {
//!         "ethereum"
//!     }
//!
//!     fn parse(&self, raw: &[u8]) -> Result<ParsedTx, ParseError> {
//!         // Parse Ethereum transaction bytes...
//!         todo!()
//!     }
//!
//!     fn curve(&self) -> CurveType {
//!         CurveType::Secp256k1
//!     }
//!
//!     fn supports_version(&self, version: u8) -> bool {
//!         // Support legacy (detected by RLP marker), EIP-2930, EIP-1559, EIP-4844
//!         matches!(version, 0 | 1 | 2 | 3)
//!     }
//! }
//! ```
//!
//! # Security Considerations
//!
//! - Parsers must validate all input data thoroughly
//! - The `hash` field in `ParsedTx` must be the exact bytes that will be signed
//! - Parsers should not trust any data from the raw transaction without validation
//! - Integer overflow and underflow must be handled carefully

use txgate_core::{error::ParseError, ParsedTx};
use txgate_crypto::CurveType;

/// Trait for blockchain transaction parsers.
///
/// Each supported blockchain implements this trait to parse raw transaction
/// bytes into a unified [`ParsedTx`] structure that can be evaluated by the
/// policy engine.
///
/// # Implementor Requirements
///
/// Implementations must:
/// - Parse raw transaction bytes according to the chain's encoding format
/// - Extract recipient address, amount, and token information
/// - Compute the transaction hash that will be signed
/// - Detect token operations (ERC-20, SPL, TRC-20, etc.)
/// - Set appropriate [`TxType`](txgate_core::TxType) for policy evaluation
/// - Return appropriate errors for malformed or unsupported transactions
///
/// # Thread Safety
///
/// Implementations must be `Send + Sync` to allow concurrent parsing
/// in the server's async runtime. This is typically achieved by:
/// - Not storing mutable state in the parser
/// - Using interior mutability with proper synchronization if state is needed
///
/// # Example: Using with Trait Objects
///
/// ```
/// use txgate_chain::Chain;
/// use txgate_core::{ParsedTx, error::ParseError};
/// use txgate_crypto::CurveType;
///
/// // Create a registry of chain parsers
/// struct ChainRegistry {
///     chains: Vec<Box<dyn Chain>>,
/// }
///
/// impl ChainRegistry {
///     fn find(&self, id: &str) -> Option<&dyn Chain> {
///         self.chains.iter().find(|c| c.id() == id).map(|c| c.as_ref())
///     }
/// }
/// ```
pub trait Chain: Send + Sync {
    /// Returns the chain identifier (e.g., "ethereum", "bitcoin", "solana").
    ///
    /// This identifier is used for:
    /// - Chain lookup in the registry
    /// - Logging and metrics
    /// - Configuration matching
    /// - Correlation with key storage
    ///
    /// # Naming Convention
    ///
    /// Chain identifiers should be:
    /// - Lowercase
    /// - Alphanumeric with hyphens for multi-word names
    /// - Consistent with industry conventions
    ///
    /// Examples: `"ethereum"`, `"bitcoin"`, `"solana"`, `"polygon"`, `"arbitrum-one"`
    ///
    /// # Example
    ///
    /// ```
    /// use txgate_chain::Chain;
    /// # use txgate_core::{ParsedTx, error::ParseError};
    /// # use txgate_crypto::CurveType;
    ///
    /// struct EthereumParser;
    ///
    /// impl Chain for EthereumParser {
    ///     fn id(&self) -> &'static str {
    ///         "ethereum"
    ///     }
    /// #   fn parse(&self, _raw: &[u8]) -> Result<ParsedTx, ParseError> {
    /// #       Err(ParseError::UnknownTxType)
    /// #   }
    /// #   fn curve(&self) -> CurveType {
    /// #       CurveType::Secp256k1
    /// #   }
    /// }
    ///
    /// let parser = EthereumParser;
    /// assert_eq!(parser.id(), "ethereum");
    /// ```
    fn id(&self) -> &'static str;

    /// Parse raw transaction bytes into a [`ParsedTx`].
    ///
    /// This is the core method of the trait. It transforms chain-specific
    /// transaction bytes into a normalized format for policy evaluation.
    ///
    /// # Arguments
    ///
    /// * `raw` - The raw transaction bytes in the chain's native format
    ///
    /// # Returns
    ///
    /// * `Ok(ParsedTx)` - Successfully parsed transaction with all fields populated
    /// * `Err(ParseError)` - Parsing failed
    ///
    /// # Errors
    ///
    /// This method returns a [`ParseError`] in the following cases:
    /// - [`ParseError::UnknownTxType`] - Transaction type byte is not recognized
    /// - [`ParseError::InvalidRlp`] - RLP decoding failed (for Ethereum)
    /// - [`ParseError::MalformedTransaction`] - Transaction structure is invalid
    /// - [`ParseError::MalformedCalldata`] - Contract call data is invalid
    /// - [`ParseError::InvalidAddress`] - Address format is invalid
    ///
    /// # Transaction Hash
    ///
    /// The returned `ParsedTx.hash` must be the exact hash that will be signed.
    /// This is critical for security:
    /// - For Ethereum legacy: Keccak256 of RLP-encoded transaction without signature
    /// - For Ethereum EIP-155: Includes `chain_id` in the signing hash
    /// - For Ethereum typed: Domain-separated hash with type prefix
    /// - For Bitcoin: Double SHA256 of serialized transaction
    /// - For Solana: SHA256 of serialized message
    ///
    /// # Example
    ///
    /// ```
    /// use txgate_chain::Chain;
    /// use txgate_core::{ParsedTx, TxType, error::ParseError};
    /// # use txgate_crypto::CurveType;
    ///
    /// struct SimpleParser;
    ///
    /// impl Chain for SimpleParser {
    ///     fn id(&self) -> &'static str { "test" }
    ///
    ///     fn parse(&self, raw: &[u8]) -> Result<ParsedTx, ParseError> {
    ///         if raw.is_empty() {
    ///             return Err(ParseError::MalformedTransaction {
    ///                 context: "empty transaction data".to_string(),
    ///             });
    ///         }
    ///         // Parse the transaction...
    ///         Ok(ParsedTx::default())
    ///     }
    /// #   fn curve(&self) -> CurveType { CurveType::Secp256k1 }
    /// }
    /// ```
    fn parse(&self, raw: &[u8]) -> Result<ParsedTx, ParseError>;

    /// Returns the elliptic curve used by this chain.
    ///
    /// This is used to select the appropriate signer for the chain.
    /// Most EVM-compatible chains use secp256k1, while Solana uses Ed25519.
    ///
    /// # Curve Selection
    ///
    /// - [`CurveType::Secp256k1`] - Ethereum, Bitcoin, Tron, Ripple, most EVM chains
    /// - [`CurveType::Ed25519`] - Solana, NEAR, Cosmos (some chains)
    ///
    /// # Example
    ///
    /// ```
    /// use txgate_chain::Chain;
    /// use txgate_crypto::CurveType;
    /// # use txgate_core::{ParsedTx, error::ParseError};
    ///
    /// struct SolanaParser;
    ///
    /// impl Chain for SolanaParser {
    ///     fn id(&self) -> &'static str { "solana" }
    /// #   fn parse(&self, _raw: &[u8]) -> Result<ParsedTx, ParseError> {
    /// #       Err(ParseError::UnknownTxType)
    /// #   }
    ///     fn curve(&self) -> CurveType {
    ///         CurveType::Ed25519
    ///     }
    /// }
    ///
    /// let parser = SolanaParser;
    /// assert_eq!(parser.curve(), CurveType::Ed25519);
    /// ```
    fn curve(&self) -> CurveType;

    /// Check if this parser supports a specific transaction version/type.
    ///
    /// This method allows parsers to declare which transaction versions they
    /// can handle. The registry can use this to select the appropriate parser
    /// for a given transaction.
    ///
    /// # Arguments
    ///
    /// * `version` - Chain-specific version identifier
    ///
    /// # Returns
    ///
    /// * `true` if this parser can handle the version
    /// * `false` otherwise
    ///
    /// # Default Implementation
    ///
    /// The default implementation returns `true` for all versions, which is
    /// suitable for parsers that handle all known transaction types.
    ///
    /// # Version Semantics
    ///
    /// The meaning of `version` is chain-specific:
    /// - Ethereum: Transaction type (0=legacy, 1=EIP-2930, 2=EIP-1559, 3=EIP-4844)
    /// - Bitcoin: Transaction version field
    /// - Solana: Message version (0=legacy, 128+=versioned)
    ///
    /// # Example
    ///
    /// ```
    /// use txgate_chain::Chain;
    /// # use txgate_core::{ParsedTx, error::ParseError};
    /// # use txgate_crypto::CurveType;
    ///
    /// struct LegacyEthereumParser;
    ///
    /// impl Chain for LegacyEthereumParser {
    ///     fn id(&self) -> &'static str { "ethereum-legacy" }
    /// #   fn parse(&self, _raw: &[u8]) -> Result<ParsedTx, ParseError> {
    /// #       Err(ParseError::UnknownTxType)
    /// #   }
    /// #   fn curve(&self) -> CurveType { CurveType::Secp256k1 }
    ///
    ///     fn supports_version(&self, version: u8) -> bool {
    ///         // Only support legacy transactions (type 0)
    ///         version == 0
    ///     }
    /// }
    ///
    /// let parser = LegacyEthereumParser;
    /// assert!(parser.supports_version(0));  // Legacy
    /// assert!(!parser.supports_version(2)); // EIP-1559 not supported
    /// ```
    fn supports_version(&self, version: u8) -> bool {
        // Default: support all versions
        let _ = version;
        true
    }
}

// ============================================================================
// Mock Implementation for Testing
// ============================================================================

/// Error type for `MockChain` configuration.
///
/// This enum mirrors the common `ParseError` variants but is `Clone`-able
/// for use in mock configurations.
#[cfg(any(test, feature = "mock"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MockParseError {
    /// Unknown transaction type.
    UnknownTxType,
    /// Malformed transaction.
    MalformedTransaction,
    /// Malformed calldata.
    MalformedCalldata,
    /// Invalid address.
    InvalidAddress,
}

#[cfg(any(test, feature = "mock"))]
impl MockParseError {
    /// Convert to a real `ParseError`.
    #[must_use]
    pub fn to_parse_error(self, context: &str) -> ParseError {
        match self {
            Self::UnknownTxType => ParseError::UnknownTxType,
            Self::MalformedTransaction => ParseError::MalformedTransaction {
                context: context.to_string(),
            },
            Self::MalformedCalldata => ParseError::MalformedCalldata,
            Self::InvalidAddress => ParseError::InvalidAddress {
                address: context.to_string(),
            },
        }
    }
}

/// A mock chain implementation for testing.
///
/// This struct allows tests to configure the behavior of a chain parser
/// without implementing actual parsing logic.
///
/// # Example
///
/// ```
/// use txgate_chain::{Chain, MockChain, MockParseError};
/// use txgate_core::{ParsedTx, TxType, error::ParseError};
/// use txgate_crypto::CurveType;
///
/// // Create a mock that returns a successful parse result
/// let mock = MockChain {
///     id: "test-chain",
///     curve: CurveType::Secp256k1,
///     parse_result: Some(ParsedTx {
///         chain: "test-chain".to_string(),
///         tx_type: TxType::Transfer,
///         ..Default::default()
///     }),
///     parse_error: None,
/// };
///
/// let result = mock.parse(&[0x01, 0x02, 0x03]);
/// assert!(result.is_ok());
///
/// // Create a mock that returns an error
/// let error_mock = MockChain {
///     id: "failing-chain",
///     curve: CurveType::Ed25519,
///     parse_result: None,
///     parse_error: Some(MockParseError::UnknownTxType),
/// };
///
/// let result = error_mock.parse(&[0x01]);
/// assert!(matches!(result, Err(ParseError::UnknownTxType)));
/// ```
#[cfg(any(test, feature = "mock"))]
#[derive(Debug, Clone)]
pub struct MockChain {
    /// The chain identifier to return from `id()`.
    pub id: &'static str,

    /// The curve type to return from `curve()`.
    pub curve: CurveType,

    /// The parse result to return (if `parse_error` is `None`).
    pub parse_result: Option<ParsedTx>,

    /// The parse error to return (takes precedence over `parse_result`).
    pub parse_error: Option<MockParseError>,
}

#[cfg(any(test, feature = "mock"))]
impl Chain for MockChain {
    fn id(&self) -> &'static str {
        self.id
    }

    fn parse(&self, _raw: &[u8]) -> Result<ParsedTx, ParseError> {
        if let Some(error) = self.parse_error {
            return Err(error.to_parse_error("mock error"));
        }
        self.parse_result
            .clone()
            .ok_or_else(|| ParseError::MalformedTransaction {
                context: "mock not configured with parse_result".to_string(),
            })
    }

    fn curve(&self) -> CurveType {
        self.curve
    }
}

#[cfg(any(test, feature = "mock"))]
impl Default for MockChain {
    fn default() -> Self {
        Self {
            id: "mock",
            curve: CurveType::Secp256k1,
            parse_result: Some(ParsedTx::default()),
            parse_error: None,
        }
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
        clippy::unreadable_literal
    )]

    use super::*;
    use txgate_core::TxType;

    // ------------------------------------------------------------------------
    // MockChain Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_mock_chain_id() {
        let mock = MockChain {
            id: "test-chain",
            ..Default::default()
        };

        assert_eq!(mock.id(), "test-chain");
    }

    #[test]
    fn test_mock_chain_curve() {
        let mock_secp = MockChain {
            curve: CurveType::Secp256k1,
            ..Default::default()
        };
        assert_eq!(mock_secp.curve(), CurveType::Secp256k1);

        let mock_ed = MockChain {
            curve: CurveType::Ed25519,
            ..Default::default()
        };
        assert_eq!(mock_ed.curve(), CurveType::Ed25519);
    }

    #[test]
    fn test_mock_chain_parse_success() {
        let expected_tx = ParsedTx {
            hash: [0xab; 32],
            recipient: Some("0x1234".to_string()),
            chain: "ethereum".to_string(),
            tx_type: TxType::Transfer,
            ..Default::default()
        };

        let mock = MockChain {
            id: "ethereum",
            curve: CurveType::Secp256k1,
            parse_result: Some(expected_tx.clone()),
            parse_error: None,
        };

        let result = mock.parse(&[0x01, 0x02, 0x03]);
        assert!(result.is_ok());

        let parsed = result.unwrap();
        assert_eq!(parsed.hash, expected_tx.hash);
        assert_eq!(parsed.recipient, expected_tx.recipient);
        assert_eq!(parsed.chain, expected_tx.chain);
    }

    #[test]
    fn test_mock_chain_parse_error() {
        let mock = MockChain {
            id: "failing",
            curve: CurveType::Secp256k1,
            parse_result: None,
            parse_error: Some(super::MockParseError::UnknownTxType),
        };

        let result = mock.parse(&[0x01]);
        assert!(matches!(result, Err(ParseError::UnknownTxType)));
    }

    #[test]
    fn test_mock_chain_error_takes_precedence() {
        // If both parse_error and parse_result are set, error takes precedence
        let mock = MockChain {
            id: "test",
            curve: CurveType::Secp256k1,
            parse_result: Some(ParsedTx::default()),
            parse_error: Some(super::MockParseError::MalformedCalldata),
        };

        let result = mock.parse(&[0x01]);
        assert!(matches!(result, Err(ParseError::MalformedCalldata)));
    }

    #[test]
    fn test_mock_chain_no_result_configured() {
        let mock = MockChain {
            id: "unconfigured",
            curve: CurveType::Secp256k1,
            parse_result: None,
            parse_error: None,
        };

        let result = mock.parse(&[0x01]);
        assert!(matches!(
            result,
            Err(ParseError::MalformedTransaction { .. })
        ));
    }

    #[test]
    fn test_mock_chain_default() {
        let mock = MockChain::default();

        assert_eq!(mock.id(), "mock");
        assert_eq!(mock.curve(), CurveType::Secp256k1);
        assert!(mock.parse(&[]).is_ok());
    }

    // ------------------------------------------------------------------------
    // supports_version Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_default_supports_all_versions() {
        let mock = MockChain::default();

        // Default implementation should support all versions
        assert!(mock.supports_version(0));
        assert!(mock.supports_version(1));
        assert!(mock.supports_version(2));
        assert!(mock.supports_version(3));
        assert!(mock.supports_version(255));
    }

    // ------------------------------------------------------------------------
    // Trait Object Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_chain_as_trait_object() {
        let mock = MockChain::default();
        let chain: Box<dyn Chain> = Box::new(mock);

        assert_eq!(chain.id(), "mock");
        assert_eq!(chain.curve(), CurveType::Secp256k1);
        assert!(chain.parse(&[]).is_ok());
    }

    #[test]
    fn test_chain_trait_object_vec() {
        let mock1 = MockChain {
            id: "chain1",
            ..Default::default()
        };
        let mock2 = MockChain {
            id: "chain2",
            curve: CurveType::Ed25519,
            ..Default::default()
        };

        let chains: Vec<Box<dyn Chain>> = vec![Box::new(mock1), Box::new(mock2)];

        assert_eq!(chains.len(), 2);
        assert_eq!(chains[0].id(), "chain1");
        assert_eq!(chains[1].id(), "chain2");
        assert_eq!(chains[0].curve(), CurveType::Secp256k1);
        assert_eq!(chains[1].curve(), CurveType::Ed25519);
    }

    #[test]
    fn test_find_chain_by_id() {
        let chains: Vec<Box<dyn Chain>> = vec![
            Box::new(MockChain {
                id: "ethereum",
                curve: CurveType::Secp256k1,
                ..Default::default()
            }),
            Box::new(MockChain {
                id: "solana",
                curve: CurveType::Ed25519,
                ..Default::default()
            }),
        ];

        let found = chains.iter().find(|c| c.id() == "ethereum");
        assert!(found.is_some());
        assert_eq!(found.unwrap().curve(), CurveType::Secp256k1);

        let not_found = chains.iter().find(|c| c.id() == "bitcoin");
        assert!(not_found.is_none());
    }

    // ------------------------------------------------------------------------
    // Send + Sync Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_chain_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<MockChain>();
    }

    #[test]
    fn test_chain_trait_object_is_send_sync() {
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        assert_send_sync::<dyn Chain>();
    }

    #[test]
    fn test_boxed_chain_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Box<dyn Chain>>();
    }

    // ------------------------------------------------------------------------
    // Custom Implementation Test
    // ------------------------------------------------------------------------

    /// A custom chain implementation for testing custom behavior.
    struct CustomVersionedChain {
        supported_versions: Vec<u8>,
    }

    impl Chain for CustomVersionedChain {
        fn id(&self) -> &'static str {
            "custom-versioned"
        }

        fn parse(&self, raw: &[u8]) -> Result<ParsedTx, ParseError> {
            if raw.is_empty() {
                return Err(ParseError::malformed_transaction("empty data"));
            }

            let version = raw[0];
            if !self.supports_version(version) {
                return Err(ParseError::UnknownTxType);
            }

            Ok(ParsedTx {
                chain: self.id().to_string(),
                ..Default::default()
            })
        }

        fn curve(&self) -> CurveType {
            CurveType::Secp256k1
        }

        fn supports_version(&self, version: u8) -> bool {
            self.supported_versions.contains(&version)
        }
    }

    #[test]
    fn test_custom_versioned_chain() {
        let chain = CustomVersionedChain {
            supported_versions: vec![0, 2],
        };

        assert!(chain.supports_version(0));
        assert!(!chain.supports_version(1));
        assert!(chain.supports_version(2));
        assert!(!chain.supports_version(3));

        // Version 0 should parse successfully
        let result = chain.parse(&[0x00, 0x01, 0x02]);
        assert!(result.is_ok());

        // Version 1 should fail
        let result = chain.parse(&[0x01, 0x01, 0x02]);
        assert!(matches!(result, Err(ParseError::UnknownTxType)));

        // Empty data should fail
        let result = chain.parse(&[]);
        assert!(matches!(
            result,
            Err(ParseError::MalformedTransaction { .. })
        ));
    }
}
