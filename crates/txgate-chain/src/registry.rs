//! Chain registry for runtime chain lookup.
//!
//! This module provides the [`ChainRegistry`] struct that holds all chain parsers
//! and provides runtime chain lookup by identifier.
//!
//! # Design
//!
//! The registry is designed to be:
//! - **Thread-safe**: Uses `Arc` internally for cheap cloning across async tasks
//! - **Immutable in production**: The `new()` constructor registers all supported chains
//! - **Testable**: Provides `empty()` and `register()` for testing with mock chains
//!
//! # Example
//!
//! ```
//! use txgate_chain::ChainRegistry;
//!
//! let registry = ChainRegistry::new();
//!
//! // List supported chains
//! println!("Supported chains: {:?}", registry.supported_chains());
//!
//! // Look up a chain parser
//! if let Some(parser) = registry.get("ethereum") {
//!     println!("Found ethereum parser: {}", parser.id());
//! }
//!
//! // Check if a chain is supported
//! if registry.supports("ethereum") {
//!     println!("Ethereum is supported!");
//! }
//! ```
//!
//! # Thread Safety
//!
//! The registry can be safely shared across threads and async tasks:
//!
//! ```
//! use txgate_chain::ChainRegistry;
//! use std::sync::Arc;
//!
//! let registry = ChainRegistry::new();
//!
//! // Clone is cheap (Arc internally)
//! let registry_clone = registry.clone();
//!
//! // Both can be used concurrently
//! std::thread::spawn(move || {
//!     let _ = registry_clone.supported_chains();
//! });
//! ```

use std::collections::HashMap;
use std::sync::Arc;

use crate::Chain;

/// Registry of supported blockchain parsers.
///
/// The registry provides runtime lookup of chain parsers by their identifier.
/// It is designed to be cloned cheaply (via [`Arc`]) for use across async tasks.
///
/// # Construction
///
/// Use [`ChainRegistry::new()`] to create a registry with all production chains,
/// or [`ChainRegistry::empty()`] for testing.
///
/// # Example
///
/// ```
/// use txgate_chain::ChainRegistry;
///
/// let registry = ChainRegistry::new();
/// println!("Supported chains: {:?}", registry.supported_chains());
///
/// if let Some(parser) = registry.get("ethereum") {
///     // Use parser...
///     println!("Found: {}", parser.id());
/// }
/// ```
#[derive(Clone)]
pub struct ChainRegistry {
    chains: Arc<HashMap<String, Arc<dyn Chain>>>,
}

impl ChainRegistry {
    /// Create a new registry with all supported chain parsers.
    ///
    /// Currently supported chains:
    /// - `ethereum` - Ethereum and EVM-compatible chains
    /// - `bitcoin` - Bitcoin (Legacy, `SegWit`, Taproot)
    /// - `solana` - Solana (Legacy and Versioned messages)
    ///
    /// # Example
    ///
    /// ```
    /// use txgate_chain::ChainRegistry;
    ///
    /// let registry = ChainRegistry::new();
    /// assert_eq!(registry.len(), 3);
    /// assert!(registry.supports("ethereum"));
    /// assert!(registry.supports("bitcoin"));
    /// assert!(registry.supports("solana"));
    /// ```
    #[must_use]
    pub fn new() -> Self {
        let mut chains: HashMap<String, Arc<dyn Chain>> = HashMap::new();

        // Register supported chains
        chains.insert(
            "ethereum".to_string(),
            Arc::new(crate::EthereumParser::new()),
        );
        chains.insert(
            "bitcoin".to_string(),
            Arc::new(crate::BitcoinParser::mainnet()),
        );
        chains.insert("solana".to_string(), Arc::new(crate::SolanaParser::new()));

        Self {
            chains: Arc::new(chains),
        }
    }

    /// Create an empty registry (for testing).
    ///
    /// This is useful when you need a registry without any production chains,
    /// typically for unit tests where you want to register mock chains.
    ///
    /// # Example
    ///
    /// ```
    /// use txgate_chain::ChainRegistry;
    ///
    /// let registry = ChainRegistry::empty();
    /// assert!(registry.is_empty());
    /// assert_eq!(registry.len(), 0);
    /// ```
    #[must_use]
    pub fn empty() -> Self {
        Self {
            chains: Arc::new(HashMap::new()),
        }
    }

    /// Register a chain parser.
    ///
    /// This is primarily used for testing with mock parsers.
    /// In production, use [`ChainRegistry::new()`] which registers all supported chains.
    ///
    /// # Arguments
    ///
    /// * `chain` - The chain parser to register
    ///
    /// # Note
    ///
    /// If a chain with the same ID is already registered, it will be replaced.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use txgate_chain::{ChainRegistry, MockChain};
    ///
    /// let mut registry = ChainRegistry::empty();
    ///
    /// let mock = MockChain {
    ///     id: "test-chain",
    ///     ..Default::default()
    /// };
    ///
    /// registry.register(mock);
    ///
    /// assert!(registry.supports("test-chain"));
    /// assert_eq!(registry.len(), 1);
    /// ```
    pub fn register<C: Chain + 'static>(&mut self, chain: C) {
        let chains = Arc::make_mut(&mut self.chains);
        chains.insert(chain.id().to_string(), Arc::new(chain));
    }

    /// Look up a chain parser by ID.
    ///
    /// # Arguments
    ///
    /// * `chain_id` - The chain identifier (e.g., "ethereum", "bitcoin")
    ///
    /// # Returns
    ///
    /// * `Some(&dyn Chain)` if the chain is supported
    /// * `None` if the chain is not supported
    ///
    /// # Example
    ///
    /// ```
    /// use txgate_chain::ChainRegistry;
    ///
    /// let registry = ChainRegistry::new();
    ///
    /// // Look up a chain (returns None if not registered)
    /// let parser = registry.get("ethereum");
    /// // Currently None - parsers will be added in future tasks
    ///
    /// // Not found
    /// let missing = registry.get("nonexistent");
    /// assert!(missing.is_none());
    /// ```
    #[must_use]
    pub fn get(&self, chain_id: &str) -> Option<&dyn Chain> {
        self.chains.get(chain_id).map(AsRef::as_ref)
    }

    /// List all supported chain IDs.
    ///
    /// Returns a sorted list of chain identifiers for consistency.
    ///
    /// # Example
    ///
    /// ```
    /// use txgate_chain::ChainRegistry;
    ///
    /// let registry = ChainRegistry::new();
    ///
    /// // Get list of all supported chains (sorted alphabetically)
    /// let chains = registry.supported_chains();
    /// assert_eq!(chains, vec!["bitcoin", "ethereum", "solana"]);
    /// ```
    #[must_use]
    pub fn supported_chains(&self) -> Vec<&str> {
        let mut chains: Vec<&str> = self.chains.keys().map(String::as_str).collect();
        chains.sort_unstable();
        chains
    }

    /// Check if a chain is supported.
    ///
    /// # Arguments
    ///
    /// * `chain_id` - The chain identifier to check
    ///
    /// # Returns
    ///
    /// * `true` if the chain is registered
    /// * `false` otherwise
    ///
    /// # Example
    ///
    /// ```
    /// use txgate_chain::ChainRegistry;
    ///
    /// let registry = ChainRegistry::new();
    ///
    /// // Check if a chain is supported
    /// assert!(registry.supports("ethereum"));
    /// assert!(registry.supports("bitcoin"));
    /// assert!(registry.supports("solana"));
    /// assert!(!registry.supports("unknown"));
    /// ```
    #[must_use]
    pub fn supports(&self, chain_id: &str) -> bool {
        self.chains.contains_key(chain_id)
    }

    /// Get the number of registered chains.
    ///
    /// # Example
    ///
    /// ```
    /// use txgate_chain::ChainRegistry;
    ///
    /// let registry = ChainRegistry::new();
    /// assert_eq!(registry.len(), 3);  // ethereum, bitcoin, solana
    ///
    /// let registry = ChainRegistry::empty();
    /// assert_eq!(registry.len(), 0);
    /// ```
    #[must_use]
    pub fn len(&self) -> usize {
        self.chains.len()
    }

    /// Check if the registry is empty.
    ///
    /// # Example
    ///
    /// ```
    /// use txgate_chain::ChainRegistry;
    ///
    /// let registry = ChainRegistry::new();
    /// assert!(!registry.is_empty());  // has 3 chains registered
    ///
    /// let registry = ChainRegistry::empty();
    /// assert!(registry.is_empty());
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.chains.is_empty()
    }
}

impl Default for ChainRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ChainRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainRegistry")
            .field("chains", &self.supported_chains())
            .finish()
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
    use crate::{MockChain, MockParseError};
    use txgate_core::TxType;
    use txgate_crypto::CurveType;

    // ------------------------------------------------------------------------
    // Construction Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_new_registry() {
        let registry = ChainRegistry::new();
        // Should have ethereum, bitcoin, and solana
        assert_eq!(registry.len(), 3);
        assert!(registry.supports("ethereum"));
        assert!(registry.supports("bitcoin"));
        assert!(registry.supports("solana"));
    }

    #[test]
    fn test_empty_registry() {
        let registry = ChainRegistry::empty();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
        assert!(registry.supported_chains().is_empty());
    }

    #[test]
    fn test_default_registry() {
        let registry = ChainRegistry::default();
        // Default is same as new()
        assert_eq!(registry.len(), 3);
    }

    // ------------------------------------------------------------------------
    // Registration Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_register_chain() {
        let mut registry = ChainRegistry::empty();

        let mock = MockChain {
            id: "test-chain",
            curve: CurveType::Secp256k1,
            ..Default::default()
        };

        registry.register(mock);

        assert!(!registry.is_empty());
        assert_eq!(registry.len(), 1);
        assert!(registry.supports("test-chain"));
    }

    #[test]
    fn test_register_multiple_chains() {
        let mut registry = ChainRegistry::empty();

        registry.register(MockChain {
            id: "ethereum",
            curve: CurveType::Secp256k1,
            ..Default::default()
        });
        registry.register(MockChain {
            id: "solana",
            curve: CurveType::Ed25519,
            ..Default::default()
        });
        registry.register(MockChain {
            id: "bitcoin",
            curve: CurveType::Secp256k1,
            ..Default::default()
        });

        assert_eq!(registry.len(), 3);
        assert!(registry.supports("ethereum"));
        assert!(registry.supports("solana"));
        assert!(registry.supports("bitcoin"));
    }

    #[test]
    fn test_register_overwrites_existing() {
        let mut registry = ChainRegistry::empty();

        registry.register(MockChain {
            id: "ethereum",
            curve: CurveType::Secp256k1,
            parse_error: Some(MockParseError::UnknownTxType),
            ..Default::default()
        });

        // Verify first registration
        let parser = registry.get("ethereum").unwrap();
        assert!(parser.parse(&[]).is_err());

        // Overwrite with new parser
        registry.register(MockChain {
            id: "ethereum",
            curve: CurveType::Secp256k1,
            parse_error: None,
            ..Default::default()
        });

        // Verify overwrite
        assert_eq!(registry.len(), 1); // Still only 1
        let parser = registry.get("ethereum").unwrap();
        assert!(parser.parse(&[]).is_ok()); // Now succeeds
    }

    // ------------------------------------------------------------------------
    // Lookup Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_get_existing_chain() {
        let mut registry = ChainRegistry::empty();
        registry.register(MockChain {
            id: "ethereum",
            curve: CurveType::Secp256k1,
            ..Default::default()
        });

        let parser = registry.get("ethereum");
        assert!(parser.is_some());

        let parser = parser.unwrap();
        assert_eq!(parser.id(), "ethereum");
        assert_eq!(parser.curve(), CurveType::Secp256k1);
    }

    #[test]
    fn test_get_nonexistent_chain() {
        let registry = ChainRegistry::empty();

        let parser = registry.get("ethereum");
        assert!(parser.is_none());

        let parser = registry.get("nonexistent");
        assert!(parser.is_none());
    }

    #[test]
    fn test_get_and_parse() {
        let mut registry = ChainRegistry::empty();

        let expected_tx = txgate_core::ParsedTx {
            chain: "ethereum".to_string(),
            tx_type: TxType::Transfer,
            recipient: Some("0x1234".to_string()),
            ..Default::default()
        };

        registry.register(MockChain {
            id: "ethereum",
            curve: CurveType::Secp256k1,
            parse_result: Some(expected_tx.clone()),
            parse_error: None,
        });

        let parser = registry.get("ethereum").unwrap();
        let result = parser.parse(&[0x02, 0x01, 0x02, 0x03]);

        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.chain, "ethereum");
        assert_eq!(parsed.tx_type, TxType::Transfer);
        assert_eq!(parsed.recipient, Some("0x1234".to_string()));
    }

    // ------------------------------------------------------------------------
    // Supported Chains Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_supported_chains_empty() {
        let registry = ChainRegistry::empty();
        assert!(registry.supported_chains().is_empty());
    }

    #[test]
    fn test_supported_chains_sorted() {
        let mut registry = ChainRegistry::empty();

        // Register in non-alphabetical order
        registry.register(MockChain {
            id: "solana",
            ..Default::default()
        });
        registry.register(MockChain {
            id: "ethereum",
            ..Default::default()
        });
        registry.register(MockChain {
            id: "bitcoin",
            ..Default::default()
        });
        registry.register(MockChain {
            id: "arbitrum",
            ..Default::default()
        });

        let chains = registry.supported_chains();

        // Should be sorted alphabetically
        assert_eq!(chains, vec!["arbitrum", "bitcoin", "ethereum", "solana"]);
    }

    // ------------------------------------------------------------------------
    // Supports Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_supports_registered_chain() {
        let mut registry = ChainRegistry::empty();
        registry.register(MockChain {
            id: "ethereum",
            ..Default::default()
        });

        assert!(registry.supports("ethereum"));
    }

    #[test]
    fn test_supports_unregistered_chain() {
        let registry = ChainRegistry::empty();
        assert!(!registry.supports("ethereum"));
        assert!(!registry.supports("bitcoin"));
        assert!(!registry.supports(""));
    }

    // ------------------------------------------------------------------------
    // Clone Tests (Arc sharing)
    // ------------------------------------------------------------------------

    #[test]
    fn test_clone_shares_arc() {
        let mut registry = ChainRegistry::empty();
        registry.register(MockChain {
            id: "ethereum",
            ..Default::default()
        });

        let clone = registry.clone();

        // Both should see the same chains
        assert_eq!(registry.len(), clone.len());
        assert!(registry.supports("ethereum"));
        assert!(clone.supports("ethereum"));

        // Arc should be shared (same pointer)
        assert!(Arc::ptr_eq(&registry.chains, &clone.chains));
    }

    #[test]
    fn test_clone_independent_mutation() {
        let mut registry = ChainRegistry::empty();
        registry.register(MockChain {
            id: "ethereum",
            ..Default::default()
        });

        let mut clone = registry.clone();

        // Mutate clone
        clone.register(MockChain {
            id: "bitcoin",
            ..Default::default()
        });

        // Original should be unaffected (Arc::make_mut creates new allocation)
        assert_eq!(registry.len(), 1);
        assert!(registry.supports("ethereum"));
        assert!(!registry.supports("bitcoin"));

        // Clone should have both
        assert_eq!(clone.len(), 2);
        assert!(clone.supports("ethereum"));
        assert!(clone.supports("bitcoin"));

        // Arcs should no longer be shared
        assert!(!Arc::ptr_eq(&registry.chains, &clone.chains));
    }

    // ------------------------------------------------------------------------
    // Thread Safety Tests (Send + Sync)
    // ------------------------------------------------------------------------

    #[test]
    fn test_registry_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<ChainRegistry>();
    }

    #[test]
    fn test_registry_is_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<ChainRegistry>();
    }

    #[test]
    fn test_registry_across_threads() {
        let mut registry = ChainRegistry::empty();
        registry.register(MockChain {
            id: "ethereum",
            ..Default::default()
        });

        let clone = registry.clone();

        let handle = std::thread::spawn(move || {
            assert!(clone.supports("ethereum"));
            clone.len()
        });

        let result = handle.join().unwrap();
        assert_eq!(result, 1);

        // Original still works
        assert!(registry.supports("ethereum"));
    }

    // ------------------------------------------------------------------------
    // Debug Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_debug_format() {
        let mut registry = ChainRegistry::empty();
        registry.register(MockChain {
            id: "ethereum",
            ..Default::default()
        });
        registry.register(MockChain {
            id: "bitcoin",
            ..Default::default()
        });

        let debug_str = format!("{registry:?}");
        assert!(debug_str.contains("ChainRegistry"));
        assert!(debug_str.contains("bitcoin"));
        assert!(debug_str.contains("ethereum"));
    }

    // ------------------------------------------------------------------------
    // Edge Cases
    // ------------------------------------------------------------------------

    #[test]
    fn test_empty_chain_id() {
        let mut registry = ChainRegistry::empty();
        registry.register(MockChain {
            id: "",
            ..Default::default()
        });

        assert!(registry.supports(""));
        assert!(registry.get("").is_some());
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn test_chain_with_special_characters() {
        let mut registry = ChainRegistry::empty();
        registry.register(MockChain {
            id: "arbitrum-one",
            ..Default::default()
        });
        registry.register(MockChain {
            id: "polygon_pos",
            ..Default::default()
        });

        assert!(registry.supports("arbitrum-one"));
        assert!(registry.supports("polygon_pos"));
    }

    #[test]
    fn test_len_and_is_empty_consistency() {
        let mut registry = ChainRegistry::empty();

        // Empty
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);

        // Add one
        registry.register(MockChain {
            id: "eth",
            ..Default::default()
        });
        assert!(!registry.is_empty());
        assert_eq!(registry.len(), 1);

        // Add another
        registry.register(MockChain {
            id: "btc",
            ..Default::default()
        });
        assert!(!registry.is_empty());
        assert_eq!(registry.len(), 2);
    }
}
