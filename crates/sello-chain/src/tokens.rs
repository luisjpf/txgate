//! Token registry for ERC-20 tokens.
//!
//! Provides metadata about known tokens for policy enrichment, including:
//! - Token symbol and name
//! - Decimal places
//! - Risk classification
//!
//! # Example
//!
//! ```rust
//! use sello_chain::tokens::{TokenRegistry, TokenInfo, RiskLevel};
//!
//! // Create registry with built-in mainnet tokens
//! let registry = TokenRegistry::with_builtins();
//!
//! // Look up USDC by address
//! let usdc_addr = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".parse().unwrap();
//! if let Some(info) = registry.get(&usdc_addr) {
//!     assert_eq!(info.symbol, "USDC");
//!     assert_eq!(info.decimals, 6);
//!     assert_eq!(info.risk_level, RiskLevel::Low);
//! }
//!
//! // Unknown tokens get default high-risk classification
//! let unknown = "0x0000000000000000000000000000000000000001".parse().unwrap();
//! let info = registry.get_or_default(&unknown);
//! assert_eq!(info.risk_level, RiskLevel::High);
//! ```

use alloy_primitives::Address;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Risk level classification for tokens.
///
/// Used by the policy engine to apply different rules based on token risk.
/// Unknown tokens default to `High` risk as a security measure.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    /// Low risk - Major stablecoins, wrapped native assets (USDC, WETH, etc.)
    Low,
    /// Medium risk - Established defi tokens (UNI, AAVE, etc.)
    Medium,
    /// High risk - Unknown tokens, newly deployed contracts
    #[default]
    High,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
        }
    }
}

/// Information about an ERC-20 token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenInfo {
    /// Token symbol (e.g., "USDC", "WETH")
    pub symbol: String,

    /// Number of decimals (typically 6 for USDC, 18 for most tokens)
    pub decimals: u8,

    /// Risk classification
    pub risk_level: RiskLevel,

    /// Optional token name (e.g., "USD Coin")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl TokenInfo {
    /// Create a new `TokenInfo`.
    #[must_use]
    pub fn new(symbol: impl Into<String>, decimals: u8, risk_level: RiskLevel) -> Self {
        Self {
            symbol: symbol.into(),
            decimals,
            risk_level,
            name: None,
        }
    }

    /// Create a `TokenInfo` with a name.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }
}

/// Registry of known ERC-20 tokens.
///
/// Provides lookup of token metadata by contract address for policy enrichment.
/// Unknown tokens are assigned `RiskLevel::High` by default.
#[derive(Debug, Clone, Default)]
pub struct TokenRegistry {
    tokens: HashMap<Address, TokenInfo>,
}

impl TokenRegistry {
    /// Create an empty token registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tokens: HashMap::new(),
        }
    }

    /// Create a registry with built-in tokens (mainnet addresses).
    ///
    /// Includes major stablecoins and wrapped assets:
    /// - USDC (`0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48`)
    /// - USDT (`0xdAC17F958D2ee523a2206206994597C13D831ec7`)
    /// - DAI  (`0x6B175474E89094C44Da98b954EedfcE8F7e08E8A`)
    /// - WETH (`0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2`)
    /// - WBTC (`0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599`)
    #[must_use]
    pub fn with_builtins() -> Self {
        let mut registry = Self::new();

        // Major stablecoins (Low risk)
        // USDC - USD Coin
        if let Ok(addr) = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".parse::<Address>() {
            registry.register(
                addr,
                TokenInfo::new("USDC", 6, RiskLevel::Low).with_name("USD Coin"),
            );
        }

        // USDT - Tether USD
        if let Ok(addr) = "0xdAC17F958D2ee523a2206206994597C13D831ec7".parse::<Address>() {
            registry.register(
                addr,
                TokenInfo::new("USDT", 6, RiskLevel::Low).with_name("Tether USD"),
            );
        }

        // DAI - Dai Stablecoin
        if let Ok(addr) = "0x6B175474E89094C44Da98b954EedfcE8F7e08E8A".parse::<Address>() {
            registry.register(
                addr,
                TokenInfo::new("DAI", 18, RiskLevel::Low).with_name("Dai Stablecoin"),
            );
        }

        // Wrapped assets (Low risk)
        // WETH - Wrapped Ether
        if let Ok(addr) = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2".parse::<Address>() {
            registry.register(
                addr,
                TokenInfo::new("WETH", 18, RiskLevel::Low).with_name("Wrapped Ether"),
            );
        }

        // WBTC - Wrapped BTC
        if let Ok(addr) = "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599".parse::<Address>() {
            registry.register(
                addr,
                TokenInfo::new("WBTC", 8, RiskLevel::Low).with_name("Wrapped BTC"),
            );
        }

        registry
    }

    /// Register a token in the registry.
    pub fn register(&mut self, address: Address, info: TokenInfo) {
        self.tokens.insert(address, info);
    }

    /// Look up token info by address.
    ///
    /// # Returns
    /// * `Some(&TokenInfo)` if the token is known
    /// * `None` if the token is unknown
    #[must_use]
    pub fn get(&self, address: &Address) -> Option<&TokenInfo> {
        self.tokens.get(address)
    }

    /// Look up token info, returning default for unknown tokens.
    ///
    /// Unknown tokens are assigned:
    /// - Symbol: Contract address (shortened, e.g., "0xA0b8...eB48")
    /// - Decimals: 18 (assumed)
    /// - Risk: High
    #[must_use]
    pub fn get_or_default(&self, address: &Address) -> TokenInfo {
        self.tokens.get(address).cloned().unwrap_or_else(|| {
            let addr_str = format!("{address:?}");
            // Create shortened address symbol: 0xXXXX...XXXX
            let symbol = if addr_str.len() >= 42 {
                format!(
                    "{}...{}",
                    addr_str.get(..6).unwrap_or("0x????"),
                    addr_str.get(38..42).unwrap_or("????")
                )
            } else {
                addr_str
            };
            TokenInfo::new(symbol, 18, RiskLevel::High)
        })
    }

    /// Check if a token is known.
    #[must_use]
    pub fn contains(&self, address: &Address) -> bool {
        self.tokens.contains_key(address)
    }

    /// Get all registered token addresses.
    pub fn addresses(&self) -> impl Iterator<Item = &Address> {
        self.tokens.keys()
    }

    /// Get the number of registered tokens.
    #[must_use]
    pub fn len(&self) -> usize {
        self.tokens.len()
    }

    /// Check if the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }

    /// Load tokens from a JSON string.
    ///
    /// Expected format:
    /// ```json
    /// {
    ///   "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48": {
    ///     "symbol": "USDC",
    ///     "decimals": 6,
    ///     "risk_level": "low",
    ///     "name": "USD Coin"
    ///   }
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the JSON is malformed or cannot be parsed.
    pub fn load_json(&mut self, json: &str) -> Result<usize, serde_json::Error> {
        let tokens: HashMap<String, TokenInfo> = serde_json::from_str(json)?;
        let mut count = 0;
        for (addr_str, info) in tokens {
            if let Ok(address) = addr_str.parse::<Address>() {
                self.register(address, info);
                count += 1;
            }
        }
        Ok(count)
    }

    /// Export registry to JSON string.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        let map: HashMap<String, &TokenInfo> = self
            .tokens
            .iter()
            .map(|(addr, info)| (format!("{addr:?}"), info))
            .collect();
        serde_json::to_string_pretty(&map)
    }
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

    #[test]
    fn test_empty_registry() {
        let registry = TokenRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn test_with_builtins_has_expected_tokens() {
        let registry = TokenRegistry::with_builtins();

        // Should have 5 built-in tokens
        assert_eq!(registry.len(), 5);
        assert!(!registry.is_empty());

        // Check USDC
        let usdc_addr: Address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
            .parse()
            .expect("valid address");
        let usdc = registry.get(&usdc_addr).expect("USDC should be registered");
        assert_eq!(usdc.symbol, "USDC");
        assert_eq!(usdc.decimals, 6);
        assert_eq!(usdc.risk_level, RiskLevel::Low);
        assert_eq!(usdc.name, Some("USD Coin".to_string()));

        // Check USDT
        let usdt_addr: Address = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
            .parse()
            .expect("valid address");
        assert!(registry.contains(&usdt_addr));

        // Check DAI
        let dai_addr: Address = "0x6B175474E89094C44Da98b954EedfcE8F7e08E8A"
            .parse()
            .expect("valid address");
        let dai = registry.get(&dai_addr).expect("DAI should be registered");
        assert_eq!(dai.symbol, "DAI");
        assert_eq!(dai.decimals, 18);

        // Check WETH
        let weth_addr: Address = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
            .parse()
            .expect("valid address");
        let weth = registry.get(&weth_addr).expect("WETH should be registered");
        assert_eq!(weth.symbol, "WETH");
        assert_eq!(weth.decimals, 18);

        // Check WBTC
        let wbtc_addr: Address = "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599"
            .parse()
            .expect("valid address");
        let wbtc = registry.get(&wbtc_addr).expect("WBTC should be registered");
        assert_eq!(wbtc.symbol, "WBTC");
        assert_eq!(wbtc.decimals, 8);
    }

    #[test]
    fn test_lookup_found() {
        let registry = TokenRegistry::with_builtins();
        let usdc_addr: Address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
            .parse()
            .expect("valid address");

        let info = registry.get(&usdc_addr);
        assert!(info.is_some());
        assert_eq!(info.expect("checked above").symbol, "USDC");
    }

    #[test]
    fn test_lookup_not_found() {
        let registry = TokenRegistry::with_builtins();
        let unknown_addr: Address = "0x0000000000000000000000000000000000000001"
            .parse()
            .expect("valid address");

        assert!(registry.get(&unknown_addr).is_none());
        assert!(!registry.contains(&unknown_addr));
    }

    #[test]
    fn test_get_or_default_for_unknown_tokens() {
        let registry = TokenRegistry::with_builtins();
        let unknown_addr: Address = "0x1234567890123456789012345678901234567890"
            .parse()
            .expect("valid address");

        let info = registry.get_or_default(&unknown_addr);

        // Unknown tokens get high risk and 18 decimals
        assert_eq!(info.risk_level, RiskLevel::High);
        assert_eq!(info.decimals, 18);
        // Symbol should be shortened address
        assert!(info.symbol.contains("0x1234"));
        assert!(info.symbol.contains("7890"));
    }

    #[test]
    fn test_get_or_default_for_known_tokens() {
        let registry = TokenRegistry::with_builtins();
        let usdc_addr: Address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
            .parse()
            .expect("valid address");

        let info = registry.get_or_default(&usdc_addr);

        // Should return actual token info, not default
        assert_eq!(info.symbol, "USDC");
        assert_eq!(info.decimals, 6);
        assert_eq!(info.risk_level, RiskLevel::Low);
    }

    #[test]
    fn test_register() {
        let mut registry = TokenRegistry::new();

        let addr: Address = "0x1234567890123456789012345678901234567890"
            .parse()
            .expect("valid address");
        let info = TokenInfo::new("TEST", 18, RiskLevel::Medium).with_name("Test Token");

        registry.register(addr, info);

        assert_eq!(registry.len(), 1);
        assert!(registry.contains(&addr));

        let retrieved = registry.get(&addr).expect("should be registered");
        assert_eq!(retrieved.symbol, "TEST");
        assert_eq!(retrieved.decimals, 18);
        assert_eq!(retrieved.risk_level, RiskLevel::Medium);
        assert_eq!(retrieved.name, Some("Test Token".to_string()));
    }

    #[test]
    fn test_register_overwrites() {
        let mut registry = TokenRegistry::new();

        let addr: Address = "0x1234567890123456789012345678901234567890"
            .parse()
            .expect("valid address");

        registry.register(addr, TokenInfo::new("OLD", 18, RiskLevel::High));
        registry.register(addr, TokenInfo::new("NEW", 6, RiskLevel::Low));

        assert_eq!(registry.len(), 1);
        let info = registry.get(&addr).expect("should be registered");
        assert_eq!(info.symbol, "NEW");
        assert_eq!(info.decimals, 6);
        assert_eq!(info.risk_level, RiskLevel::Low);
    }

    #[test]
    fn test_load_json() {
        let mut registry = TokenRegistry::new();

        let json = r#"{
            "0x1234567890123456789012345678901234567890": {
                "symbol": "TEST",
                "decimals": 18,
                "risk_level": "medium",
                "name": "Test Token"
            },
            "0xabcdef0123456789abcdef0123456789abcdef01": {
                "symbol": "ABC",
                "decimals": 6,
                "risk_level": "low"
            }
        }"#;

        let count = registry.load_json(json).expect("valid JSON");
        assert_eq!(count, 2);
        assert_eq!(registry.len(), 2);

        let test_addr: Address = "0x1234567890123456789012345678901234567890"
            .parse()
            .expect("valid address");
        let test_info = registry.get(&test_addr).expect("should be registered");
        assert_eq!(test_info.symbol, "TEST");
        assert_eq!(test_info.risk_level, RiskLevel::Medium);
        assert_eq!(test_info.name, Some("Test Token".to_string()));

        let abc_addr: Address = "0xabcdef0123456789abcdef0123456789abcdef01"
            .parse()
            .expect("valid address");
        let abc_info = registry.get(&abc_addr).expect("should be registered");
        assert_eq!(abc_info.symbol, "ABC");
        assert_eq!(abc_info.decimals, 6);
        assert_eq!(abc_info.risk_level, RiskLevel::Low);
        assert_eq!(abc_info.name, None);
    }

    #[test]
    fn test_load_json_invalid() {
        let mut registry = TokenRegistry::new();

        let result = registry.load_json("not valid json");
        assert!(result.is_err());
    }

    #[test]
    fn test_load_json_skips_invalid_addresses() {
        let mut registry = TokenRegistry::new();

        let json = r#"{
            "not-an-address": {
                "symbol": "SKIP",
                "decimals": 18,
                "risk_level": "high"
            },
            "0x1234567890123456789012345678901234567890": {
                "symbol": "VALID",
                "decimals": 18,
                "risk_level": "low"
            }
        }"#;

        let count = registry.load_json(json).expect("valid JSON");
        // Only the valid address should be loaded
        assert_eq!(count, 1);
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn test_risk_level_serialization() {
        // Test Low
        let json = serde_json::to_string(&RiskLevel::Low).expect("serialize");
        assert_eq!(json, r#""low""#);
        let deserialized: RiskLevel = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deserialized, RiskLevel::Low);

        // Test Medium
        let json = serde_json::to_string(&RiskLevel::Medium).expect("serialize");
        assert_eq!(json, r#""medium""#);
        let deserialized: RiskLevel = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deserialized, RiskLevel::Medium);

        // Test High
        let json = serde_json::to_string(&RiskLevel::High).expect("serialize");
        assert_eq!(json, r#""high""#);
        let deserialized: RiskLevel = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deserialized, RiskLevel::High);
    }

    #[test]
    fn test_risk_level_default() {
        assert_eq!(RiskLevel::default(), RiskLevel::High);
    }

    #[test]
    fn test_risk_level_display() {
        assert_eq!(format!("{}", RiskLevel::Low), "low");
        assert_eq!(format!("{}", RiskLevel::Medium), "medium");
        assert_eq!(format!("{}", RiskLevel::High), "high");
    }

    #[test]
    fn test_token_info_new() {
        let info = TokenInfo::new("TEST", 18, RiskLevel::Medium);
        assert_eq!(info.symbol, "TEST");
        assert_eq!(info.decimals, 18);
        assert_eq!(info.risk_level, RiskLevel::Medium);
        assert_eq!(info.name, None);
    }

    #[test]
    fn test_token_info_with_name() {
        let info = TokenInfo::new("TEST", 18, RiskLevel::Medium).with_name("Test Token");
        assert_eq!(info.symbol, "TEST");
        assert_eq!(info.name, Some("Test Token".to_string()));
    }

    #[test]
    fn test_token_info_serialization() {
        let info = TokenInfo::new("TEST", 18, RiskLevel::Medium).with_name("Test Token");
        let json = serde_json::to_string(&info).expect("serialize");

        // Verify it contains expected fields
        assert!(json.contains(r#""symbol":"TEST""#));
        assert!(json.contains(r#""decimals":18"#));
        assert!(json.contains(r#""risk_level":"medium""#));
        assert!(json.contains(r#""name":"Test Token""#));

        // Round-trip
        let deserialized: TokenInfo = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deserialized, info);
    }

    #[test]
    fn test_token_info_serialization_without_name() {
        let info = TokenInfo::new("TEST", 18, RiskLevel::Low);
        let json = serde_json::to_string(&info).expect("serialize");

        // Should not contain name field when None
        assert!(!json.contains("name"));

        // Round-trip
        let deserialized: TokenInfo = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deserialized, info);
    }

    #[test]
    fn test_addresses_iterator() {
        let registry = TokenRegistry::with_builtins();
        let addresses: Vec<_> = registry.addresses().collect();
        assert_eq!(addresses.len(), 5);
    }

    #[test]
    fn test_to_json() {
        let mut registry = TokenRegistry::new();
        let addr: Address = "0x1234567890123456789012345678901234567890"
            .parse()
            .expect("valid address");
        registry.register(addr, TokenInfo::new("TEST", 18, RiskLevel::Low));

        let json = registry.to_json().expect("serialize");
        assert!(json.contains("TEST"));
        assert!(json.contains("0x1234567890123456789012345678901234567890"));
    }
}
