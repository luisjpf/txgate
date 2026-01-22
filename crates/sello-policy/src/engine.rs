//! Policy engine for transaction rule enforcement.
//!
//! This module provides the core policy engine that evaluates transactions against
//! configured rules including whitelists, blacklists, and amount limits.
//!
//! # Rule Evaluation Order
//!
//! Rules are evaluated in strict priority order:
//!
//! 1. **Blacklist** - Highest priority. If the recipient is blacklisted, DENY immediately.
//! 2. **Whitelist** - If whitelist is enabled and recipient is not whitelisted, DENY.
//! 3. **Transaction Limit** - If amount exceeds per-transaction limit, DENY.
//! 4. **Daily Limit** - If amount would exceed daily limit, DENY.
//! 5. **Allow** - If all checks pass, the transaction is ALLOWED.
//!
//! # Thread Safety
//!
//! The [`DefaultPolicyEngine`] is `Send + Sync` and can be safely shared across threads.
//!
//! # Example
//!
//! ```no_run
//! use sello_policy::engine::{PolicyEngine, DefaultPolicyEngine};
//! use sello_policy::config::PolicyConfig;
//! use sello_policy::history::TransactionHistory;
//! use sello_core::types::{ParsedTx, PolicyResult};
//! use alloy_primitives::U256;
//! use std::sync::Arc;
//!
//! // Create a policy config
//! let config = PolicyConfig::new()
//!     .with_blacklist(vec!["0xBAD".to_string()])
//!     .with_transaction_limit("ETH", U256::from(5_000_000_000_000_000_000u64));
//!
//! // Create transaction history
//! let history = Arc::new(TransactionHistory::in_memory().unwrap());
//!
//! // Create the engine
//! let engine = DefaultPolicyEngine::new(config, history).unwrap();
//!
//! // Check a transaction
//! let tx = ParsedTx::default();
//! let result = engine.check(&tx);
//! ```

use crate::config::PolicyConfig;
use crate::history::TransactionHistory;
use alloy_primitives::U256;
use sello_core::error::PolicyError;
use sello_core::types::{ParsedTx, PolicyResult};
use std::sync::Arc;

/// Trait for policy engines that enforce transaction rules.
///
/// Implementors of this trait can check transactions against policy rules
/// and record signed transactions for tracking purposes (e.g., daily limits).
///
/// # Thread Safety
///
/// All implementations must be `Send + Sync` to allow concurrent access
/// from multiple request handlers.
///
/// # Example
///
/// ```no_run
/// use sello_policy::engine::PolicyEngine;
/// use sello_core::types::{ParsedTx, PolicyResult};
/// use sello_core::error::PolicyError;
///
/// fn process_transaction(engine: &dyn PolicyEngine, tx: &ParsedTx) -> Result<(), PolicyError> {
///     let result = engine.check(tx)?;
///     if result.is_allowed() {
///         // Transaction approved, record it
///         engine.record(tx)?;
///     }
///     Ok(())
/// }
/// ```
pub trait PolicyEngine: Send + Sync {
    /// Check if a transaction is allowed by policy rules.
    ///
    /// Evaluates the transaction against all configured policy rules in order
    /// of priority (blacklist > whitelist > `tx_limit` > `daily_limit`).
    ///
    /// # Arguments
    ///
    /// * `tx` - The parsed transaction to check
    ///
    /// # Returns
    ///
    /// * `Ok(PolicyResult::Allowed)` - Transaction passes all policy checks
    /// * `Ok(PolicyResult::Denied { rule, reason })` - Transaction denied by a rule
    /// * `Err(PolicyError)` - Policy evaluation failed (e.g., database error)
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError`] if policy evaluation fails due to:
    /// - Database errors when checking daily limits
    /// - Invalid policy configuration
    fn check(&self, tx: &ParsedTx) -> Result<PolicyResult, PolicyError>;

    /// Record a transaction that was signed (for limit tracking).
    ///
    /// This should be called after a transaction is successfully signed
    /// to update the daily spending totals.
    ///
    /// # Arguments
    ///
    /// * `tx` - The signed transaction to record
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError`] if recording fails due to:
    /// - Database errors
    /// - Internal errors
    fn record(&self, tx: &ParsedTx) -> Result<(), PolicyError>;
}

/// Detailed result of a policy check operation.
///
/// Provides specific information about why a transaction was allowed or denied,
/// enabling detailed error messages and audit logging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyCheckResult {
    /// Transaction is allowed by all policy rules.
    Allowed,

    /// Transaction denied - recipient address is blacklisted.
    DeniedBlacklisted {
        /// The blacklisted address.
        address: String,
    },

    /// Transaction denied - recipient address is not in the whitelist.
    DeniedNotWhitelisted {
        /// The address that is not whitelisted.
        address: String,
    },

    /// Transaction denied - amount exceeds single transaction limit.
    DeniedExceedsTransactionLimit {
        /// Token identifier (e.g., "ETH" or contract address).
        token: String,
        /// The requested transaction amount.
        amount: U256,
        /// The configured limit.
        limit: U256,
    },

    /// Transaction denied - amount would exceed daily limit.
    DeniedExceedsDailyLimit {
        /// Token identifier (e.g., "ETH" or contract address).
        token: String,
        /// The requested transaction amount.
        amount: U256,
        /// The current daily total before this transaction.
        daily_total: U256,
        /// The configured daily limit.
        limit: U256,
    },
}

impl PolicyCheckResult {
    /// Returns `true` if the transaction is allowed.
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed)
    }

    /// Returns `true` if the transaction is denied.
    #[must_use]
    pub const fn is_denied(&self) -> bool {
        !self.is_allowed()
    }

    /// Returns the rule name that caused the denial, if any.
    #[must_use]
    pub const fn rule_name(&self) -> Option<&'static str> {
        match self {
            Self::Allowed => None,
            Self::DeniedBlacklisted { .. } => Some("blacklist"),
            Self::DeniedNotWhitelisted { .. } => Some("whitelist"),
            Self::DeniedExceedsTransactionLimit { .. } => Some("tx_limit"),
            Self::DeniedExceedsDailyLimit { .. } => Some("daily_limit"),
        }
    }

    /// Returns a human-readable reason for the denial, if any.
    #[must_use]
    pub fn reason(&self) -> Option<String> {
        match self {
            Self::Allowed => None,
            Self::DeniedBlacklisted { address } => {
                Some(format!("recipient address is blacklisted: {address}"))
            }
            Self::DeniedNotWhitelisted { address } => {
                Some(format!("recipient address not in whitelist: {address}"))
            }
            Self::DeniedExceedsTransactionLimit {
                token,
                amount,
                limit,
            } => Some(format!(
                "amount {amount} exceeds transaction limit {limit} for {token}"
            )),
            Self::DeniedExceedsDailyLimit {
                token,
                amount,
                daily_total,
                limit,
            } => Some(format!(
                "amount {amount} plus daily total {daily_total} exceeds daily limit {limit} for {token}"
            )),
        }
    }
}

impl From<PolicyCheckResult> for PolicyResult {
    fn from(result: PolicyCheckResult) -> Self {
        if result == PolicyCheckResult::Allowed {
            Self::Allowed
        } else {
            let rule = result.rule_name().unwrap_or("unknown").to_string();
            let reason = result
                .reason()
                .unwrap_or_else(|| "policy denied".to_string());
            Self::Denied { rule, reason }
        }
    }
}

/// Default policy engine implementation.
///
/// Evaluates transactions against configured whitelist, blacklist, and limit rules.
/// Uses [`TransactionHistory`] for tracking daily spending totals.
///
/// # Rule Evaluation Order
///
/// 1. Blacklist check (highest priority)
/// 2. Whitelist check (if enabled)
/// 3. Transaction limit check
/// 4. Daily limit check
/// 5. Allow (if all checks pass)
///
/// # Thread Safety
///
/// This struct is `Send + Sync` and can be safely shared across threads.
/// The underlying [`TransactionHistory`] handles concurrent access.
pub struct DefaultPolicyEngine {
    /// Policy configuration with whitelist, blacklist, and limits.
    config: PolicyConfig,
    /// Transaction history for tracking daily totals.
    history: Arc<TransactionHistory>,
}

impl std::fmt::Debug for DefaultPolicyEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DefaultPolicyEngine")
            .field("config", &self.config)
            .field("history", &"<TransactionHistory>")
            .finish()
    }
}

impl DefaultPolicyEngine {
    /// Creates a new policy engine with the given configuration and history.
    ///
    /// # Arguments
    ///
    /// * `config` - Policy configuration with whitelist, blacklist, and limits
    /// * `history` - Transaction history for tracking daily totals
    ///
    /// # Returns
    ///
    /// A new `DefaultPolicyEngine` instance.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::InvalidConfiguration`] if the configuration is invalid
    /// (e.g., an address appears in both whitelist and blacklist).
    ///
    /// # Example
    ///
    /// ```no_run
    /// use sello_policy::engine::DefaultPolicyEngine;
    /// use sello_policy::config::PolicyConfig;
    /// use sello_policy::history::TransactionHistory;
    /// use alloy_primitives::U256;
    /// use std::sync::Arc;
    ///
    /// let config = PolicyConfig::new()
    ///     .with_whitelist(vec!["0xAAA".to_string()])
    ///     .with_transaction_limit("ETH", U256::from(5_000_000_000_000_000_000u64));
    ///
    /// let history = Arc::new(TransactionHistory::in_memory().unwrap());
    /// let engine = DefaultPolicyEngine::new(config, history).unwrap();
    /// ```
    pub fn new(
        config: PolicyConfig,
        history: Arc<TransactionHistory>,
    ) -> Result<Self, PolicyError> {
        // Validate configuration
        config.validate()?;

        Ok(Self { config, history })
    }

    /// Check recipient against blacklist.
    ///
    /// # Returns
    ///
    /// * `Some(DeniedBlacklisted)` - If the recipient is blacklisted
    /// * `None` - If the recipient is not blacklisted or has no recipient
    fn check_blacklist(&self, tx: &ParsedTx) -> Option<PolicyCheckResult> {
        let recipient = tx.recipient.as_ref()?;

        if self.config.is_blacklisted(recipient) {
            return Some(PolicyCheckResult::DeniedBlacklisted {
                address: recipient.clone(),
            });
        }

        None
    }

    /// Check recipient against whitelist (if enabled).
    ///
    /// # Returns
    ///
    /// * `Some(DeniedNotWhitelisted)` - If whitelist is enabled and recipient is not whitelisted
    /// * `None` - If whitelist is disabled, recipient is whitelisted, or transaction has no recipient
    fn check_whitelist(&self, tx: &ParsedTx) -> Option<PolicyCheckResult> {
        // Whitelist only applies if enabled
        if !self.config.whitelist_enabled {
            return None;
        }

        let recipient = tx.recipient.as_ref()?;

        if !self.config.is_whitelisted(recipient) {
            return Some(PolicyCheckResult::DeniedNotWhitelisted {
                address: recipient.clone(),
            });
        }

        None
    }

    /// Check transaction amount against per-transaction limit.
    ///
    /// # Returns
    ///
    /// * `Some(DeniedExceedsTransactionLimit)` - If amount exceeds the configured limit
    /// * `None` - If no limit is configured, amount is within limit, or transaction has no amount
    fn check_transaction_limit(&self, tx: &ParsedTx) -> Option<PolicyCheckResult> {
        let amount = tx.amount?;

        // Determine token key: use token_address if present, otherwise "ETH"
        let token = tx.token_address.as_deref().unwrap_or("ETH");

        // Get the configured limit for this token
        let limit = self.config.get_transaction_limit(token)?;

        // Check if amount exceeds limit
        if amount > limit {
            return Some(PolicyCheckResult::DeniedExceedsTransactionLimit {
                token: token.to_string(),
                amount,
                limit,
            });
        }

        None
    }

    /// Check daily total against daily limit.
    ///
    /// # Returns
    ///
    /// * `Ok(Some(DeniedExceedsDailyLimit))` - If amount would exceed daily limit
    /// * `Ok(None)` - If no limit is configured, within limit, or transaction has no amount
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError`] if fetching the daily total fails.
    fn check_daily_limit(&self, tx: &ParsedTx) -> Result<Option<PolicyCheckResult>, PolicyError> {
        let Some(amount) = tx.amount else {
            return Ok(None);
        };

        // Determine token key: use token_address if present, otherwise "ETH"
        let token = tx.token_address.as_deref().unwrap_or("ETH");

        // Get the configured daily limit for this token
        let Some(limit) = self.config.get_daily_limit(token) else {
            return Ok(None);
        };

        // Get current daily total from history
        let daily_total = self.history.daily_total(token).map_err(|e| {
            PolicyError::invalid_configuration(format!("failed to get daily total: {e}"))
        })?;

        // Check if new transaction would exceed daily limit
        // Use saturating_add to prevent overflow
        let new_total = daily_total.saturating_add(amount);

        if new_total > limit {
            return Ok(Some(PolicyCheckResult::DeniedExceedsDailyLimit {
                token: token.to_string(),
                amount,
                daily_total,
                limit,
            }));
        }

        Ok(None)
    }
}

impl PolicyEngine for DefaultPolicyEngine {
    fn check(&self, tx: &ParsedTx) -> Result<PolicyResult, PolicyError> {
        // 1. Check blacklist (highest priority)
        if let Some(result) = self.check_blacklist(tx) {
            return Ok(result.into());
        }

        // 2. Check whitelist (if enabled)
        if let Some(result) = self.check_whitelist(tx) {
            return Ok(result.into());
        }

        // 3. Check transaction limit
        if let Some(result) = self.check_transaction_limit(tx) {
            return Ok(result.into());
        }

        // 4. Check daily limit
        if let Some(result) = self.check_daily_limit(tx)? {
            return Ok(result.into());
        }

        // 5. All checks passed
        Ok(PolicyResult::Allowed)
    }

    fn record(&self, tx: &ParsedTx) -> Result<(), PolicyError> {
        // Determine token key: use token_address if present, otherwise "ETH"
        let token = tx.token_address.as_deref().unwrap_or("ETH");

        // Get amount, default to zero if not present
        let amount = tx.amount.unwrap_or(U256::ZERO);

        // Get transaction hash as hex string
        let hash = hex::encode(tx.hash);

        // Record in history
        self.history.record(token, amount, &hash).map_err(|e| {
            PolicyError::invalid_configuration(format!("failed to record transaction: {e}"))
        })
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
    use sello_core::types::TxType;
    use std::collections::HashMap;

    /// Helper to create a basic test transaction.
    fn create_test_tx(recipient: Option<&str>, amount: Option<U256>) -> ParsedTx {
        ParsedTx {
            hash: [0xab; 32],
            recipient: recipient.map(String::from),
            amount,
            token: Some("ETH".to_string()),
            token_address: None,
            tx_type: TxType::Transfer,
            chain: "ethereum".to_string(),
            nonce: Some(1),
            chain_id: Some(1),
            metadata: HashMap::new(),
        }
    }

    /// Helper to create a token transfer transaction.
    fn create_token_tx(
        recipient: Option<&str>,
        amount: Option<U256>,
        token_address: &str,
    ) -> ParsedTx {
        ParsedTx {
            hash: [0xcd; 32],
            recipient: recipient.map(String::from),
            amount,
            token: Some("USDC".to_string()),
            token_address: Some(token_address.to_string()),
            tx_type: TxType::TokenTransfer,
            chain: "ethereum".to_string(),
            nonce: Some(2),
            chain_id: Some(1),
            metadata: HashMap::new(),
        }
    }

    // =========================================================================
    // PolicyCheckResult tests
    // =========================================================================

    mod policy_check_result_tests {
        use super::*;

        #[test]
        fn test_allowed_is_allowed() {
            let result = PolicyCheckResult::Allowed;
            assert!(result.is_allowed());
            assert!(!result.is_denied());
            assert!(result.rule_name().is_none());
            assert!(result.reason().is_none());
        }

        #[test]
        fn test_denied_blacklisted() {
            let result = PolicyCheckResult::DeniedBlacklisted {
                address: "0xBAD".to_string(),
            };
            assert!(!result.is_allowed());
            assert!(result.is_denied());
            assert_eq!(result.rule_name(), Some("blacklist"));
            assert!(result.reason().unwrap().contains("blacklisted"));
        }

        #[test]
        fn test_denied_not_whitelisted() {
            let result = PolicyCheckResult::DeniedNotWhitelisted {
                address: "0xUNKNOWN".to_string(),
            };
            assert!(!result.is_allowed());
            assert!(result.is_denied());
            assert_eq!(result.rule_name(), Some("whitelist"));
            assert!(result.reason().unwrap().contains("not in whitelist"));
        }

        #[test]
        fn test_denied_exceeds_transaction_limit() {
            let result = PolicyCheckResult::DeniedExceedsTransactionLimit {
                token: "ETH".to_string(),
                amount: U256::from(10u64),
                limit: U256::from(5u64),
            };
            assert!(!result.is_allowed());
            assert!(result.is_denied());
            assert_eq!(result.rule_name(), Some("tx_limit"));
            assert!(result
                .reason()
                .unwrap()
                .contains("exceeds transaction limit"));
        }

        #[test]
        fn test_denied_exceeds_daily_limit() {
            let result = PolicyCheckResult::DeniedExceedsDailyLimit {
                token: "ETH".to_string(),
                amount: U256::from(5u64),
                daily_total: U256::from(8u64),
                limit: U256::from(10u64),
            };
            assert!(!result.is_allowed());
            assert!(result.is_denied());
            assert_eq!(result.rule_name(), Some("daily_limit"));
            assert!(result.reason().unwrap().contains("exceeds daily limit"));
        }

        #[test]
        fn test_conversion_to_policy_result_allowed() {
            let check_result = PolicyCheckResult::Allowed;
            let policy_result: PolicyResult = check_result.into();
            assert!(policy_result.is_allowed());
        }

        #[test]
        fn test_conversion_to_policy_result_denied() {
            let check_result = PolicyCheckResult::DeniedBlacklisted {
                address: "0xBAD".to_string(),
            };
            let policy_result: PolicyResult = check_result.into();
            assert!(policy_result.is_denied());

            if let PolicyResult::Denied { rule, reason } = policy_result {
                assert_eq!(rule, "blacklist");
                assert!(reason.contains("blacklisted"));
            } else {
                panic!("expected Denied variant");
            }
        }
    }

    // =========================================================================
    // DefaultPolicyEngine creation tests
    // =========================================================================

    mod engine_creation_tests {
        use super::*;

        #[test]
        fn test_create_engine_with_valid_config() {
            let config = PolicyConfig::new()
                .with_whitelist(vec!["0xAAA".to_string()])
                .with_blacklist(vec!["0xBBB".to_string()]);

            let history = Arc::new(TransactionHistory::in_memory().unwrap());
            let engine = DefaultPolicyEngine::new(config, history);

            assert!(engine.is_ok());
        }

        #[test]
        fn test_create_engine_with_invalid_config() {
            // Address in both whitelist and blacklist
            let config = PolicyConfig::new()
                .with_whitelist(vec!["0xAAA".to_string()])
                .with_blacklist(vec!["0xAAA".to_string()]);

            let history = Arc::new(TransactionHistory::in_memory().unwrap());
            let engine = DefaultPolicyEngine::new(config, history);

            assert!(engine.is_err());
            let err = engine.unwrap_err();
            assert!(matches!(err, PolicyError::InvalidConfiguration { .. }));
        }

        #[test]
        fn test_create_engine_with_empty_config() {
            let config = PolicyConfig::new();
            let history = Arc::new(TransactionHistory::in_memory().unwrap());
            let engine = DefaultPolicyEngine::new(config, history);

            assert!(engine.is_ok());
        }
    }

    // =========================================================================
    // Blacklist tests
    // =========================================================================

    mod blacklist_tests {
        use super::*;

        #[test]
        fn test_blacklist_blocks_transaction() {
            let config = PolicyConfig::new().with_blacklist(vec!["0xBAD".to_string()]);

            let history = Arc::new(TransactionHistory::in_memory().unwrap());
            let engine = DefaultPolicyEngine::new(config, history).unwrap();

            let tx = create_test_tx(Some("0xBAD"), Some(U256::from(100u64)));
            let result = engine.check(&tx).unwrap();

            assert!(result.is_denied());
            if let PolicyResult::Denied { rule, .. } = result {
                assert_eq!(rule, "blacklist");
            } else {
                panic!("expected Denied variant");
            }
        }

        #[test]
        fn test_blacklist_case_insensitive() {
            let config = PolicyConfig::new().with_blacklist(vec!["0xBAD".to_string()]);

            let history = Arc::new(TransactionHistory::in_memory().unwrap());
            let engine = DefaultPolicyEngine::new(config, history).unwrap();

            let tx = create_test_tx(Some("0xbad"), Some(U256::from(100u64)));
            let result = engine.check(&tx).unwrap();

            assert!(result.is_denied());
        }

        #[test]
        fn test_non_blacklisted_address_allowed() {
            let config = PolicyConfig::new().with_blacklist(vec!["0xBAD".to_string()]);

            let history = Arc::new(TransactionHistory::in_memory().unwrap());
            let engine = DefaultPolicyEngine::new(config, history).unwrap();

            let tx = create_test_tx(Some("0xGOOD"), Some(U256::from(100u64)));
            let result = engine.check(&tx).unwrap();

            assert!(result.is_allowed());
        }

        #[test]
        fn test_no_recipient_skips_blacklist_check() {
            let config = PolicyConfig::new().with_blacklist(vec!["0xBAD".to_string()]);

            let history = Arc::new(TransactionHistory::in_memory().unwrap());
            let engine = DefaultPolicyEngine::new(config, history).unwrap();

            let tx = create_test_tx(None, Some(U256::from(100u64)));
            let result = engine.check(&tx).unwrap();

            // Should pass since there's no recipient to check
            assert!(result.is_allowed());
        }
    }

    // =========================================================================
    // Whitelist tests
    // =========================================================================

    mod whitelist_tests {
        use super::*;

        #[test]
        fn test_whitelist_allows_only_whitelisted_when_enabled() {
            let config = PolicyConfig::new().with_whitelist(vec!["0xGOOD".to_string()]);

            let history = Arc::new(TransactionHistory::in_memory().unwrap());
            let engine = DefaultPolicyEngine::new(config, history).unwrap();

            // Whitelisted address should be allowed
            let tx = create_test_tx(Some("0xGOOD"), Some(U256::from(100u64)));
            let result = engine.check(&tx).unwrap();
            assert!(result.is_allowed());

            // Non-whitelisted address should be denied
            let tx = create_test_tx(Some("0xOTHER"), Some(U256::from(100u64)));
            let result = engine.check(&tx).unwrap();
            assert!(result.is_denied());
            if let PolicyResult::Denied { rule, .. } = result {
                assert_eq!(rule, "whitelist");
            }
        }

        #[test]
        fn test_whitelist_disabled_allows_all() {
            let config = PolicyConfig::new()
                .with_whitelist(vec!["0xGOOD".to_string()])
                .with_whitelist_enabled(false);

            let history = Arc::new(TransactionHistory::in_memory().unwrap());
            let engine = DefaultPolicyEngine::new(config, history).unwrap();

            // Any address should be allowed when whitelist is disabled
            let tx = create_test_tx(Some("0xOTHER"), Some(U256::from(100u64)));
            let result = engine.check(&tx).unwrap();
            assert!(result.is_allowed());
        }

        #[test]
        fn test_whitelist_case_insensitive() {
            let config = PolicyConfig::new().with_whitelist(vec!["0xGOOD".to_string()]);

            let history = Arc::new(TransactionHistory::in_memory().unwrap());
            let engine = DefaultPolicyEngine::new(config, history).unwrap();

            let tx = create_test_tx(Some("0xgood"), Some(U256::from(100u64)));
            let result = engine.check(&tx).unwrap();
            assert!(result.is_allowed());
        }

        #[test]
        fn test_no_recipient_skips_whitelist_check() {
            let config = PolicyConfig::new().with_whitelist(vec!["0xGOOD".to_string()]);

            let history = Arc::new(TransactionHistory::in_memory().unwrap());
            let engine = DefaultPolicyEngine::new(config, history).unwrap();

            let tx = create_test_tx(None, Some(U256::from(100u64)));
            let result = engine.check(&tx).unwrap();

            // Should pass since there's no recipient to check
            assert!(result.is_allowed());
        }
    }

    // =========================================================================
    // Transaction limit tests
    // =========================================================================

    mod transaction_limit_tests {
        use super::*;

        #[test]
        fn test_transaction_limit_enforcement() {
            let config = PolicyConfig::new().with_transaction_limit("ETH", U256::from(100u64));

            let history = Arc::new(TransactionHistory::in_memory().unwrap());
            let engine = DefaultPolicyEngine::new(config, history).unwrap();

            // Within limit - should be allowed
            let tx = create_test_tx(Some("0xREC"), Some(U256::from(50u64)));
            let result = engine.check(&tx).unwrap();
            assert!(result.is_allowed());

            // At limit - should be allowed
            let tx = create_test_tx(Some("0xREC"), Some(U256::from(100u64)));
            let result = engine.check(&tx).unwrap();
            assert!(result.is_allowed());

            // Above limit - should be denied
            let tx = create_test_tx(Some("0xREC"), Some(U256::from(101u64)));
            let result = engine.check(&tx).unwrap();
            assert!(result.is_denied());
            if let PolicyResult::Denied { rule, .. } = result {
                assert_eq!(rule, "tx_limit");
            }
        }

        #[test]
        fn test_transaction_limit_for_token() {
            let token_address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
            let config =
                PolicyConfig::new().with_transaction_limit(token_address, U256::from(1000u64));

            let history = Arc::new(TransactionHistory::in_memory().unwrap());
            let engine = DefaultPolicyEngine::new(config, history).unwrap();

            // Above limit for token - should be denied
            let tx = create_token_tx(Some("0xREC"), Some(U256::from(1001u64)), token_address);
            let result = engine.check(&tx).unwrap();
            assert!(result.is_denied());

            // ETH transfer should not be affected by token limit
            let tx = create_test_tx(Some("0xREC"), Some(U256::from(1001u64)));
            let result = engine.check(&tx).unwrap();
            assert!(result.is_allowed());
        }

        #[test]
        fn test_no_transaction_limit_allows_any_amount() {
            let config = PolicyConfig::new();

            let history = Arc::new(TransactionHistory::in_memory().unwrap());
            let engine = DefaultPolicyEngine::new(config, history).unwrap();

            let tx = create_test_tx(Some("0xREC"), Some(U256::MAX));
            let result = engine.check(&tx).unwrap();
            assert!(result.is_allowed());
        }

        #[test]
        fn test_zero_transaction_limit_denies_everything() {
            let config = PolicyConfig::new().with_transaction_limit("ETH", U256::ZERO);

            let history = Arc::new(TransactionHistory::in_memory().unwrap());
            let engine = DefaultPolicyEngine::new(config, history).unwrap();

            // Even a tiny amount should be denied
            let tx = create_test_tx(Some("0xREC"), Some(U256::from(1u64)));
            let result = engine.check(&tx).unwrap();
            assert!(result.is_denied());

            // Zero amount should be allowed (not exceeding)
            let tx = create_test_tx(Some("0xREC"), Some(U256::ZERO));
            let result = engine.check(&tx).unwrap();
            assert!(result.is_allowed());
        }

        #[test]
        fn test_no_amount_skips_transaction_limit_check() {
            let config = PolicyConfig::new().with_transaction_limit("ETH", U256::from(100u64));

            let history = Arc::new(TransactionHistory::in_memory().unwrap());
            let engine = DefaultPolicyEngine::new(config, history).unwrap();

            let tx = create_test_tx(Some("0xREC"), None);
            let result = engine.check(&tx).unwrap();
            assert!(result.is_allowed());
        }
    }

    // =========================================================================
    // Daily limit tests
    // =========================================================================

    mod daily_limit_tests {
        use super::*;

        #[test]
        fn test_daily_limit_enforcement() {
            let config = PolicyConfig::new().with_daily_limit("ETH", U256::from(1000u64));

            let history = Arc::new(TransactionHistory::in_memory().unwrap());
            let engine = DefaultPolicyEngine::new(config, Arc::clone(&history)).unwrap();

            // First transaction within limit
            let tx = create_test_tx(Some("0xREC"), Some(U256::from(500u64)));
            let result = engine.check(&tx).unwrap();
            assert!(result.is_allowed());

            // Record the transaction
            engine.record(&tx).unwrap();

            // Second transaction that would exceed daily limit
            let tx = create_test_tx(Some("0xREC"), Some(U256::from(600u64)));
            let result = engine.check(&tx).unwrap();
            assert!(result.is_denied());
            if let PolicyResult::Denied { rule, .. } = result {
                assert_eq!(rule, "daily_limit");
            }

            // Transaction that keeps us within limit should be allowed
            let tx = create_test_tx(Some("0xREC"), Some(U256::from(400u64)));
            let result = engine.check(&tx).unwrap();
            assert!(result.is_allowed());
        }

        #[test]
        fn test_daily_limit_for_token() {
            let token_address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
            let config = PolicyConfig::new().with_daily_limit(token_address, U256::from(1000u64));

            let history = Arc::new(TransactionHistory::in_memory().unwrap());
            let engine = DefaultPolicyEngine::new(config, Arc::clone(&history)).unwrap();

            // Record a token transaction
            let tx = create_token_tx(Some("0xREC"), Some(U256::from(800u64)), token_address);
            engine.record(&tx).unwrap();

            // Next token transaction that exceeds limit
            let tx = create_token_tx(Some("0xREC"), Some(U256::from(300u64)), token_address);
            let result = engine.check(&tx).unwrap();
            assert!(result.is_denied());

            // ETH transaction should not be affected
            let tx = create_test_tx(Some("0xREC"), Some(U256::from(10000u64)));
            let result = engine.check(&tx).unwrap();
            assert!(result.is_allowed());
        }

        #[test]
        fn test_no_daily_limit_allows_any_amount() {
            let config = PolicyConfig::new();

            let history = Arc::new(TransactionHistory::in_memory().unwrap());
            let engine = DefaultPolicyEngine::new(config, Arc::clone(&history)).unwrap();

            // Record a large transaction
            let tx = create_test_tx(Some("0xREC"), Some(U256::MAX / U256::from(2)));
            engine.record(&tx).unwrap();

            // Another large transaction should be allowed
            let tx = create_test_tx(Some("0xREC"), Some(U256::MAX / U256::from(2)));
            let result = engine.check(&tx).unwrap();
            assert!(result.is_allowed());
        }

        #[test]
        fn test_zero_daily_limit_denies_everything() {
            let config = PolicyConfig::new().with_daily_limit("ETH", U256::ZERO);

            let history = Arc::new(TransactionHistory::in_memory().unwrap());
            let engine = DefaultPolicyEngine::new(config, history).unwrap();

            // Even a tiny amount should be denied
            let tx = create_test_tx(Some("0xREC"), Some(U256::from(1u64)));
            let result = engine.check(&tx).unwrap();
            assert!(result.is_denied());

            // Zero amount should be allowed
            let tx = create_test_tx(Some("0xREC"), Some(U256::ZERO));
            let result = engine.check(&tx).unwrap();
            assert!(result.is_allowed());
        }

        #[test]
        fn test_no_amount_skips_daily_limit_check() {
            let config = PolicyConfig::new().with_daily_limit("ETH", U256::from(100u64));

            let history = Arc::new(TransactionHistory::in_memory().unwrap());
            let engine = DefaultPolicyEngine::new(config, history).unwrap();

            let tx = create_test_tx(Some("0xREC"), None);
            let result = engine.check(&tx).unwrap();
            assert!(result.is_allowed());
        }
    }

    // =========================================================================
    // Rule precedence tests
    // =========================================================================

    mod rule_precedence_tests {
        use super::*;

        #[test]
        fn test_blacklist_takes_precedence_over_whitelist() {
            // This test verifies that blacklist check happens before whitelist
            // We can't have an address in both lists (validation prevents it),
            // but we can test that a blacklisted address is denied even if
            // whitelist is enabled with other addresses
            let config = PolicyConfig::new()
                .with_whitelist(vec!["0xGOOD".to_string()])
                .with_blacklist(vec!["0xBAD".to_string()]);

            let history = Arc::new(TransactionHistory::in_memory().unwrap());
            let engine = DefaultPolicyEngine::new(config, history).unwrap();

            // Blacklisted address should be denied
            let tx = create_test_tx(Some("0xBAD"), Some(U256::from(100u64)));
            let result = engine.check(&tx).unwrap();
            assert!(result.is_denied());
            if let PolicyResult::Denied { rule, .. } = result {
                assert_eq!(rule, "blacklist");
            }
        }

        #[test]
        fn test_whitelist_takes_precedence_over_tx_limit() {
            let config = PolicyConfig::new()
                .with_whitelist(vec!["0xGOOD".to_string()])
                .with_transaction_limit("ETH", U256::from(100u64));

            let history = Arc::new(TransactionHistory::in_memory().unwrap());
            let engine = DefaultPolicyEngine::new(config, history).unwrap();

            // Non-whitelisted address should be denied by whitelist, not tx_limit
            let tx = create_test_tx(Some("0xOTHER"), Some(U256::from(1000u64)));
            let result = engine.check(&tx).unwrap();
            assert!(result.is_denied());
            if let PolicyResult::Denied { rule, .. } = result {
                assert_eq!(rule, "whitelist");
            }
        }

        #[test]
        fn test_tx_limit_takes_precedence_over_daily_limit() {
            let config = PolicyConfig::new()
                .with_transaction_limit("ETH", U256::from(50u64))
                .with_daily_limit("ETH", U256::from(100u64));

            let history = Arc::new(TransactionHistory::in_memory().unwrap());
            let engine = DefaultPolicyEngine::new(config, history).unwrap();

            // Amount exceeds both limits, should be denied by tx_limit first
            let tx = create_test_tx(Some("0xREC"), Some(U256::from(60u64)));
            let result = engine.check(&tx).unwrap();
            assert!(result.is_denied());
            if let PolicyResult::Denied { rule, .. } = result {
                assert_eq!(rule, "tx_limit");
            }
        }

        #[test]
        fn test_full_rule_evaluation_order() {
            // Create a config with all rules
            let config = PolicyConfig::new()
                .with_whitelist(vec!["0xGOOD".to_string(), "0xALSO_GOOD".to_string()])
                .with_blacklist(vec!["0xBAD".to_string()])
                .with_transaction_limit("ETH", U256::from(100u64))
                .with_daily_limit("ETH", U256::from(200u64));

            let history = Arc::new(TransactionHistory::in_memory().unwrap());
            let engine = DefaultPolicyEngine::new(config, Arc::clone(&history)).unwrap();

            // 1. Blacklisted address - denied by blacklist
            let tx = create_test_tx(Some("0xBAD"), Some(U256::from(50u64)));
            let result = engine.check(&tx).unwrap();
            if let PolicyResult::Denied { rule, .. } = result {
                assert_eq!(rule, "blacklist");
            }

            // 2. Not whitelisted - denied by whitelist
            let tx = create_test_tx(Some("0xOTHER"), Some(U256::from(50u64)));
            let result = engine.check(&tx).unwrap();
            if let PolicyResult::Denied { rule, .. } = result {
                assert_eq!(rule, "whitelist");
            }

            // 3. Whitelisted but over tx limit - denied by tx_limit
            let tx = create_test_tx(Some("0xGOOD"), Some(U256::from(150u64)));
            let result = engine.check(&tx).unwrap();
            if let PolicyResult::Denied { rule, .. } = result {
                assert_eq!(rule, "tx_limit");
            }

            // 4. Record some transactions to affect daily limit
            let tx = create_test_tx(Some("0xGOOD"), Some(U256::from(80u64)));
            engine.record(&tx).unwrap();
            let tx = create_test_tx(Some("0xALSO_GOOD"), Some(U256::from(80u64)));
            engine.record(&tx).unwrap();

            // 5. Within tx limit but over daily limit - denied by daily_limit
            let tx = create_test_tx(Some("0xGOOD"), Some(U256::from(50u64)));
            let result = engine.check(&tx).unwrap();
            if let PolicyResult::Denied { rule, .. } = result {
                assert_eq!(rule, "daily_limit");
            }

            // 6. All checks pass - allowed
            let tx = create_test_tx(Some("0xGOOD"), Some(U256::from(10u64)));
            let result = engine.check(&tx).unwrap();
            assert!(result.is_allowed());
        }
    }

    // =========================================================================
    // Record transaction tests
    // =========================================================================

    mod record_tests {
        use super::*;

        #[test]
        fn test_record_updates_history() {
            let config = PolicyConfig::new();
            let history = Arc::new(TransactionHistory::in_memory().unwrap());
            let engine = DefaultPolicyEngine::new(config, Arc::clone(&history)).unwrap();

            // Record a transaction
            let tx = create_test_tx(Some("0xREC"), Some(U256::from(100u64)));
            engine.record(&tx).unwrap();

            // Check that history was updated
            let total = history.daily_total("ETH").unwrap();
            assert_eq!(total, U256::from(100u64));

            // Record another transaction
            let tx = create_test_tx(Some("0xREC"), Some(U256::from(50u64)));
            engine.record(&tx).unwrap();

            let total = history.daily_total("ETH").unwrap();
            assert_eq!(total, U256::from(150u64));
        }

        #[test]
        fn test_record_token_transaction() {
            let token_address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
            let config = PolicyConfig::new();
            let history = Arc::new(TransactionHistory::in_memory().unwrap());
            let engine = DefaultPolicyEngine::new(config, Arc::clone(&history)).unwrap();

            // Record a token transaction
            let tx = create_token_tx(Some("0xREC"), Some(U256::from(1000u64)), token_address);
            engine.record(&tx).unwrap();

            // Check that history was updated for the token
            let total = history.daily_total(token_address).unwrap();
            assert_eq!(total, U256::from(1000u64));

            // ETH should still be zero
            let eth_total = history.daily_total("ETH").unwrap();
            assert_eq!(eth_total, U256::ZERO);
        }

        #[test]
        fn test_record_with_no_amount() {
            let config = PolicyConfig::new();
            let history = Arc::new(TransactionHistory::in_memory().unwrap());
            let engine = DefaultPolicyEngine::new(config, Arc::clone(&history)).unwrap();

            // Record a transaction with no amount (defaults to zero)
            let tx = create_test_tx(Some("0xREC"), None);
            engine.record(&tx).unwrap();

            // History should show zero
            let total = history.daily_total("ETH").unwrap();
            assert_eq!(total, U256::ZERO);
        }
    }

    // =========================================================================
    // Send + Sync tests
    // =========================================================================

    mod send_sync_tests {
        use super::*;

        #[test]
        fn test_policy_engine_is_send_sync() {
            fn assert_send_sync<T: Send + Sync>() {}
            assert_send_sync::<DefaultPolicyEngine>();
        }

        #[test]
        fn test_policy_check_result_is_send_sync() {
            fn assert_send_sync<T: Send + Sync>() {}
            assert_send_sync::<PolicyCheckResult>();
        }

        #[test]
        fn test_engine_can_be_shared_across_threads() {
            use std::thread;

            let config = PolicyConfig::new().with_transaction_limit("ETH", U256::from(1000u64));

            let history = Arc::new(TransactionHistory::in_memory().unwrap());
            let engine = Arc::new(DefaultPolicyEngine::new(config, history).unwrap());

            let mut handles = vec![];

            for i in 0..5 {
                let engine_clone = Arc::clone(&engine);
                let handle = thread::spawn(move || {
                    let tx = create_test_tx(Some("0xREC"), Some(U256::from(100u64 * (i + 1))));
                    engine_clone.check(&tx)
                });
                handles.push(handle);
            }

            for handle in handles {
                let result = handle.join().unwrap().unwrap();
                // All should be allowed since they're all under the limit
                assert!(result.is_allowed());
            }
        }
    }

    // =========================================================================
    // Edge case tests
    // =========================================================================

    mod edge_case_tests {
        use super::*;

        #[test]
        fn test_empty_config_allows_everything() {
            let config = PolicyConfig::new();
            let history = Arc::new(TransactionHistory::in_memory().unwrap());
            let engine = DefaultPolicyEngine::new(config, history).unwrap();

            let tx = create_test_tx(Some("0xANYONE"), Some(U256::MAX));
            let result = engine.check(&tx).unwrap();
            assert!(result.is_allowed());
        }

        #[test]
        fn test_empty_transaction() {
            let config = PolicyConfig::new()
                .with_whitelist(vec!["0xGOOD".to_string()])
                .with_transaction_limit("ETH", U256::from(100u64));

            let history = Arc::new(TransactionHistory::in_memory().unwrap());
            let engine = DefaultPolicyEngine::new(config, history).unwrap();

            // Transaction with no recipient and no amount
            let tx = ParsedTx::default();
            let result = engine.check(&tx).unwrap();

            // Should be allowed because:
            // - No recipient to blacklist/whitelist
            // - No amount to check against limits
            assert!(result.is_allowed());
        }

        #[test]
        fn test_max_u256_amount() {
            let config = PolicyConfig::new()
                .with_transaction_limit("ETH", U256::MAX)
                .with_daily_limit("ETH", U256::MAX);

            let history = Arc::new(TransactionHistory::in_memory().unwrap());
            let engine = DefaultPolicyEngine::new(config, history).unwrap();

            let tx = create_test_tx(Some("0xREC"), Some(U256::MAX));
            let result = engine.check(&tx).unwrap();
            assert!(result.is_allowed());
        }

        #[test]
        fn test_daily_limit_with_overflow_protection() {
            let config = PolicyConfig::new().with_daily_limit("ETH", U256::MAX);

            let history = Arc::new(TransactionHistory::in_memory().unwrap());
            let engine = DefaultPolicyEngine::new(config, Arc::clone(&history)).unwrap();

            // Record a large transaction
            let tx = create_test_tx(Some("0xREC"), Some(U256::MAX));
            engine.record(&tx).unwrap();

            // Try another transaction - should use saturating_add and not overflow
            let tx = create_test_tx(Some("0xREC"), Some(U256::from(1u64)));
            let result = engine.check(&tx).unwrap();

            // The new_total would saturate at MAX, which equals the limit, so it should be allowed
            assert!(result.is_allowed());
        }

        #[test]
        fn test_daily_limit_exactly_at_limit_after_saturation() {
            let config = PolicyConfig::new().with_daily_limit("ETH", U256::MAX);

            let history = Arc::new(TransactionHistory::in_memory().unwrap());
            let engine = DefaultPolicyEngine::new(config, Arc::clone(&history)).unwrap();

            // Record U256::MAX - 50
            let tx = create_test_tx(Some("0xREC"), Some(U256::MAX - U256::from(50u64)));
            engine.record(&tx).unwrap();

            // Try to send 100 more - this will saturate at MAX and exceed limit
            let tx = create_test_tx(Some("0xREC"), Some(U256::from(100u64)));
            let result = engine.check(&tx).unwrap();

            // Should be denied because new_total (saturated at MAX) > MAX is false,
            // but MAX + 100 saturates to MAX which is not > MAX, so it's allowed
            assert!(result.is_allowed());
        }

        #[test]
        fn test_engine_debug_format() {
            let config = PolicyConfig::new();
            let history = Arc::new(TransactionHistory::in_memory().unwrap());
            let engine = DefaultPolicyEngine::new(config, history).unwrap();

            let debug_str = format!("{engine:?}");
            assert!(debug_str.contains("DefaultPolicyEngine"));
            assert!(debug_str.contains("config"));
            assert!(debug_str.contains("TransactionHistory"));
        }

        #[test]
        fn test_check_result_equality() {
            let result1 = PolicyCheckResult::Allowed;
            let result2 = PolicyCheckResult::Allowed;
            assert_eq!(result1, result2);

            let result3 = PolicyCheckResult::DeniedBlacklisted {
                address: "0xBAD".to_string(),
            };
            let result4 = PolicyCheckResult::DeniedBlacklisted {
                address: "0xBAD".to_string(),
            };
            assert_eq!(result3, result4);
        }

        #[test]
        fn test_check_result_clone() {
            let result = PolicyCheckResult::DeniedExceedsTransactionLimit {
                token: "ETH".to_string(),
                amount: U256::from(100u64),
                limit: U256::from(50u64),
            };
            let cloned = result.clone();
            assert_eq!(result, cloned);
        }
    }

    // =========================================================================
    // Additional coverage tests for uncovered branches
    // =========================================================================

    mod additional_coverage_tests {
        use super::*;

        #[test]
        fn test_transaction_with_token_address_no_limit() {
            let config = PolicyConfig::new();
            let history = Arc::new(TransactionHistory::in_memory().unwrap());
            let engine = DefaultPolicyEngine::new(config, history).unwrap();

            // Token transaction without any configured limits
            let tx = create_token_tx(
                Some("0xREC"),
                Some(U256::MAX),
                "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            );
            let result = engine.check(&tx).unwrap();
            assert!(result.is_allowed());
        }

        #[test]
        fn test_record_transaction_with_token_address() {
            let config = PolicyConfig::new();
            let history = Arc::new(TransactionHistory::in_memory().unwrap());
            let engine = DefaultPolicyEngine::new(config, Arc::clone(&history)).unwrap();

            let token_address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
            let tx = create_token_tx(Some("0xREC"), Some(U256::from(1000u64)), token_address);

            engine.record(&tx).unwrap();

            // Verify the token address was used as the key
            let total = history.daily_total(token_address).unwrap();
            assert_eq!(total, U256::from(1000u64));
        }

        #[test]
        fn test_whitelist_disabled_explicitly() {
            // Test that whitelist is properly disabled even when addresses are present
            let config = PolicyConfig::new()
                .with_whitelist(vec!["0xGOOD".to_string()])
                .with_whitelist_enabled(false);

            let history = Arc::new(TransactionHistory::in_memory().unwrap());
            let engine = DefaultPolicyEngine::new(config, history).unwrap();

            // Non-whitelisted address should be allowed when whitelist is disabled
            let tx = create_test_tx(Some("0xOTHER"), Some(U256::from(100u64)));
            let result = engine.check(&tx).unwrap();
            assert!(result.is_allowed());
        }

        #[test]
        fn test_policy_check_result_all_variants_have_rule_names() {
            // Verify all denied variants return a rule name
            let blacklisted = PolicyCheckResult::DeniedBlacklisted {
                address: "0x1".to_string(),
            };
            assert_eq!(blacklisted.rule_name(), Some("blacklist"));

            let not_whitelisted = PolicyCheckResult::DeniedNotWhitelisted {
                address: "0x2".to_string(),
            };
            assert_eq!(not_whitelisted.rule_name(), Some("whitelist"));

            let tx_limit = PolicyCheckResult::DeniedExceedsTransactionLimit {
                token: "ETH".to_string(),
                amount: U256::from(10u64),
                limit: U256::from(5u64),
            };
            assert_eq!(tx_limit.rule_name(), Some("tx_limit"));

            let daily_limit = PolicyCheckResult::DeniedExceedsDailyLimit {
                token: "ETH".to_string(),
                amount: U256::from(5u64),
                daily_total: U256::from(8u64),
                limit: U256::from(10u64),
            };
            assert_eq!(daily_limit.rule_name(), Some("daily_limit"));
        }

        #[test]
        fn test_conversion_edge_case_unknown_rule() {
            // This tests the unwrap_or fallback in the conversion
            // Though in practice this should never happen with current variants
            let allowed = PolicyCheckResult::Allowed;
            let policy_result: PolicyResult = allowed.into();
            assert!(policy_result.is_allowed());
        }

        // =========================================================================
        // Daily Limit Boundary Tests
        // =========================================================================

        #[test]
        fn test_daily_limit_amount_exactly_equal_to_limit() {
            // Arrange: Configure daily limit
            let config = PolicyConfig::new().with_daily_limit("ETH", U256::from(1000u64));
            let history = Arc::new(TransactionHistory::in_memory().unwrap());
            let engine = DefaultPolicyEngine::new(config, history).unwrap();

            // Act: Try to send exactly the limit amount
            let tx = create_test_tx(Some("0xREC"), Some(U256::from(1000u64)));
            let result = engine.check(&tx).unwrap();

            // Assert: Should be allowed (not exceeding)
            assert!(result.is_allowed());
        }

        #[test]
        fn test_daily_limit_boundary_total_plus_amount_equals_limit() {
            // Arrange: Configure daily limit and record some transactions
            let config = PolicyConfig::new().with_daily_limit("ETH", U256::from(1000u64));
            let history = Arc::new(TransactionHistory::in_memory().unwrap());
            let engine = DefaultPolicyEngine::new(config, Arc::clone(&history)).unwrap();

            // Record transactions totaling 600
            let tx1 = create_test_tx(Some("0xREC"), Some(U256::from(300u64)));
            engine.record(&tx1).unwrap();
            let tx2 = create_test_tx(Some("0xREC"), Some(U256::from(300u64)));
            engine.record(&tx2).unwrap();

            // Act: Try to send exactly the remaining amount (400)
            let tx3 = create_test_tx(Some("0xREC"), Some(U256::from(400u64)));
            let result = engine.check(&tx3).unwrap();

            // Assert: Should be allowed (total = 1000, exactly at limit)
            assert!(result.is_allowed());
        }

        #[test]
        fn test_daily_limit_boundary_one_over_limit() {
            // Arrange: Configure daily limit
            let config = PolicyConfig::new().with_daily_limit("ETH", U256::from(1000u64));
            let history = Arc::new(TransactionHistory::in_memory().unwrap());
            let engine = DefaultPolicyEngine::new(config, history).unwrap();

            // Act: Try to send one unit over the limit
            let tx = create_test_tx(Some("0xREC"), Some(U256::from(1001u64)));
            let result = engine.check(&tx).unwrap();

            // Assert: Should be denied
            assert!(result.is_denied());
            if let PolicyResult::Denied { rule, .. } = result {
                assert_eq!(rule, "daily_limit");
            }
        }

        #[test]
        fn test_daily_limit_u256_max_amount() {
            // Arrange: Configure daily limit to U256::MAX
            let config = PolicyConfig::new().with_daily_limit("ETH", U256::MAX);
            let history = Arc::new(TransactionHistory::in_memory().unwrap());
            let engine = DefaultPolicyEngine::new(config, history).unwrap();

            // Act: Try to send U256::MAX
            let tx = create_test_tx(Some("0xREC"), Some(U256::MAX));
            let result = engine.check(&tx).unwrap();

            // Assert: Should be allowed
            assert!(result.is_allowed());
        }

        #[test]
        fn test_daily_limit_overflow_protection_with_saturating_add() {
            // Arrange: Configure daily limit to U256::MAX
            let config = PolicyConfig::new().with_daily_limit("ETH", U256::MAX);
            let history = Arc::new(TransactionHistory::in_memory().unwrap());
            let engine = DefaultPolicyEngine::new(config, Arc::clone(&history)).unwrap();

            // Record a very large transaction
            let large_tx = create_test_tx(Some("0xREC"), Some(U256::MAX - U256::from(10u64)));
            engine.record(&large_tx).unwrap();

            // Act: Try to add more (this would overflow without saturating_add)
            let tx = create_test_tx(Some("0xREC"), Some(U256::from(100u64)));
            let result = engine.check(&tx).unwrap();

            // Assert: The saturating_add in check_daily_limit should prevent overflow
            // new_total = (U256::MAX - 10) + 100 = saturates to U256::MAX
            // U256::MAX > U256::MAX is false, so it should be allowed
            assert!(result.is_allowed());
        }

        #[test]
        fn test_daily_limit_with_u256_max_minus_one() {
            // Arrange: Configure limit to U256::MAX and record MAX - 1
            let config = PolicyConfig::new().with_daily_limit("ETH", U256::MAX);
            let history = Arc::new(TransactionHistory::in_memory().unwrap());
            let engine = DefaultPolicyEngine::new(config, Arc::clone(&history)).unwrap();

            // Record U256::MAX - 1
            let tx1 = create_test_tx(Some("0xREC"), Some(U256::MAX - U256::from(1u64)));
            engine.record(&tx1).unwrap();

            // Act: Try to send 1 more (total would be exactly MAX)
            let tx2 = create_test_tx(Some("0xREC"), Some(U256::from(1u64)));
            let result = engine.check(&tx2).unwrap();

            // Assert: Should be allowed (total = MAX, not > MAX)
            assert!(result.is_allowed());
        }

        #[test]
        fn test_daily_limit_accumulation_near_limit() {
            // Arrange: Configure daily limit
            let config = PolicyConfig::new().with_daily_limit("ETH", U256::from(1000u64));
            let history = Arc::new(TransactionHistory::in_memory().unwrap());
            let engine = DefaultPolicyEngine::new(config, Arc::clone(&history)).unwrap();

            // Record transactions approaching the limit
            engine
                .record(&create_test_tx(Some("0xREC"), Some(U256::from(250u64))))
                .unwrap();
            engine
                .record(&create_test_tx(Some("0xREC"), Some(U256::from(250u64))))
                .unwrap();
            engine
                .record(&create_test_tx(Some("0xREC"), Some(U256::from(250u64))))
                .unwrap();
            engine
                .record(&create_test_tx(Some("0xREC"), Some(U256::from(249u64))))
                .unwrap();

            // Total is now 999

            // Act: Try to send 1 more (total = 1000)
            let tx = create_test_tx(Some("0xREC"), Some(U256::from(1u64)));
            let result = engine.check(&tx).unwrap();

            // Assert: Should be allowed
            assert!(result.is_allowed());

            // Act: Try to send 2 more (total = 1001)
            let tx2 = create_test_tx(Some("0xREC"), Some(U256::from(2u64)));
            let result2 = engine.check(&tx2).unwrap();

            // Assert: Should be denied
            assert!(result2.is_denied());
        }

        #[test]
        fn test_daily_limit_zero_amount_with_existing_total() {
            // Arrange: Configure daily limit and record some transactions
            let config = PolicyConfig::new().with_daily_limit("ETH", U256::from(1000u64));
            let history = Arc::new(TransactionHistory::in_memory().unwrap());
            let engine = DefaultPolicyEngine::new(config, Arc::clone(&history)).unwrap();

            // Record transactions at the limit
            engine
                .record(&create_test_tx(Some("0xREC"), Some(U256::from(1000u64))))
                .unwrap();

            // Act: Try to send zero amount
            let tx = create_test_tx(Some("0xREC"), Some(U256::ZERO));
            let result = engine.check(&tx).unwrap();

            // Assert: Should be allowed (not exceeding)
            assert!(result.is_allowed());
        }

        #[test]
        fn test_daily_limit_multiple_tokens_independent() {
            // Arrange: Configure limits for multiple tokens
            let config = PolicyConfig::new()
                .with_daily_limit("ETH", U256::from(1000u64))
                .with_daily_limit(
                    "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                    U256::from(5000u64),
                );

            let history = Arc::new(TransactionHistory::in_memory().unwrap());
            let engine = DefaultPolicyEngine::new(config, Arc::clone(&history)).unwrap();

            // Act: Record ETH at limit
            engine
                .record(&create_test_tx(Some("0xREC"), Some(U256::from(1000u64))))
                .unwrap();

            // Token should still have full limit available
            let token_tx = create_token_tx(
                Some("0xREC"),
                Some(U256::from(5000u64)),
                "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            );
            let result = engine.check(&token_tx).unwrap();

            // Assert: Token transaction should be allowed
            assert!(result.is_allowed());
        }

        #[test]
        fn test_daily_limit_reason_message_includes_values() {
            // Arrange: Configure daily limit and approach it
            let config = PolicyConfig::new().with_daily_limit("ETH", U256::from(1000u64));
            let history = Arc::new(TransactionHistory::in_memory().unwrap());
            let engine = DefaultPolicyEngine::new(config, Arc::clone(&history)).unwrap();

            // Record transaction
            engine
                .record(&create_test_tx(Some("0xREC"), Some(U256::from(900u64))))
                .unwrap();

            // Act: Try to exceed limit
            let tx = create_test_tx(Some("0xREC"), Some(U256::from(200u64)));
            let result = engine.check(&tx).unwrap();

            // Assert: Should be denied with descriptive reason
            assert!(result.is_denied());
            if let PolicyResult::Denied { reason, .. } = result {
                assert!(reason.contains("200")); // amount
                assert!(reason.contains("900")); // daily_total
                assert!(reason.contains("1000")); // limit
                assert!(reason.contains("ETH"));
            }
        }
    }
}
