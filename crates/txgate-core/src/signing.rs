//! Signing flow orchestration for the `TxGate` signing service.
//!
//! This module provides the [`SigningService`] that orchestrates the complete
//! signing flow: parsing, policy checking, and signing.
//!
//! # Flow Overview
//!
//! The signing service performs the following steps:
//!
//! 1. **Parse** - Transform raw transaction bytes into a [`ParsedTx`]
//! 2. **Check** - Evaluate the transaction against policy rules
//! 3. **Sign** - If allowed, sign the transaction hash

//!
//! # Example
//!
//! ```ignore
//! use txgate_core::signing::{SigningService, SigningResult};
//! use txgate_chain::Chain;
//! use txgate_policy::PolicyEngine;
//! use txgate_crypto::Signer;
//!
//! // Create the service with your implementations
//! let service = SigningService::new(chain, policy, signer);
//!
//! // Sign a transaction
//! let result = service.sign(&raw_tx_bytes)?;
//!
//! // Or just check policy without signing (dry run)
//! let result = service.check(&raw_tx_bytes)?;
//! ```
//!
//! # Thread Safety
//!
//! [`SigningService`] is `Send + Sync` when all its components are,
//! allowing it to be shared across async tasks.

use crate::error::{ParseError, PolicyError, SignError};
use crate::types::{ParsedTx, PolicyResult};

// ============================================================================
// Type Aliases
// ============================================================================

/// Signature as a 64-byte array (r || s without recovery ID).
///
/// This is the raw ECDSA signature without the recovery ID byte.
/// For Ethereum transactions that need the recovery ID, it is returned
/// separately in [`SigningResult::recovery_id`].
pub type SignatureBytes = [u8; 64];

// ============================================================================
// SigningError
// ============================================================================

/// Errors that can occur during the signing flow.
///
/// This enum covers all failure modes in the signing orchestration:
/// - Transaction parsing failures
/// - Policy evaluation failures
/// - Policy denial (transaction not allowed)
/// - Signing operation failures
#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    /// Failed to parse the transaction.
    ///
    /// The raw transaction bytes could not be decoded into a [`ParsedTx`].
    #[error("failed to parse transaction: {0}")]
    ParseError(#[from] ParseError),

    /// Policy evaluation failed.
    ///
    /// An error occurred while evaluating the policy rules, distinct from
    /// a policy denial. This typically indicates a configuration or system error.
    #[error("policy check failed: {0}")]
    PolicyError(#[from] PolicyError),

    /// Signing operation failed.
    ///
    /// The cryptographic signing operation failed.
    #[error("signing failed: {0}")]
    SignError(#[from] SignError),

    /// Transaction denied by policy.
    ///
    /// The transaction was rejected by one or more policy rules.
    /// The reason provides details about which rule denied it.
    #[error("transaction denied by policy: {reason}")]
    PolicyDenied {
        /// Human-readable reason for the denial.
        reason: String,
    },
}

impl SigningError {
    /// Create a policy denied error with the given reason.
    #[must_use]
    pub fn policy_denied(reason: impl Into<String>) -> Self {
        Self::PolicyDenied {
            reason: reason.into(),
        }
    }

    /// Returns `true` if this error is a policy denial.
    #[must_use]
    pub const fn is_policy_denied(&self) -> bool {
        matches!(self, Self::PolicyDenied { .. })
    }

    /// Returns the denial reason if this is a policy denial.
    #[must_use]
    pub fn denial_reason(&self) -> Option<&str> {
        match self {
            Self::PolicyDenied { reason } => Some(reason),
            _ => None,
        }
    }
}

// ============================================================================
// PolicyCheckResult
// ============================================================================

/// Detailed result of a policy check operation.
///
/// This enum provides specific information about why a transaction was
/// allowed or denied, enabling detailed error messages and audit logging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyCheckResult {
    /// Transaction is allowed by all policy rules.
    Allowed,
    /// Transaction was denied by a policy rule.
    Denied {
        /// The name of the rule that denied the transaction.
        rule: String,
        /// Human-readable reason for the denial.
        reason: String,
    },
}

impl PolicyCheckResult {
    /// Returns `true` if the policy allows the transaction.
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed)
    }

    /// Returns `true` if the policy denies the transaction.
    #[must_use]
    pub const fn is_denied(&self) -> bool {
        matches!(self, Self::Denied { .. })
    }

    /// Creates a denied result with the given rule and reason.
    #[must_use]
    pub fn denied(rule: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::Denied {
            rule: rule.into(),
            reason: reason.into(),
        }
    }
}

impl From<PolicyResult> for PolicyCheckResult {
    fn from(result: PolicyResult) -> Self {
        match result {
            PolicyResult::Allowed => Self::Allowed,
            PolicyResult::Denied { rule, reason } => Self::Denied { rule, reason },
        }
    }
}

// ============================================================================
// SigningResult
// ============================================================================

/// Comprehensive result of a signing operation.
///
/// Contains all information about the signing attempt:
/// - The parsed transaction
/// - The policy check result
/// - The signature (if signing was performed and allowed)
/// - The recovery ID for ECDSA signatures
///
/// # Signature Format
///
/// For secp256k1 signatures, the signature is 64 bytes (r || s).
/// The recovery ID is returned separately for flexibility in different
/// transaction formats:
///
/// - Ethereum legacy: `v = recovery_id + 27`
/// - Ethereum EIP-155: `v = recovery_id + 35 + chain_id * 2`
/// - Ethereum EIP-2930/EIP-1559: `v = recovery_id`
#[derive(Debug, Clone)]
pub struct SigningResult {
    /// The parsed transaction with all extracted fields.
    pub parsed_tx: ParsedTx,

    /// The result of the policy check.
    pub policy_result: PolicyCheckResult,

    /// The signature (if signing was performed and allowed).
    ///
    /// This is `None` for:
    /// - Dry-run checks (using [`SigningService::check`])
    /// - Transactions denied by policy
    pub signature: Option<SignatureBytes>,

    /// Recovery ID for ECDSA signatures (0 or 1).
    ///
    /// This is needed for Ethereum `ecrecover` operations.
    /// `None` if no signature was produced.
    pub recovery_id: Option<u8>,
}

impl SigningResult {
    /// Create a new signing result for an allowed transaction.
    #[must_use]
    pub const fn allowed(parsed_tx: ParsedTx, signature: SignatureBytes, recovery_id: u8) -> Self {
        Self {
            parsed_tx,
            policy_result: PolicyCheckResult::Allowed,
            signature: Some(signature),
            recovery_id: Some(recovery_id),
        }
    }

    /// Create a signing result for a dry-run check (no signature).
    #[must_use]
    pub const fn checked(parsed_tx: ParsedTx, policy_result: PolicyCheckResult) -> Self {
        Self {
            parsed_tx,
            policy_result,
            signature: None,
            recovery_id: None,
        }
    }

    /// Returns `true` if the transaction was allowed.
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        self.policy_result.is_allowed()
    }

    /// Returns `true` if a signature was produced.
    #[must_use]
    pub const fn has_signature(&self) -> bool {
        self.signature.is_some()
    }

    /// Returns the signature as a 65-byte array with recovery ID appended.
    ///
    /// Returns `None` if no signature was produced.
    #[must_use]
    pub fn signature_with_recovery_id(&self) -> Option<[u8; 65]> {
        match (self.signature, self.recovery_id) {
            (Some(sig), Some(v)) => {
                let mut result = [0u8; 65];
                result[..64].copy_from_slice(&sig);
                result[64] = v;
                Some(result)
            }
            _ => None,
        }
    }
}

// ============================================================================
// SigningService
// ============================================================================

/// Orchestrates the signing flow: parsing, policy checking, and signing.
///
/// The `SigningService` combines a chain parser, policy engine, and signer
/// into a unified interface for processing transaction signing requests.
///
/// # Type Parameters
///
/// * `C` - Chain parser implementing the [`ChainParser`] trait
/// * `P` - Policy engine implementing the [`PolicyEngineExt`] trait
/// * `S` - Signer implementing the [`SignerExt`] trait
///
/// # Thread Safety
///
/// This struct is `Send + Sync` when all type parameters are, allowing
/// it to be safely shared across threads and async tasks.
///
/// # Example
///
/// ```ignore
/// use txgate_core::signing::SigningService;
///
/// // Create with concrete implementations
/// let service = SigningService::new(ethereum_parser, policy_engine, secp256k1_signer);
///
/// // Sign a transaction (includes policy check)
/// let result = service.sign(&raw_tx)?;
/// if result.is_allowed() {
///     let sig = result.signature.expect("signature present");
///     println!("Signature: 0x{}", hex::encode(sig));
/// }
///
/// // Or just check without signing
/// let check_result = service.check(&raw_tx)?;
/// if check_result.is_allowed() {
///     println!("Transaction would be allowed");
/// }
/// ```
pub struct SigningService<C, P, S> {
    /// The chain parser for decoding raw transactions.
    chain: C,
    /// The policy engine for evaluating rules.
    policy: P,
    /// The signer for producing signatures.
    signer: S,
}

impl<C, P, S> std::fmt::Debug for SigningService<C, P, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningService")
            .field("chain", &"<Chain>")
            .field("policy", &"<PolicyEngine>")
            .field("signer", &"<Signer>")
            .finish()
    }
}

impl<C, P, S> SigningService<C, P, S> {
    /// Create a new signing service with the given components.
    ///
    /// # Arguments
    ///
    /// * `chain` - The chain parser for decoding raw transactions
    /// * `policy` - The policy engine for evaluating rules
    /// * `signer` - The signer for producing signatures
    ///
    /// # Example
    ///
    /// ```ignore
    /// let service = SigningService::new(chain, policy, signer);
    /// ```
    #[must_use]
    pub const fn new(chain: C, policy: P, signer: S) -> Self {
        Self {
            chain,
            policy,
            signer,
        }
    }

    /// Get a reference to the chain parser.
    #[must_use]
    pub const fn chain(&self) -> &C {
        &self.chain
    }

    /// Get a reference to the policy engine.
    #[must_use]
    pub const fn policy(&self) -> &P {
        &self.policy
    }

    /// Get a reference to the signer.
    #[must_use]
    pub const fn signer(&self) -> &S {
        &self.signer
    }
}

/// Trait for chain parsers.
///
/// This trait is defined here to avoid circular dependencies.
/// It mirrors the `Chain` trait from `txgate-chain`.
pub trait ChainParser: Send + Sync {
    /// Parse raw transaction bytes into a [`ParsedTx`].
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] if the transaction cannot be decoded.
    fn parse(&self, raw: &[u8]) -> Result<ParsedTx, ParseError>;
}

/// Trait for policy engines.
///
/// This trait is defined here to avoid circular dependencies.
/// It mirrors the `PolicyEngine` trait from `txgate-policy`.
pub trait PolicyEngineExt: Send + Sync {
    /// Check if a transaction is allowed by policy rules.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError`] if policy evaluation fails.
    fn check(&self, tx: &ParsedTx) -> Result<PolicyResult, PolicyError>;
}

/// Trait for signers.
///
/// This trait is defined here to avoid circular dependencies.
/// It mirrors the `Signer` trait from `txgate-crypto`.
pub trait SignerExt: Send + Sync {
    /// Sign a 32-byte hash.
    ///
    /// Returns the signature as a `Vec<u8>`. For secp256k1, this is
    /// 65 bytes: `r (32) || s (32) || v (1)`.
    ///
    /// # Errors
    ///
    /// Returns [`SignError`] if signing fails.
    fn sign(&self, hash: &[u8; 32]) -> Result<Vec<u8>, SignError>;
}

impl<C, P, S> SigningService<C, P, S>
where
    C: ChainParser,
    P: PolicyEngineExt,
    S: SignerExt,
{
    /// Sign a raw transaction.
    ///
    /// This method performs the complete signing flow:
    ///
    /// 1. **Parse** - Transform raw bytes into a [`ParsedTx`]
    /// 2. **Check** - Evaluate against policy rules
    /// 3. **Sign** - If allowed, sign the transaction hash
    ///
    /// # Arguments
    ///
    /// * `raw_tx` - The raw transaction bytes to sign
    ///
    /// # Returns
    ///
    /// A [`SigningResult`] containing the parsed transaction, policy result,
    /// and signature (if allowed).
    ///
    /// # Errors
    ///
    /// Returns [`SigningError`] if:
    /// - Transaction parsing fails ([`SigningError::ParseError`])
    /// - Policy evaluation fails ([`SigningError::PolicyError`])
    /// - Transaction is denied by policy ([`SigningError::PolicyDenied`])
    /// - Signing operation fails ([`SigningError::SignError`])
    ///
    /// # Example
    ///
    /// ```ignore
    /// let result = service.sign(&raw_tx)?;
    ///
    /// // Access the signature
    /// let sig = result.signature.expect("signature present");
    /// let recovery_id = result.recovery_id.expect("recovery ID present");
    ///
    /// // Or get as 65-byte array
    /// let full_sig = result.signature_with_recovery_id().unwrap();
    /// ```
    pub fn sign(&self, raw_tx: &[u8]) -> Result<SigningResult, SigningError> {
        // 1. Parse transaction
        let parsed_tx = self.chain.parse(raw_tx)?;

        // 2. Check policy
        let policy_result = self.policy.check(&parsed_tx)?;

        // 3. If denied, return error with reason
        if let PolicyResult::Denied { reason, .. } = &policy_result {
            return Err(SigningError::PolicyDenied {
                reason: reason.clone(),
            });
        }

        // 4. Sign the transaction hash
        let sig_bytes = self.signer.sign(&parsed_tx.hash)?;

        // Extract signature components (expecting 65 bytes: r || s || v)
        let (signature, recovery_id) = extract_signature_components(&sig_bytes)?;

        // Return result
        Ok(SigningResult {
            parsed_tx,
            policy_result: PolicyCheckResult::Allowed,
            signature: Some(signature),
            recovery_id: Some(recovery_id),
        })
    }

    /// Parse and check policy without signing (dry run).
    ///
    /// This method performs the parsing and policy check steps without
    /// actually signing the transaction. Useful for validating transactions
    /// before committing to sign them.
    ///
    /// # Arguments
    ///
    /// * `raw_tx` - The raw transaction bytes to check
    ///
    /// # Returns
    ///
    /// A [`SigningResult`] containing the parsed transaction and policy result.
    /// The `signature` and `recovery_id` fields will be `None`.
    ///
    /// # Errors
    ///
    /// Returns [`SigningError`] if:
    /// - Transaction parsing fails ([`SigningError::ParseError`])
    /// - Policy evaluation fails ([`SigningError::PolicyError`])
    ///
    /// Note: This method does NOT return an error if the policy denies the
    /// transaction. Instead, check `result.is_allowed()` or `result.policy_result`.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let result = service.check(&raw_tx)?;
    ///
    /// if result.is_allowed() {
    ///     println!("Transaction would be allowed");
    ///     // Optionally proceed to sign
    ///     let sign_result = service.sign(&raw_tx)?;
    /// } else {
    ///     println!("Transaction would be denied");
    /// }
    /// ```
    pub fn check(&self, raw_tx: &[u8]) -> Result<SigningResult, SigningError> {
        // 1. Parse transaction
        let parsed_tx = self.chain.parse(raw_tx)?;

        // 2. Check policy
        let policy_result = self.policy.check(&parsed_tx)?;

        // 3. Return result without signing
        Ok(SigningResult {
            parsed_tx,
            policy_result: policy_result.into(),
            signature: None,
            recovery_id: None,
        })
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Extract signature components from a raw signature.
///
/// Expects 65 bytes: `r (32) || s (32) || v (1)`.
fn extract_signature_components(sig: &[u8]) -> Result<(SignatureBytes, u8), SigningError> {
    // Try to convert to a fixed-size array, which validates the length
    let sig_array: [u8; 65] = sig.try_into().map_err(|_| {
        SigningError::SignError(SignError::signature_failed(format!(
            "expected 65-byte signature, got {} bytes",
            sig.len()
        )))
    })?;

    let mut signature = [0u8; 64];
    signature.copy_from_slice(&sig_array[..64]);
    let recovery_id = sig_array[64];

    Ok((signature, recovery_id))
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
        clippy::large_enum_variant,
        clippy::redundant_clone,
        dead_code
    )]

    use super::*;
    use crate::types::TxType;
    use std::collections::HashMap;

    // ========================================================================
    // Mock Implementations
    // ========================================================================

    /// Configuration for mock chain behavior.
    #[derive(Clone)]
    enum MockChainBehavior {
        Success(ParsedTx),
        Failure(MockParseErrorKind),
    }

    /// Cloneable parse error kinds for mocks.
    #[derive(Clone, Copy)]
    enum MockParseErrorKind {
        UnknownTxType,
        MalformedTransaction,
    }

    impl MockParseErrorKind {
        fn to_error(self) -> ParseError {
            match self {
                Self::UnknownTxType => ParseError::UnknownTxType,
                Self::MalformedTransaction => ParseError::malformed_transaction("mock error"),
            }
        }
    }

    /// Mock chain parser for testing.
    struct MockChain {
        behavior: MockChainBehavior,
    }

    impl MockChain {
        fn success(tx: ParsedTx) -> Self {
            Self {
                behavior: MockChainBehavior::Success(tx),
            }
        }

        fn failure(kind: MockParseErrorKind) -> Self {
            Self {
                behavior: MockChainBehavior::Failure(kind),
            }
        }
    }

    impl ChainParser for MockChain {
        fn parse(&self, _raw: &[u8]) -> Result<ParsedTx, ParseError> {
            match &self.behavior {
                MockChainBehavior::Success(tx) => Ok(tx.clone()),
                MockChainBehavior::Failure(kind) => Err(kind.to_error()),
            }
        }
    }

    /// Configuration for mock policy behavior.
    #[derive(Clone)]
    enum MockPolicyBehavior {
        Allowed,
        Denied { rule: String, reason: String },
        Error(MockPolicyErrorKind),
    }

    /// Cloneable policy error kinds for mocks.
    #[derive(Clone, Copy)]
    enum MockPolicyErrorKind {
        InvalidConfiguration,
    }

    impl MockPolicyErrorKind {
        fn to_error(self) -> PolicyError {
            match self {
                Self::InvalidConfiguration => PolicyError::invalid_configuration("mock error"),
            }
        }
    }

    /// Mock policy engine for testing.
    struct MockPolicy {
        check_behavior: MockPolicyBehavior,
    }

    impl MockPolicy {
        fn allowed() -> Self {
            Self {
                check_behavior: MockPolicyBehavior::Allowed,
            }
        }

        fn denied(rule: &str, reason: &str) -> Self {
            Self {
                check_behavior: MockPolicyBehavior::Denied {
                    rule: rule.to_string(),
                    reason: reason.to_string(),
                },
            }
        }

        #[allow(dead_code)]
        fn check_error(kind: MockPolicyErrorKind) -> Self {
            Self {
                check_behavior: MockPolicyBehavior::Error(kind),
            }
        }
    }

    impl PolicyEngineExt for MockPolicy {
        fn check(&self, _tx: &ParsedTx) -> Result<PolicyResult, PolicyError> {
            match &self.check_behavior {
                MockPolicyBehavior::Allowed => Ok(PolicyResult::Allowed),
                MockPolicyBehavior::Denied { rule, reason } => Ok(PolicyResult::Denied {
                    rule: rule.clone(),
                    reason: reason.clone(),
                }),
                MockPolicyBehavior::Error(kind) => Err(kind.to_error()),
            }
        }
    }

    /// Configuration for mock signer behavior.
    enum MockSignerBehavior {
        Success { recovery_id: u8 },
        Failure(MockSignErrorKind),
    }

    /// Cloneable sign error kinds for mocks.
    #[derive(Clone, Copy)]
    enum MockSignErrorKind {
        InvalidKey,
    }

    impl MockSignErrorKind {
        fn to_error(self) -> SignError {
            match self {
                Self::InvalidKey => SignError::InvalidKey,
            }
        }
    }

    /// Mock signer for testing.
    struct MockSigner {
        behavior: MockSignerBehavior,
    }

    impl MockSigner {
        fn success() -> Self {
            Self {
                behavior: MockSignerBehavior::Success { recovery_id: 0 },
            }
        }

        fn success_with_recovery_id(recovery_id: u8) -> Self {
            Self {
                behavior: MockSignerBehavior::Success { recovery_id },
            }
        }

        fn failure(kind: MockSignErrorKind) -> Self {
            Self {
                behavior: MockSignerBehavior::Failure(kind),
            }
        }
    }

    impl SignerExt for MockSigner {
        fn sign(&self, _hash: &[u8; 32]) -> Result<Vec<u8>, SignError> {
            match &self.behavior {
                MockSignerBehavior::Success { recovery_id } => {
                    let mut sig = vec![0u8; 65];
                    sig[..32].copy_from_slice(&[0xab; 32]); // r
                    sig[32..64].copy_from_slice(&[0xcd; 32]); // s
                    sig[64] = *recovery_id; // v
                    Ok(sig)
                }
                MockSignerBehavior::Failure(kind) => Err(kind.to_error()),
            }
        }
    }

    /// Helper to create a test transaction.
    fn test_tx() -> ParsedTx {
        ParsedTx {
            hash: [0x42; 32],
            recipient: Some("0x1234".to_string()),
            amount: Some(crate::U256::from(100)),
            token: Some("ETH".to_string()),
            token_address: None,
            tx_type: TxType::Transfer,
            chain: "ethereum".to_string(),
            nonce: Some(1),
            chain_id: Some(1),
            metadata: HashMap::new(),
        }
    }

    // ========================================================================
    // SigningError Tests
    // ========================================================================

    mod signing_error_tests {
        use super::*;

        #[test]
        fn test_from_parse_error() {
            let err = ParseError::UnknownTxType;
            let signing_err: SigningError = err.into();

            assert!(matches!(signing_err, SigningError::ParseError(_)));
            assert!(!signing_err.is_policy_denied());
            assert!(signing_err.denial_reason().is_none());
        }

        #[test]
        fn test_from_policy_error() {
            let err = PolicyError::invalid_configuration("test");
            let signing_err: SigningError = err.into();

            assert!(matches!(signing_err, SigningError::PolicyError(_)));
            assert!(!signing_err.is_policy_denied());
        }

        #[test]
        fn test_from_sign_error() {
            let err = SignError::InvalidKey;
            let signing_err: SigningError = err.into();

            assert!(matches!(signing_err, SigningError::SignError(_)));
            assert!(!signing_err.is_policy_denied());
        }

        #[test]
        fn test_policy_denied() {
            let err = SigningError::policy_denied("blacklisted address");

            assert!(err.is_policy_denied());
            assert_eq!(err.denial_reason(), Some("blacklisted address"));
            assert!(err.to_string().contains("denied by policy"));
        }

        #[test]
        fn test_error_display() {
            let parse_err: SigningError = ParseError::UnknownTxType.into();
            assert!(parse_err.to_string().contains("parse transaction"));

            let policy_err: SigningError = PolicyError::invalid_configuration("test").into();
            assert!(policy_err.to_string().contains("policy check failed"));

            let sign_err: SigningError = SignError::InvalidKey.into();
            assert!(sign_err.to_string().contains("signing failed"));

            let denied_err = SigningError::policy_denied("test reason");
            assert!(denied_err.to_string().contains("denied by policy"));
            assert!(denied_err.to_string().contains("test reason"));
        }
    }

    // ========================================================================
    // PolicyCheckResult Tests
    // ========================================================================

    mod policy_check_result_tests {
        use super::*;

        #[test]
        fn test_allowed() {
            let result = PolicyCheckResult::Allowed;
            assert!(result.is_allowed());
            assert!(!result.is_denied());
        }

        #[test]
        fn test_denied() {
            let result = PolicyCheckResult::denied("blacklist", "address blocked");
            assert!(!result.is_allowed());
            assert!(result.is_denied());
        }

        #[test]
        fn test_from_policy_result_allowed() {
            let policy_result = PolicyResult::Allowed;
            let check_result: PolicyCheckResult = policy_result.into();
            assert!(check_result.is_allowed());
        }

        #[test]
        fn test_from_policy_result_denied() {
            let policy_result = PolicyResult::Denied {
                rule: "whitelist".to_string(),
                reason: "not in list".to_string(),
            };
            let check_result: PolicyCheckResult = policy_result.into();
            assert!(check_result.is_denied());

            if let PolicyCheckResult::Denied { rule, reason } = check_result {
                assert_eq!(rule, "whitelist");
                assert_eq!(reason, "not in list");
            } else {
                panic!("expected Denied variant");
            }
        }
    }

    // ========================================================================
    // SigningResult Tests
    // ========================================================================

    mod signing_result_tests {
        use super::*;

        #[test]
        fn test_allowed_constructor() {
            let tx = test_tx();
            let sig = [0xab; 64];
            let result = SigningResult::allowed(tx.clone(), sig, 0);

            assert!(result.is_allowed());
            assert!(result.has_signature());
            assert_eq!(result.signature, Some(sig));
            assert_eq!(result.recovery_id, Some(0));
            assert_eq!(result.parsed_tx.hash, tx.hash);
        }

        #[test]
        fn test_checked_constructor() {
            let tx = test_tx();
            let result = SigningResult::checked(tx.clone(), PolicyCheckResult::Allowed);

            assert!(result.is_allowed());
            assert!(!result.has_signature());
            assert!(result.signature.is_none());
            assert!(result.recovery_id.is_none());
        }

        #[test]
        fn test_signature_with_recovery_id() {
            let tx = test_tx();
            let sig = [0xab; 64];
            let result = SigningResult::allowed(tx, sig, 1);

            let full_sig = result.signature_with_recovery_id().unwrap();
            assert_eq!(full_sig.len(), 65);
            assert_eq!(&full_sig[..64], &sig);
            assert_eq!(full_sig[64], 1);
        }

        #[test]
        fn test_signature_with_recovery_id_none() {
            let tx = test_tx();
            let result = SigningResult::checked(tx, PolicyCheckResult::Allowed);

            assert!(result.signature_with_recovery_id().is_none());
        }
    }

    // ========================================================================
    // SigningService Tests
    // ========================================================================

    mod signing_service_tests {
        use super::*;

        #[test]
        fn test_successful_signing_flow() {
            let tx = test_tx();
            let chain = MockChain::success(tx.clone());
            let policy = MockPolicy::allowed();
            let signer = MockSigner::success();

            let service = SigningService::new(chain, policy, signer);
            let result = service.sign(&[0x01, 0x02, 0x03]).unwrap();

            assert!(result.is_allowed());
            assert!(result.has_signature());
            assert!(result.signature.is_some());
            assert_eq!(result.recovery_id, Some(0));
            assert_eq!(result.parsed_tx.hash, tx.hash);
        }

        #[test]
        fn test_policy_denial_flow() {
            let tx = test_tx();
            let chain = MockChain::success(tx);
            let policy = MockPolicy::denied("blacklist", "address is blacklisted");
            let signer = MockSigner::success();

            let service = SigningService::new(chain, policy, signer);
            let result = service.sign(&[0x01]);

            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(err.is_policy_denied());
            assert_eq!(err.denial_reason(), Some("address is blacklisted"));
        }

        #[test]
        fn test_parse_error_handling() {
            let chain = MockChain::failure(MockParseErrorKind::UnknownTxType);
            let policy = MockPolicy::allowed();
            let signer = MockSigner::success();

            let service = SigningService::new(chain, policy, signer);
            let result = service.sign(&[0x01]);

            assert!(result.is_err());
            assert!(matches!(result.unwrap_err(), SigningError::ParseError(_)));
        }

        #[test]
        fn test_sign_error_handling() {
            let tx = test_tx();
            let chain = MockChain::success(tx);
            let policy = MockPolicy::allowed();
            let signer = MockSigner::failure(MockSignErrorKind::InvalidKey);

            let service = SigningService::new(chain, policy, signer);
            let result = service.sign(&[0x01]);

            assert!(result.is_err());
            assert!(matches!(result.unwrap_err(), SigningError::SignError(_)));
        }

        #[test]
        fn test_dry_run_check() {
            let tx = test_tx();
            let chain = MockChain::success(tx.clone());
            let policy = MockPolicy::allowed();
            let signer = MockSigner::success();

            let service = SigningService::new(chain, policy, signer);
            let result = service.check(&[0x01]).unwrap();

            assert!(result.is_allowed());
            assert!(!result.has_signature());
            assert!(result.signature.is_none());
            assert_eq!(result.parsed_tx.hash, tx.hash);
        }

        #[test]
        fn test_dry_run_check_denied() {
            let tx = test_tx();
            let chain = MockChain::success(tx);
            let policy = MockPolicy::denied("tx_limit", "exceeds limit");
            let signer = MockSigner::success();

            let service = SigningService::new(chain, policy, signer);
            let result = service.check(&[0x01]).unwrap();

            // check() does NOT return error for denial
            assert!(!result.is_allowed());
            assert!(!result.has_signature());
        }

        #[test]
        fn test_recovery_id_passed_through() {
            let tx = test_tx();
            let chain = MockChain::success(tx);
            let policy = MockPolicy::allowed();
            let signer = MockSigner::success_with_recovery_id(1);

            let service = SigningService::new(chain, policy, signer);
            let result = service.sign(&[0x01]).unwrap();

            assert_eq!(result.recovery_id, Some(1));
        }

        #[test]
        fn test_accessors() {
            let tx = test_tx();
            let chain = MockChain::success(tx);
            let policy = MockPolicy::allowed();
            let signer = MockSigner::success();

            let service = SigningService::new(chain, policy, signer);

            // Test accessors compile and work
            let _ = service.chain();
            let _ = service.policy();
            let _ = service.signer();
        }

        #[test]
        fn test_debug_impl() {
            let tx = test_tx();
            let chain = MockChain::success(tx);
            let policy = MockPolicy::allowed();
            let signer = MockSigner::success();

            let service = SigningService::new(chain, policy, signer);
            let debug_str = format!("{service:?}");

            assert!(debug_str.contains("SigningService"));
        }
    }

    // ========================================================================
    // Extract Signature Components Tests
    // ========================================================================

    mod extract_signature_tests {
        use super::*;

        #[test]
        fn test_valid_65_byte_signature() {
            let mut sig = vec![0u8; 65];
            sig[..32].copy_from_slice(&[0xaa; 32]);
            sig[32..64].copy_from_slice(&[0xbb; 32]);
            sig[64] = 1;

            let (signature, recovery_id) = extract_signature_components(&sig).unwrap();

            assert_eq!(&signature[..32], &[0xaa; 32]);
            assert_eq!(&signature[32..64], &[0xbb; 32]);
            assert_eq!(recovery_id, 1);
        }

        #[test]
        fn test_invalid_length_too_short() {
            let sig = vec![0u8; 64];
            let result = extract_signature_components(&sig);

            assert!(result.is_err());
            assert!(matches!(result.unwrap_err(), SigningError::SignError(_)));
        }

        #[test]
        fn test_invalid_length_too_long() {
            let sig = vec![0u8; 66];
            let result = extract_signature_components(&sig);

            assert!(result.is_err());
        }
    }

    // ========================================================================
    // Send + Sync Tests
    // ========================================================================

    mod send_sync_tests {
        use super::*;

        #[test]
        fn test_signing_error_is_send_sync() {
            fn assert_send_sync<T: Send + Sync>() {}
            assert_send_sync::<SigningError>();
        }

        #[test]
        fn test_signing_result_is_send_sync() {
            fn assert_send_sync<T: Send + Sync>() {}
            assert_send_sync::<SigningResult>();
        }

        #[test]
        fn test_policy_check_result_is_send_sync() {
            fn assert_send_sync<T: Send + Sync>() {}
            assert_send_sync::<PolicyCheckResult>();
        }

        // SigningService is Send + Sync when C, P, S are
        // We can't easily test this with mocks using RefCell (not Sync),
        // but the trait bounds enforce it for real implementations.
    }
}
