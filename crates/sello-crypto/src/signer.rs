//! High-level signing traits and implementations.
//!
//! This module provides the [`Signer`] trait for abstracting over different
//! signing implementations, and concrete implementations for specific curves.
//!
//! # Supported Signers
//!
//! - [`Secp256k1Signer`] - For Ethereum, Bitcoin, Tron, and Ripple
//! - [`Ed25519Signer`] - For Solana and other ed25519-based chains
//!
//! # Example
//!
//! ```rust
//! use sello_crypto::signer::{Signer, Secp256k1Signer, Chain};
//!
//! // Generate a new signer
//! let signer = Secp256k1Signer::generate();
//!
//! // Get the Ethereum address
//! let address = signer.address(Chain::Ethereum).expect("valid address");
//! println!("Ethereum address: {address}");
//!
//! // Sign a message hash
//! let hash = [0u8; 32]; // In practice, this would be a real hash
//! let signature = signer.sign(&hash).expect("signing failed");
//! assert_eq!(signature.len(), 65); // r || s || v
//! ```

use bitcoin::secp256k1::PublicKey as BitcoinPublicKey;
use bitcoin::{Address, CompressedPublicKey, Network};
use sha3::{Digest, Keccak256};

use crate::keypair::{KeyPair, Secp256k1KeyPair};
use sello_core::error::SignError;

// ============================================================================
// Chain Enum
// ============================================================================

/// Supported blockchain networks for address derivation.
///
/// This enum represents the different blockchain networks that Sello supports
/// for address derivation. Each chain may have different address formats and
/// derivation rules.
///
/// # Example
///
/// ```rust
/// use sello_crypto::signer::{Signer, Secp256k1Signer, Chain};
///
/// let signer = Secp256k1Signer::generate();
///
/// // Derive Ethereum address
/// let eth_addr = signer.address(Chain::Ethereum).expect("valid");
/// assert!(eth_addr.starts_with("0x"));
///
/// // Solana requires Ed25519, so this will fail
/// let sol_result = signer.address(Chain::Solana);
/// assert!(sol_result.is_err());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Chain {
    /// Ethereum and EVM-compatible chains (Polygon, BSC, Arbitrum, etc.)
    Ethereum,
    /// Bitcoin mainnet
    Bitcoin,
    /// Solana (requires Ed25519)
    Solana,
    /// Tron network (uses same curve as Ethereum but different address format)
    Tron,
    /// Ripple/XRP Ledger
    Ripple,
}

impl std::fmt::Display for Chain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ethereum => write!(f, "ethereum"),
            Self::Bitcoin => write!(f, "bitcoin"),
            Self::Solana => write!(f, "solana"),
            Self::Tron => write!(f, "tron"),
            Self::Ripple => write!(f, "ripple"),
        }
    }
}

// ============================================================================
// CurveType Enum
// ============================================================================

/// Elliptic curve types supported by Sello.
///
/// This enum identifies the cryptographic curve used by a signer,
/// which is important for ensuring compatibility with different blockchains.
///
/// # Curve Selection
///
/// - [`CurveType::Secp256k1`] - Used by Ethereum, Bitcoin, Tron, Ripple
/// - [`CurveType::Ed25519`] - Used by Solana, NEAR, Cosmos (some chains)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CurveType {
    /// The secp256k1 curve used by Bitcoin, Ethereum, and related chains.
    Secp256k1,
    /// The Ed25519 curve used by Solana, NEAR, and some other chains.
    Ed25519,
}

impl std::fmt::Display for CurveType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Secp256k1 => write!(f, "secp256k1"),
            Self::Ed25519 => write!(f, "ed25519"),
        }
    }
}

// ============================================================================
// Signer Trait
// ============================================================================

/// Trait for transaction signing operations.
///
/// This trait provides a high-level interface for signing transaction hashes
/// and deriving blockchain addresses from the underlying key pair.
///
/// # Thread Safety
///
/// All implementations must be `Send + Sync` to support multi-threaded
/// signing operations.
///
/// # Signature Format
///
/// For secp256k1 signers, the signature is returned as 65 bytes:
/// - `r` (32 bytes) - The R component of the ECDSA signature
/// - `s` (32 bytes) - The S component of the ECDSA signature
/// - `v` (1 byte) - The recovery ID (0 or 1)
///
/// For Ethereum transactions, you may need to adjust `v`:
/// - Legacy transactions: `v = recovery_id + 27`
/// - EIP-155: `v = recovery_id + 35 + chain_id * 2`
/// - EIP-2930/EIP-1559: `v = recovery_id`
///
/// # Example
///
/// ```rust
/// use sello_crypto::signer::{Signer, Secp256k1Signer, Chain, CurveType};
///
/// fn sign_transaction<S: Signer>(signer: &S, hash: &[u8; 32]) -> Vec<u8> {
///     signer.sign(hash).expect("signing failed")
/// }
///
/// let signer = Secp256k1Signer::generate();
/// assert_eq!(signer.curve(), CurveType::Secp256k1);
///
/// let hash = [0u8; 32];
/// let sig = sign_transaction(&signer, &hash);
/// assert_eq!(sig.len(), 65);
/// ```
pub trait Signer: Send + Sync {
    /// Sign a 32-byte message hash.
    ///
    /// # Arguments
    /// * `hash` - The pre-computed hash of the message/transaction to sign.
    ///   This should be a cryptographic hash (e.g., Keccak-256 for Ethereum),
    ///   NOT the raw message.
    ///
    /// # Returns
    /// A signature that can be verified against this signer's public key.
    /// For secp256k1, this is 65 bytes: `r || s || v` where `v` is the recovery ID.
    ///
    /// # Errors
    /// Returns an error if signing fails (e.g., due to key corruption).
    ///
    /// # Example
    ///
    /// ```rust
    /// use sello_crypto::signer::{Signer, Secp256k1Signer};
    /// use sha3::{Digest, Keccak256};
    ///
    /// let signer = Secp256k1Signer::generate();
    ///
    /// // Hash the message first
    /// let message = b"Hello, Ethereum!";
    /// let hash: [u8; 32] = Keccak256::digest(message).into();
    ///
    /// // Sign the hash
    /// let signature = signer.sign(&hash).expect("signing failed");
    /// assert_eq!(signature.len(), 65);
    /// ```
    fn sign(&self, hash: &[u8; 32]) -> Result<Vec<u8>, SignError>;

    /// Get the public key bytes.
    ///
    /// Returns the compressed public key:
    /// - secp256k1: 33 bytes (prefix + X coordinate)
    /// - ed25519: 32 bytes
    ///
    /// # Example
    ///
    /// ```rust
    /// use sello_crypto::signer::{Signer, Secp256k1Signer};
    ///
    /// let signer = Secp256k1Signer::generate();
    /// let pubkey = signer.public_key();
    /// assert_eq!(pubkey.len(), 33); // Compressed secp256k1
    /// ```
    fn public_key(&self) -> &[u8];

    /// Derive the blockchain address for a specific chain.
    ///
    /// # Arguments
    /// * `chain` - The blockchain network to derive the address for.
    ///
    /// # Returns
    /// The address as a string with the appropriate format for the chain:
    /// - Ethereum: EIP-55 checksummed hex with `0x` prefix
    /// - Bitcoin: `Base58Check` encoded P2PKH address
    /// - Tron: `Base58Check` encoded with `0x41` prefix (starts with `T`)
    /// - Solana: Base58 encoded (requires Ed25519)
    /// - Ripple: `Base58Check` with Ripple alphabet
    ///
    /// # Errors
    /// Returns an error if:
    /// - The chain requires a different curve (e.g., Solana needs Ed25519)
    /// - Address derivation is not yet implemented for the chain
    ///
    /// # Example
    ///
    /// ```rust
    /// use sello_crypto::signer::{Signer, Secp256k1Signer, Chain};
    ///
    /// let signer = Secp256k1Signer::generate();
    ///
    /// // Get Ethereum address (EIP-55 checksummed)
    /// let address = signer.address(Chain::Ethereum).expect("valid");
    /// assert!(address.starts_with("0x"));
    /// assert_eq!(address.len(), 42); // 0x + 40 hex chars
    /// ```
    fn address(&self, chain: Chain) -> Result<String, SignError>;

    /// Get the curve type used by this signer.
    ///
    /// This is useful for determining compatibility with different chains.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sello_crypto::signer::{Signer, Secp256k1Signer, CurveType};
    ///
    /// let signer = Secp256k1Signer::generate();
    /// assert_eq!(signer.curve(), CurveType::Secp256k1);
    /// ```
    fn curve(&self) -> CurveType;
}

// ============================================================================
// Secp256k1Signer Implementation
// ============================================================================

/// Secp256k1 signer for Ethereum, Bitcoin, Tron, and Ripple.
///
/// This signer wraps a [`Secp256k1KeyPair`] and provides a high-level
/// signing interface that returns recoverable signatures suitable for
/// blockchain transactions.
///
/// # Signature Format
///
/// Signatures are returned as 65 bytes: `r (32) || s (32) || v (1)`
/// where `v` is the raw recovery ID (0 or 1).
///
/// # Security
///
/// - The underlying key pair uses secure key material handling
/// - Signatures are normalized to prevent malleability
/// - Recovery IDs are computed correctly for `ecrecover`
///
/// # Example
///
/// ```rust
/// use sello_crypto::signer::{Signer, Secp256k1Signer, Chain};
///
/// // Generate a new signer
/// let signer = Secp256k1Signer::generate();
///
/// // Or create from raw bytes
/// let secret = [0x42u8; 32]; // Use real secret in production!
/// let signer = Secp256k1Signer::from_bytes(secret).expect("valid key");
///
/// // Get the Ethereum address
/// let address = signer.address(Chain::Ethereum).expect("valid");
/// println!("Address: {address}");
///
/// // Sign a hash
/// let hash = [0u8; 32];
/// let signature = signer.sign(&hash).expect("signing failed");
/// assert_eq!(signature.len(), 65);
/// ```
#[derive(Debug)]
pub struct Secp256k1Signer {
    /// The underlying key pair
    key_pair: Secp256k1KeyPair,
    /// Cached compressed public key bytes
    public_key_bytes: [u8; 33],
}

impl Secp256k1Signer {
    /// Create a new signer from a key pair.
    ///
    /// # Arguments
    /// * `key_pair` - The secp256k1 key pair to use for signing.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sello_crypto::keypair::{KeyPair, Secp256k1KeyPair};
    /// use sello_crypto::signer::Secp256k1Signer;
    ///
    /// let key_pair = Secp256k1KeyPair::generate();
    /// let signer = Secp256k1Signer::new(key_pair);
    /// ```
    #[must_use]
    pub fn new(key_pair: Secp256k1KeyPair) -> Self {
        let public_key_bytes = *key_pair.public_key().compressed();
        Self {
            key_pair,
            public_key_bytes,
        }
    }

    /// Create a new signer with a randomly generated key.
    ///
    /// Uses a cryptographically secure random number generator.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sello_crypto::signer::Secp256k1Signer;
    ///
    /// let signer = Secp256k1Signer::generate();
    /// ```
    #[must_use]
    pub fn generate() -> Self {
        Self::new(Secp256k1KeyPair::generate())
    }

    /// Create a signer from raw secret key bytes.
    ///
    /// # Arguments
    /// * `bytes` - The 32-byte secret key material.
    ///
    /// # Errors
    /// Returns an error if the bytes don't represent a valid secp256k1
    /// secret key (e.g., zero or greater than the curve order).
    ///
    /// # Example
    ///
    /// ```rust
    /// use sello_crypto::signer::Secp256k1Signer;
    ///
    /// let secret = [0x42u8; 32];
    /// let signer = Secp256k1Signer::from_bytes(secret).expect("valid key");
    /// ```
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, SignError> {
        let key_pair = Secp256k1KeyPair::from_bytes(bytes)?;
        Ok(Self::new(key_pair))
    }

    /// Get a reference to the underlying key pair.
    ///
    /// This is useful when you need access to the full key pair functionality.
    #[must_use]
    pub const fn key_pair(&self) -> &Secp256k1KeyPair {
        &self.key_pair
    }

    /// Derive the Ethereum address and return as EIP-55 checksummed string.
    fn ethereum_address(&self) -> String {
        let address = self.key_pair.public_key().ethereum_address();
        to_eip55_checksum(&address)
    }

    /// Derive the Bitcoin P2WPKH (bech32) address for the specified network.
    ///
    /// P2WPKH addresses start with `bc1q` on mainnet and `tb1q` on testnet.
    ///
    /// # Arguments
    /// * `network` - The Bitcoin network (mainnet, testnet, signet, regtest).
    ///
    /// # Returns
    /// The bech32-encoded P2WPKH address.
    fn bitcoin_p2wpkh_address(&self, network: Network) -> Result<String, SignError> {
        // Get the compressed public key bytes (33 bytes)
        let compressed = self.public_key_bytes;

        // Create a bitcoin PublicKey from the compressed bytes
        let bitcoin_pubkey = BitcoinPublicKey::from_slice(&compressed)
            .map_err(|e| SignError::signature_failed(format!("Invalid public key: {e}")))?;

        // Create CompressedPublicKey wrapper
        let compressed_pubkey = CompressedPublicKey(bitcoin_pubkey);

        // Create P2WPKH address
        let address = Address::p2wpkh(&compressed_pubkey, network);

        Ok(address.to_string())
    }
}

impl Signer for Secp256k1Signer {
    fn sign(&self, hash: &[u8; 32]) -> Result<Vec<u8>, SignError> {
        let signature = self.key_pair.sign(hash)?;
        // Return 65-byte recoverable signature: r || s || v
        Ok(signature.to_recoverable_bytes().to_vec())
    }

    fn public_key(&self) -> &[u8] {
        &self.public_key_bytes
    }

    fn address(&self, chain: Chain) -> Result<String, SignError> {
        match chain {
            Chain::Ethereum => Ok(self.ethereum_address()),
            Chain::Bitcoin => {
                // P2WPKH bech32 address (starts with bc1q)
                self.bitcoin_p2wpkh_address(Network::Bitcoin)
            }
            Chain::Tron => {
                // TRON uses same format as Ethereum but with T prefix and Base58Check
                // TODO: Implement Tron address derivation
                Err(SignError::signature_failed(
                    "Tron address derivation not yet implemented",
                ))
            }
            Chain::Ripple => {
                // Ripple uses secp256k1 but with Base58Check using Ripple alphabet
                // TODO: Implement Ripple address derivation
                Err(SignError::signature_failed(
                    "Ripple address derivation not yet implemented",
                ))
            }
            Chain::Solana => {
                // Solana requires Ed25519, not secp256k1
                Err(SignError::wrong_curve("ed25519", "secp256k1"))
            }
        }
    }

    fn curve(&self) -> CurveType {
        CurveType::Secp256k1
    }
}

// ============================================================================
// Ed25519Signer Implementation
// ============================================================================

/// Ed25519 signer for Solana and other ed25519-based chains.
///
/// This signer wraps an [`Ed25519KeyPair`](crate::keypair::Ed25519KeyPair) and provides
/// a high-level signing interface suitable for blockchain transactions.
///
/// # Signature Format
///
/// Signatures are returned as 64 bytes: the standard ed25519 signature format.
///
/// # Security
///
/// - The underlying key pair uses secure key material handling
/// - Uses ed25519-dalek for cryptographic operations
///
/// # Example
///
/// ```rust
/// use sello_crypto::signer::{Signer, Ed25519Signer, Chain};
///
/// // Generate a new signer
/// let signer = Ed25519Signer::generate();
///
/// // Get the Solana address
/// let address = signer.address(Chain::Solana).expect("valid");
/// println!("Solana address: {address}");
///
/// // Sign a hash
/// let hash = [0u8; 32];
/// let signature = signer.sign(&hash).expect("signing failed");
/// assert_eq!(signature.len(), 64);
/// ```
#[derive(Debug)]
pub struct Ed25519Signer {
    /// The underlying key pair
    key_pair: crate::keypair::Ed25519KeyPair,
    /// Cached public key bytes
    public_key_bytes: [u8; 32],
}

impl Ed25519Signer {
    /// Create a new signer from a key pair.
    ///
    /// # Arguments
    /// * `key_pair` - The ed25519 key pair to use for signing.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sello_crypto::keypair::{KeyPair, Ed25519KeyPair};
    /// use sello_crypto::signer::Ed25519Signer;
    ///
    /// let key_pair = Ed25519KeyPair::generate();
    /// let signer = Ed25519Signer::new(key_pair);
    /// ```
    #[must_use]
    pub fn new(key_pair: crate::keypair::Ed25519KeyPair) -> Self {
        let public_key_bytes = *key_pair.public_key().as_bytes();
        Self {
            key_pair,
            public_key_bytes,
        }
    }

    /// Create a new signer with a randomly generated key.
    ///
    /// Uses a cryptographically secure random number generator.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sello_crypto::signer::Ed25519Signer;
    ///
    /// let signer = Ed25519Signer::generate();
    /// ```
    #[must_use]
    pub fn generate() -> Self {
        Self::new(crate::keypair::Ed25519KeyPair::generate())
    }

    /// Create a signer from raw secret key bytes.
    ///
    /// # Arguments
    /// * `bytes` - The 32-byte secret key material.
    ///
    /// # Errors
    /// Returns an error if the bytes don't represent a valid ed25519 secret key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use sello_crypto::signer::Ed25519Signer;
    ///
    /// let secret = [0x42u8; 32];
    /// let signer = Ed25519Signer::from_bytes(secret).expect("valid key");
    /// ```
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, SignError> {
        let key_pair = crate::keypair::Ed25519KeyPair::from_bytes(bytes)?;
        Ok(Self::new(key_pair))
    }

    /// Get a reference to the underlying key pair.
    ///
    /// This is useful when you need access to the full key pair functionality.
    #[must_use]
    pub const fn key_pair(&self) -> &crate::keypair::Ed25519KeyPair {
        &self.key_pair
    }

    /// Derive the Solana address (base58-encoded public key).
    fn solana_address(&self) -> String {
        self.key_pair.public_key().solana_address()
    }
}

impl Signer for Ed25519Signer {
    fn sign(&self, hash: &[u8; 32]) -> Result<Vec<u8>, SignError> {
        let signature = self.key_pair.sign(hash)?;
        // Return 64-byte ed25519 signature
        Ok(signature.as_ref().to_vec())
    }

    fn public_key(&self) -> &[u8] {
        &self.public_key_bytes
    }

    fn address(&self, chain: Chain) -> Result<String, SignError> {
        match chain {
            Chain::Solana => Ok(self.solana_address()),
            Chain::Ethereum | Chain::Bitcoin | Chain::Tron | Chain::Ripple => {
                // These chains require secp256k1, not ed25519
                Err(SignError::wrong_curve("secp256k1", "ed25519"))
            }
        }
    }

    fn curve(&self) -> CurveType {
        CurveType::Ed25519
    }
}

// ============================================================================
// EIP-55 Address Checksum
// ============================================================================

/// Convert an Ethereum address to EIP-55 checksummed format.
///
/// EIP-55 uses a mixed-case hexadecimal encoding where the case of each
/// letter encodes a checksum. This helps prevent typos when copying addresses.
///
/// # Algorithm
///
/// 1. Convert the address to lowercase hex (without `0x` prefix)
/// 2. Hash the hex string with Keccak-256
/// 3. For each character in the hex address:
///    - If it's a digit (0-9), keep it as-is
///    - If it's a letter (a-f), uppercase it if the corresponding nibble
///      in the hash is >= 8
///
/// # Arguments
/// * `address` - The 20-byte Ethereum address.
///
/// # Returns
/// The EIP-55 checksummed address string with `0x` prefix.
///
/// # Example
///
/// ```ignore
/// let address = hex::decode("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed").unwrap();
/// let checksummed = to_eip55_checksum(&address.try_into().unwrap());
/// assert_eq!(checksummed, "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
/// ```
fn to_eip55_checksum(address: &[u8; 20]) -> String {
    // Step 1: Convert to lowercase hex (without 0x prefix)
    let hex_addr = hex::encode(address);

    // Step 2: Hash the lowercase hex address
    // Keccak256 always produces exactly 32 bytes
    let hash: [u8; 32] = Keccak256::digest(hex_addr.as_bytes()).into();

    // Step 3: Build the checksummed address
    let mut checksummed = String::with_capacity(42);
    checksummed.push_str("0x");

    for (i, c) in hex_addr.chars().enumerate() {
        if c.is_ascii_digit() {
            // Digits don't have case, keep as-is
            checksummed.push(c);
        } else {
            // For letters, check the corresponding nibble in the hash
            // Each byte in the hash has two nibbles (4 bits each)
            // Since hex_addr is exactly 40 chars (20 bytes * 2), i/2 ranges from 0 to 19
            // The hash is 32 bytes, so this indexing is always safe
            // We use get() for safety even though the bounds are guaranteed
            let hash_byte = hash.get(i / 2).copied().unwrap_or(0);
            let nibble = if i % 2 == 0 {
                (hash_byte >> 4) & 0x0f // High nibble
            } else {
                hash_byte & 0x0f // Low nibble
            };

            // If nibble >= 8, uppercase the letter
            if nibble >= 8 {
                checksummed.push(c.to_ascii_uppercase());
            } else {
                checksummed.push(c);
            }
        }
    }

    checksummed
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::panic)]
    #![allow(clippy::uninlined_format_args)]

    use super::*;

    // ------------------------------------------------------------------------
    // Chain Enum Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_chain_display() {
        assert_eq!(Chain::Ethereum.to_string(), "ethereum");
        assert_eq!(Chain::Bitcoin.to_string(), "bitcoin");
        assert_eq!(Chain::Solana.to_string(), "solana");
        assert_eq!(Chain::Tron.to_string(), "tron");
        assert_eq!(Chain::Ripple.to_string(), "ripple");
    }

    #[test]
    fn test_chain_equality() {
        assert_eq!(Chain::Ethereum, Chain::Ethereum);
        assert_ne!(Chain::Ethereum, Chain::Bitcoin);
    }

    #[test]
    fn test_chain_debug() {
        let debug_output = format!("{:?}", Chain::Ethereum);
        assert_eq!(debug_output, "Ethereum");
    }

    // ------------------------------------------------------------------------
    // CurveType Enum Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_curve_type_display() {
        assert_eq!(CurveType::Secp256k1.to_string(), "secp256k1");
        assert_eq!(CurveType::Ed25519.to_string(), "ed25519");
    }

    #[test]
    fn test_curve_type_equality() {
        assert_eq!(CurveType::Secp256k1, CurveType::Secp256k1);
        assert_ne!(CurveType::Secp256k1, CurveType::Ed25519);
    }

    // ------------------------------------------------------------------------
    // Secp256k1Signer Creation Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_generate_creates_valid_signer() {
        let signer = Secp256k1Signer::generate();

        // Public key should be 33 bytes (compressed)
        assert_eq!(signer.public_key().len(), 33);

        // Curve type should be secp256k1
        assert_eq!(signer.curve(), CurveType::Secp256k1);
    }

    #[test]
    fn test_generate_produces_unique_signers() {
        let signer1 = Secp256k1Signer::generate();
        let signer2 = Secp256k1Signer::generate();

        // Should generate different public keys
        assert_ne!(signer1.public_key(), signer2.public_key());
    }

    #[test]
    fn test_from_bytes_success() {
        let bytes = [0x42u8; 32];
        let result = Secp256k1Signer::from_bytes(bytes);
        assert!(result.is_ok());
    }

    #[test]
    fn test_from_bytes_invalid_zero() {
        let bytes = [0u8; 32];
        let result = Secp256k1Signer::from_bytes(bytes);
        assert!(matches!(result, Err(SignError::InvalidKey)));
    }

    #[test]
    fn test_from_bytes_deterministic() {
        let bytes = [0x42u8; 32];

        let signer1 = Secp256k1Signer::from_bytes(bytes).expect("valid key");
        let signer2 = Secp256k1Signer::from_bytes(bytes).expect("valid key");

        assert_eq!(signer1.public_key(), signer2.public_key());
    }

    #[test]
    fn test_new_from_keypair() {
        let key_pair = Secp256k1KeyPair::generate();
        let expected_pubkey = *key_pair.public_key().compressed();

        let signer = Secp256k1Signer::new(key_pair);

        assert_eq!(signer.public_key(), &expected_pubkey);
    }

    // ------------------------------------------------------------------------
    // Signing Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_sign_produces_65_bytes() {
        let signer = Secp256k1Signer::generate();
        let hash = [0x42u8; 32];

        let signature = signer.sign(&hash).expect("signing should succeed");

        // Signature should be 65 bytes: r (32) || s (32) || v (1)
        assert_eq!(signature.len(), 65);
    }

    #[test]
    fn test_sign_recovery_id_valid() {
        let signer = Secp256k1Signer::generate();
        let hash = [0x42u8; 32];

        let signature = signer.sign(&hash).expect("signing should succeed");

        // Recovery ID (last byte) should be 0 or 1
        let recovery_id = signature[64];
        assert!(recovery_id == 0 || recovery_id == 1);
    }

    #[test]
    fn test_different_hashes_produce_different_signatures() {
        let signer = Secp256k1Signer::generate();
        let hash1 = [0x42u8; 32];
        let hash2 = [0x43u8; 32];

        let sig1 = signer.sign(&hash1).expect("signing should succeed");
        let sig2 = signer.sign(&hash2).expect("signing should succeed");

        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_sign_is_deterministic_with_same_key() {
        // Note: ECDSA is NOT deterministic by default (uses random k).
        // However, the signature components should be consistent with the keypair.
        let bytes = [0x42u8; 32];
        let signer = Secp256k1Signer::from_bytes(bytes).expect("valid key");
        let hash = [0x42u8; 32];

        // Sign twice with same key and hash
        let sig1 = signer.sign(&hash).expect("signing should succeed");
        let sig2 = signer.sign(&hash).expect("signing should succeed");

        // Note: These may or may not be equal depending on k256's implementation
        // k256 uses RFC 6979 deterministic nonces, so they should be equal
        assert_eq!(sig1, sig2, "k256 uses RFC 6979 deterministic nonces");
    }

    // ------------------------------------------------------------------------
    // Ethereum Address Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_ethereum_address_format() {
        let signer = Secp256k1Signer::generate();

        let address = signer.address(Chain::Ethereum).expect("valid address");

        // Should start with 0x
        assert!(address.starts_with("0x"));

        // Should be 42 characters (0x + 40 hex chars)
        assert_eq!(address.len(), 42);
    }

    #[test]
    fn test_ethereum_address_deterministic() {
        let bytes = [0x42u8; 32];
        let signer = Secp256k1Signer::from_bytes(bytes).expect("valid key");

        let address1 = signer.address(Chain::Ethereum).expect("valid address");
        let address2 = signer.address(Chain::Ethereum).expect("valid address");

        assert_eq!(address1, address2);
    }

    /// Test EIP-55 checksum with a known test vector.
    #[test]
    fn test_eip55_checksum_known_vector() {
        // Test vector from EIP-55 specification
        // Address: 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed
        let address_hex = "5aaeb6053f3e94c9b9a09f33669435e7ef1beaed";
        let mut address = [0u8; 20];
        hex::decode_to_slice(address_hex, &mut address).expect("valid hex");

        let checksummed = to_eip55_checksum(&address);

        assert_eq!(checksummed, "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
    }

    /// Test EIP-55 checksum with all-lowercase address.
    #[test]
    fn test_eip55_checksum_all_lowercase() {
        // fb6916095ca1df60bb79ce92ce3ea74c37c5d359
        let address_hex = "fb6916095ca1df60bb79ce92ce3ea74c37c5d359";
        let mut address = [0u8; 20];
        hex::decode_to_slice(address_hex, &mut address).expect("valid hex");

        let checksummed = to_eip55_checksum(&address);

        assert_eq!(checksummed, "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359");
    }

    /// Test EIP-55 checksum with another known vector.
    #[test]
    fn test_eip55_checksum_vector_2() {
        // dbf03b407c01e7cd3cbea99509d93f8dddc8c6fb
        let address_hex = "dbf03b407c01e7cd3cbea99509d93f8dddc8c6fb";
        let mut address = [0u8; 20];
        hex::decode_to_slice(address_hex, &mut address).expect("valid hex");

        let checksummed = to_eip55_checksum(&address);

        assert_eq!(checksummed, "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB");
    }

    /// Test with a real Ethereum address from a known private key.
    #[test]
    fn test_ethereum_address_known_private_key() {
        // This is a well-known test private key
        // Private key: 0xfad9c8855b740a0b7ed4c221dbad0f33a83a49cad6b3fe8d5817ac83d38b6a19
        let private_key_hex = "fad9c8855b740a0b7ed4c221dbad0f33a83a49cad6b3fe8d5817ac83d38b6a19";
        let mut private_key = [0u8; 32];
        hex::decode_to_slice(private_key_hex, &mut private_key).expect("valid hex");

        let signer = Secp256k1Signer::from_bytes(private_key).expect("valid key");
        let address = signer.address(Chain::Ethereum).expect("valid address");

        // The expected address (lowercase) is: 0x96216849c49358b10257cb55b28ea603c874b05e
        // We need to verify the EIP-55 checksummed version
        let expected_raw = "96216849c49358b10257cb55b28ea603c874b05e";
        let mut expected_bytes = [0u8; 20];
        hex::decode_to_slice(expected_raw, &mut expected_bytes).expect("valid hex");
        let expected_checksummed = to_eip55_checksum(&expected_bytes);

        assert_eq!(address, expected_checksummed);
    }

    // ------------------------------------------------------------------------
    // Unsupported Chain Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_bitcoin_address_format() {
        let signer = Secp256k1Signer::generate();

        let address = signer.address(Chain::Bitcoin).expect("valid address");

        // P2WPKH mainnet addresses start with bc1q
        assert!(
            address.starts_with("bc1q"),
            "Address should start with bc1q: {address}"
        );

        // P2WPKH addresses are 42 or 62 characters depending on format
        // bc1q (4) + 38 characters = 42 for standard P2WPKH
        assert_eq!(
            address.len(),
            42,
            "P2WPKH address should be 42 characters: {address}"
        );
    }

    #[test]
    fn test_bitcoin_address_deterministic() {
        let bytes = [0x42u8; 32];
        let signer = Secp256k1Signer::from_bytes(bytes).expect("valid key");

        let address1 = signer.address(Chain::Bitcoin).expect("valid address");
        let address2 = signer.address(Chain::Bitcoin).expect("valid address");

        assert_eq!(address1, address2);
    }

    #[test]
    fn test_bitcoin_address_known_private_key() {
        // Use a known test private key and verify the address
        let private_key_hex = "fad9c8855b740a0b7ed4c221dbad0f33a83a49cad6b3fe8d5817ac83d38b6a19";
        let mut private_key = [0u8; 32];
        hex::decode_to_slice(private_key_hex, &mut private_key).expect("valid hex");

        let signer = Secp256k1Signer::from_bytes(private_key).expect("valid key");
        let address = signer.address(Chain::Bitcoin).expect("valid address");

        // Verify it's a valid bech32 address
        assert!(address.starts_with("bc1q"));
        // The address should be deterministic - same key always produces same address
        let address2 = signer.address(Chain::Bitcoin).expect("valid address");
        assert_eq!(address, address2);
    }

    #[test]
    fn test_tron_address_not_implemented() {
        let signer = Secp256k1Signer::generate();

        let result = signer.address(Chain::Tron);

        assert!(result.is_err());
        match result {
            Err(SignError::SignatureFailed { context }) => {
                assert!(context.contains("Tron"));
            }
            _ => panic!("Expected SignatureFailed error"),
        }
    }

    #[test]
    fn test_ripple_address_not_implemented() {
        let signer = Secp256k1Signer::generate();

        let result = signer.address(Chain::Ripple);

        assert!(result.is_err());
        match result {
            Err(SignError::SignatureFailed { context }) => {
                assert!(context.contains("Ripple"));
            }
            _ => panic!("Expected SignatureFailed error"),
        }
    }

    #[test]
    fn test_solana_address_wrong_curve() {
        let signer = Secp256k1Signer::generate();

        let result = signer.address(Chain::Solana);

        assert!(result.is_err());
        match result {
            Err(SignError::WrongCurve { expected, actual }) => {
                assert_eq!(expected, "ed25519");
                assert_eq!(actual, "secp256k1");
            }
            _ => panic!("Expected WrongCurve error"),
        }
    }

    // ------------------------------------------------------------------------
    // Thread Safety Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_signer_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Secp256k1Signer>();
    }

    #[test]
    fn test_signer_trait_object_is_send_sync() {
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        assert_send_sync::<dyn Signer>();
    }

    // ------------------------------------------------------------------------
    // Debug Output Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_signer_debug_output() {
        let signer = Secp256k1Signer::generate();
        let debug_output = format!("{:?}", signer);

        // Should contain the struct name
        assert!(debug_output.contains("Secp256k1Signer"));
        // Should not expose the private key (inherits from KeyPair's Debug)
    }

    // ------------------------------------------------------------------------
    // Key Pair Access Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_key_pair_accessor() {
        let bytes = [0x42u8; 32];
        let signer = Secp256k1Signer::from_bytes(bytes).expect("valid key");

        let key_pair = signer.key_pair();

        // Should be able to access the underlying key pair
        assert_eq!(key_pair.public_key().compressed(), signer.public_key());
    }

    // ------------------------------------------------------------------------
    // EIP-55 Checksum Edge Cases
    // ------------------------------------------------------------------------

    #[test]
    fn test_eip55_checksum_all_digits_address() {
        // Address with only digits (no letters to case-transform)
        let address_hex = "1234567890123456789012345678901234567890";
        let mut address = [0u8; 20];
        hex::decode_to_slice(address_hex, &mut address).expect("valid hex");

        let checksummed = to_eip55_checksum(&address);

        // Should still be all lowercase digits with 0x prefix
        assert!(checksummed.starts_with("0x"));
        assert_eq!(checksummed.len(), 42);
        assert!(checksummed[2..].chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_eip55_checksum_boundary_nibbles() {
        // Test addresses that exercise boundary conditions in nibble extraction
        // High nibbles (even indices) and low nibbles (odd indices)
        let test_vectors = vec![
            // Address designed to test nibble extraction at different positions
            ("0000000000000000000000000000000000000000", 42),
            ("ffffffffffffffffffffffffffffffffffffffff", 42),
            ("abcdefabcdefabcdefabcdefabcdefabcdefabcd", 42),
        ];

        for (hex_addr, expected_len) in test_vectors {
            let mut address = [0u8; 20];
            hex::decode_to_slice(hex_addr, &mut address).expect("valid hex");

            let checksummed = to_eip55_checksum(&address);
            assert_eq!(checksummed.len(), expected_len);
            assert!(checksummed.starts_with("0x"));
        }
    }

    #[test]
    fn test_eip55_checksum_hash_byte_boundary() {
        // Test that we correctly handle hash byte extraction at i/2
        // This exercises the hash.get(i/2) logic
        for i in 0..20 {
            let mut address = [0u8; 20];
            address[i] = 0xAB; // Mix of letters to test case conversion

            let checksummed = to_eip55_checksum(&address);
            assert_eq!(checksummed.len(), 42);
            assert!(checksummed.starts_with("0x"));
        }
    }

    #[test]
    fn test_eip55_checksum_even_odd_indices() {
        // Specifically test even and odd character indices for nibble extraction
        let address_hex = "aabbccddeeff00112233445566778899aabbccdd";
        let mut address = [0u8; 20];
        hex::decode_to_slice(address_hex, &mut address).expect("valid hex");

        let checksummed = to_eip55_checksum(&address);

        // Verify format is correct
        assert_eq!(checksummed.len(), 42);
        assert!(checksummed.starts_with("0x"));

        // Verify all characters after 0x are valid hex
        assert!(checksummed[2..].chars().all(|c| c.is_ascii_hexdigit()));
    }

    // ------------------------------------------------------------------------
    // Signature Verification Roundtrip Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_sign_and_verify_with_keypair() {
        let bytes = [0x42u8; 32];
        let signer = Secp256k1Signer::from_bytes(bytes).expect("valid key");
        let hash = [0x42u8; 32];

        let signature = signer.sign(&hash).expect("signing should succeed");

        // Extract the signature without recovery ID for verification
        let sig_bytes: [u8; 64] = signature[..64].try_into().expect("64 bytes");
        let sig = crate::keypair::Secp256k1Signature::from_bytes_and_recovery_id(
            sig_bytes,
            signature[64],
        );

        // Verify using the key pair
        assert!(signer.key_pair().verify(&hash, &sig));
    }

    // ------------------------------------------------------------------------
    // Ed25519Signer Creation Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_ed25519_generate_creates_valid_signer() {
        let signer = Ed25519Signer::generate();

        // Public key should be 32 bytes
        assert_eq!(signer.public_key().len(), 32);

        // Curve type should be ed25519
        assert_eq!(signer.curve(), CurveType::Ed25519);
    }

    #[test]
    fn test_ed25519_generate_produces_unique_signers() {
        let signer1 = Ed25519Signer::generate();
        let signer2 = Ed25519Signer::generate();

        // Should generate different public keys
        assert_ne!(signer1.public_key(), signer2.public_key());
    }

    #[test]
    fn test_ed25519_from_bytes_success() {
        let bytes = [0x42u8; 32];
        let result = Ed25519Signer::from_bytes(bytes);
        assert!(result.is_ok());
    }

    #[test]
    fn test_ed25519_from_bytes_deterministic() {
        let bytes = [0x42u8; 32];

        let signer1 = Ed25519Signer::from_bytes(bytes).expect("valid key");
        let signer2 = Ed25519Signer::from_bytes(bytes).expect("valid key");

        assert_eq!(signer1.public_key(), signer2.public_key());
    }

    #[test]
    fn test_ed25519_new_from_keypair() {
        let key_pair = crate::keypair::Ed25519KeyPair::generate();
        let expected_pubkey = *key_pair.public_key().as_bytes();

        let signer = Ed25519Signer::new(key_pair);

        assert_eq!(signer.public_key(), &expected_pubkey);
    }

    // ------------------------------------------------------------------------
    // Ed25519 Signing Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_ed25519_sign_produces_64_bytes() {
        let signer = Ed25519Signer::generate();
        let hash = [0x42u8; 32];

        let signature = signer.sign(&hash).expect("signing should succeed");

        // Ed25519 signature should be 64 bytes
        assert_eq!(signature.len(), 64);
    }

    #[test]
    fn test_ed25519_different_hashes_produce_different_signatures() {
        let signer = Ed25519Signer::generate();
        let hash1 = [0x42u8; 32];
        let hash2 = [0x43u8; 32];

        let sig1 = signer.sign(&hash1).expect("signing should succeed");
        let sig2 = signer.sign(&hash2).expect("signing should succeed");

        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_ed25519_sign_is_deterministic() {
        // Ed25519 signatures are deterministic (no random k)
        let bytes = [0x42u8; 32];
        let signer = Ed25519Signer::from_bytes(bytes).expect("valid key");
        let hash = [0x42u8; 32];

        let sig1 = signer.sign(&hash).expect("signing should succeed");
        let sig2 = signer.sign(&hash).expect("signing should succeed");

        assert_eq!(sig1, sig2, "ed25519 signatures should be deterministic");
    }

    // ------------------------------------------------------------------------
    // Ed25519 Solana Address Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_ed25519_solana_address_format() {
        let signer = Ed25519Signer::generate();

        let address = signer.address(Chain::Solana).expect("valid address");

        // Solana addresses are base58 encoded, typically 32-44 characters
        assert!(
            address.len() >= 32 && address.len() <= 44,
            "Solana address should be 32-44 characters: {address}"
        );
    }

    #[test]
    fn test_ed25519_solana_address_deterministic() {
        let bytes = [0x42u8; 32];
        let signer = Ed25519Signer::from_bytes(bytes).expect("valid key");

        let address1 = signer.address(Chain::Solana).expect("valid address");
        let address2 = signer.address(Chain::Solana).expect("valid address");

        assert_eq!(address1, address2);
    }

    // ------------------------------------------------------------------------
    // Ed25519 Wrong Curve Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_ed25519_ethereum_address_wrong_curve() {
        let signer = Ed25519Signer::generate();

        let result = signer.address(Chain::Ethereum);

        assert!(result.is_err());
        match result {
            Err(SignError::WrongCurve { expected, actual }) => {
                assert_eq!(expected, "secp256k1");
                assert_eq!(actual, "ed25519");
            }
            _ => panic!("Expected WrongCurve error"),
        }
    }

    #[test]
    fn test_ed25519_bitcoin_address_wrong_curve() {
        let signer = Ed25519Signer::generate();

        let result = signer.address(Chain::Bitcoin);

        assert!(result.is_err());
        match result {
            Err(SignError::WrongCurve { expected, actual }) => {
                assert_eq!(expected, "secp256k1");
                assert_eq!(actual, "ed25519");
            }
            _ => panic!("Expected WrongCurve error"),
        }
    }

    #[test]
    fn test_ed25519_tron_address_wrong_curve() {
        let signer = Ed25519Signer::generate();

        let result = signer.address(Chain::Tron);

        assert!(result.is_err());
        match result {
            Err(SignError::WrongCurve { expected, actual }) => {
                assert_eq!(expected, "secp256k1");
                assert_eq!(actual, "ed25519");
            }
            _ => panic!("Expected WrongCurve error"),
        }
    }

    #[test]
    fn test_ed25519_ripple_address_wrong_curve() {
        let signer = Ed25519Signer::generate();

        let result = signer.address(Chain::Ripple);

        assert!(result.is_err());
        match result {
            Err(SignError::WrongCurve { expected, actual }) => {
                assert_eq!(expected, "secp256k1");
                assert_eq!(actual, "ed25519");
            }
            _ => panic!("Expected WrongCurve error"),
        }
    }

    // ------------------------------------------------------------------------
    // Ed25519 Thread Safety Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_ed25519_signer_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Ed25519Signer>();
    }

    // ------------------------------------------------------------------------
    // Ed25519 Debug and Key Pair Access Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_ed25519_signer_debug_output() {
        let signer = Ed25519Signer::generate();
        let debug_output = format!("{:?}", signer);

        // Should contain the struct name
        assert!(debug_output.contains("Ed25519Signer"));
    }

    #[test]
    fn test_ed25519_key_pair_accessor() {
        let bytes = [0x42u8; 32];
        let signer = Ed25519Signer::from_bytes(bytes).expect("valid key");

        let key_pair = signer.key_pair();

        // Should be able to access the underlying key pair
        assert_eq!(key_pair.public_key().as_bytes(), signer.public_key());
    }

    // ------------------------------------------------------------------------
    // Ed25519 Sign and Verify Roundtrip
    // ------------------------------------------------------------------------

    #[test]
    fn test_ed25519_sign_and_verify_with_keypair() {
        let bytes = [0x42u8; 32];
        let signer = Ed25519Signer::from_bytes(bytes).expect("valid key");
        let hash = [0x42u8; 32];

        let signature = signer.sign(&hash).expect("signing should succeed");

        // Convert signature bytes to Ed25519Signature
        let sig_bytes: [u8; 64] = signature.try_into().expect("64 bytes");
        let sig = crate::keypair::Ed25519Signature::from_bytes(sig_bytes);

        // Verify using the key pair
        assert!(signer.key_pair().verify(&hash, &sig));
    }
}

#[cfg(test)]
mod proptest_tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::indexing_slicing)]

    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn test_sign_always_produces_65_bytes(hash in any::<[u8; 32]>()) {
            let signer = Secp256k1Signer::generate();
            let signature = signer.sign(&hash).expect("signing should succeed");
            prop_assert_eq!(signature.len(), 65);
        }

        #[test]
        fn test_recovery_id_always_valid(hash in any::<[u8; 32]>()) {
            let signer = Secp256k1Signer::generate();
            let signature = signer.sign(&hash).expect("signing should succeed");
            let recovery_id = signature[64];
            prop_assert!(recovery_id <= 1);
        }

        #[test]
        fn test_ethereum_address_always_valid_format(seed in any::<[u8; 32]>()) {
            // Skip invalid seeds
            if seed == [0u8; 32] {
                return Ok(());
            }

            if let Ok(signer) = Secp256k1Signer::from_bytes(seed) {
                let address = signer.address(Chain::Ethereum).expect("valid address");

                // Should start with 0x
                prop_assert!(address.starts_with("0x"));

                // Should be 42 characters
                prop_assert_eq!(address.len(), 42);

                // Remaining characters should be valid hex
                prop_assert!(address[2..].chars().all(|c| c.is_ascii_hexdigit()));
            }
        }
    }
}
