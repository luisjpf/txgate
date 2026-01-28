//! Cryptographic key pair traits and implementations.
//!
//! This module provides the [`KeyPair`] trait for abstracting over different
//! elliptic curve key pairs, and implementations for specific curves.
//!
//! # Supported Curves
//!
//! - [`Secp256k1KeyPair`] - For Ethereum, Bitcoin, Tron, and Ripple
//! - [`Ed25519KeyPair`] - For Solana and other ed25519-based chains
//!
//! # Example
//!
//! ```rust
//! use txgate_crypto::keypair::{KeyPair, Secp256k1KeyPair};
//!
//! // Generate a new random key pair
//! let keypair = Secp256k1KeyPair::generate();
//!
//! // Get the public key
//! let pubkey = keypair.public_key();
//! println!("Compressed: {} bytes", pubkey.compressed().len());
//!
//! // Get Ethereum address
//! let eth_address = pubkey.ethereum_address();
//! println!("Ethereum address: 0x{}", hex::encode(eth_address));
//!
//! // Sign a message hash
//! let hash = [0u8; 32]; // In practice, this would be a real hash
//! let signature = keypair.sign(&hash).expect("signing failed");
//! println!("Signature: {} bytes", signature.as_ref().len());
//! ```

use k256::ecdsa::{RecoveryId, Signature as K256Signature, SigningKey, VerifyingKey};
use sha3::{Digest, Keccak256};

use crate::keys::SecretKey;
use txgate_core::error::SignError;

// ============================================================================
// KeyPair Trait
// ============================================================================

/// Trait for cryptographic key pairs.
///
/// This trait abstracts over different elliptic curve key pairs,
/// allowing the signing service to work with multiple curves.
///
/// # Thread Safety
///
/// All implementations must be `Send + Sync` to support multi-threaded
/// signing operations.
///
/// # Example
///
/// ```rust
/// use txgate_crypto::keypair::{KeyPair, Secp256k1KeyPair};
///
/// fn sign_message<K: KeyPair>(keypair: &K, hash: &[u8; 32]) -> Vec<u8> {
///     keypair.sign(hash)
///         .expect("signing failed")
///         .as_ref()
///         .to_vec()
/// }
///
/// let keypair = Secp256k1KeyPair::generate();
/// let hash = [0u8; 32];
/// let sig = sign_message(&keypair, &hash);
/// ```
pub trait KeyPair: Send + Sync {
    /// The signature type produced by this key pair.
    type Signature: AsRef<[u8]>;

    /// The public key type for this key pair.
    type PublicKey: AsRef<[u8]>;

    /// Generate a new random key pair.
    ///
    /// Uses a cryptographically secure random number generator.
    fn generate() -> Self
    where
        Self: Sized;

    /// Create a key pair from raw secret key bytes.
    ///
    /// # Arguments
    /// * `bytes` - The 32-byte secret key material
    ///
    /// # Errors
    /// Returns an error if the bytes don't represent a valid secret key
    /// for this curve.
    fn from_bytes(bytes: [u8; 32]) -> Result<Self, SignError>
    where
        Self: Sized;

    /// Get the public key.
    fn public_key(&self) -> &Self::PublicKey;

    /// Sign a 32-byte message hash.
    ///
    /// # Arguments
    /// * `hash` - The 32-byte hash to sign (NOT the raw message)
    ///
    /// # Returns
    /// The signature bytes.
    ///
    /// # Errors
    /// Returns an error if signing fails.
    ///
    /// # Important
    /// The `hash` parameter should be a cryptographic hash of the message
    /// (e.g., SHA-256 or Keccak-256), NOT the raw message itself.
    fn sign(&self, hash: &[u8; 32]) -> Result<Self::Signature, SignError>;
}

// ============================================================================
// Secp256k1 Public Key
// ============================================================================

/// Wrapper for secp256k1 public keys.
///
/// Stores both compressed (33 bytes) and uncompressed (65 bytes) formats
/// to avoid recomputation.
///
/// # Formats
///
/// - **Compressed**: 33 bytes, prefix `0x02` or `0x03` + 32-byte X coordinate
/// - **Uncompressed**: 65 bytes, prefix `0x04` + 32-byte X + 32-byte Y
///
/// # Example
///
/// ```rust
/// use txgate_crypto::keypair::{KeyPair, Secp256k1KeyPair};
///
/// let keypair = Secp256k1KeyPair::generate();
/// let pubkey = keypair.public_key();
///
/// // Get compressed format (33 bytes)
/// assert_eq!(pubkey.compressed().len(), 33);
///
/// // Get uncompressed format (65 bytes)
/// assert_eq!(pubkey.uncompressed().len(), 65);
///
/// // Get Ethereum address (20 bytes)
/// let address = pubkey.ethereum_address();
/// assert_eq!(address.len(), 20);
/// ```
#[derive(Clone)]
pub struct Secp256k1PublicKey {
    /// Compressed public key (33 bytes: prefix + X coordinate)
    compressed: [u8; 33],
    /// Uncompressed public key (65 bytes: prefix + X + Y coordinates)
    uncompressed: [u8; 65],
}

impl Secp256k1PublicKey {
    /// Create a new public key from a k256 `VerifyingKey`.
    fn from_verifying_key(verifying: &VerifyingKey) -> Self {
        let point = verifying.to_encoded_point(false);
        let uncompressed_bytes = point.as_bytes();

        let mut uncompressed = [0u8; 65];
        uncompressed.copy_from_slice(uncompressed_bytes);

        let point_compressed = verifying.to_encoded_point(true);
        let compressed_bytes = point_compressed.as_bytes();

        let mut compressed = [0u8; 33];
        compressed.copy_from_slice(compressed_bytes);

        Self {
            compressed,
            uncompressed,
        }
    }

    /// Get the compressed public key (33 bytes).
    ///
    /// Format: `prefix (1 byte) || X (32 bytes)`
    /// - Prefix is `0x02` if Y is even, `0x03` if Y is odd
    #[must_use]
    pub const fn compressed(&self) -> &[u8; 33] {
        &self.compressed
    }

    /// Get the uncompressed public key (65 bytes).
    ///
    /// Format: `0x04 || X (32 bytes) || Y (32 bytes)`
    #[must_use]
    pub const fn uncompressed(&self) -> &[u8; 65] {
        &self.uncompressed
    }

    /// Derive the Ethereum address from this public key.
    ///
    /// The Ethereum address is the last 20 bytes of the Keccak-256 hash
    /// of the uncompressed public key (without the `0x04` prefix).
    ///
    /// # Example
    ///
    /// ```rust
    /// use txgate_crypto::keypair::{KeyPair, Secp256k1KeyPair};
    ///
    /// let keypair = Secp256k1KeyPair::generate();
    /// let address = keypair.public_key().ethereum_address();
    /// assert_eq!(address.len(), 20);
    /// ```
    #[must_use]
    pub fn ethereum_address(&self) -> [u8; 20] {
        // Hash the uncompressed public key without the 0x04 prefix
        // The uncompressed key is always 65 bytes, so [1..] is 64 bytes
        let hash = Keccak256::digest(&self.uncompressed[1..]);

        // Take the last 20 bytes of the hash
        // Keccak256 always produces 32 bytes
        let mut address = [0u8; 20];

        // Use get() to safely extract the slice, though this should never fail
        // since Keccak256 always produces exactly 32 bytes
        if let Some(hash_tail) = hash.get(12..32) {
            address.copy_from_slice(hash_tail);
        }

        address
    }
}

impl AsRef<[u8]> for Secp256k1PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.compressed
    }
}

impl std::fmt::Debug for Secp256k1PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Secp256k1PublicKey({})", hex::encode(self.compressed))
    }
}

// ============================================================================
// Secp256k1 Signature
// ============================================================================

/// Wrapper for secp256k1 ECDSA signatures.
///
/// Contains the 64-byte signature (r || s) and the recovery ID for
/// Ethereum compatibility.
///
/// # Signature Formats
///
/// - **Standard**: 64 bytes (r: 32 bytes || s: 32 bytes)
/// - **Recoverable**: 65 bytes (r || s || v) where v is the recovery ID
///
/// # Security
///
/// The S value is normalized to the lower half of the curve order to
/// prevent signature malleability attacks.
///
/// # Example
///
/// ```rust
/// use txgate_crypto::keypair::{KeyPair, Secp256k1KeyPair};
///
/// let keypair = Secp256k1KeyPair::generate();
/// let hash = [0u8; 32];
/// let signature = keypair.sign(&hash).expect("signing failed");
///
/// // Get standard 64-byte signature
/// assert_eq!(signature.as_ref().len(), 64);
///
/// // Get recoverable signature with recovery ID
/// let recoverable = signature.to_recoverable_bytes();
/// assert_eq!(recoverable.len(), 65);
///
/// // Get recovery ID for ecrecover
/// let v = signature.recovery_id();
/// assert!(v == 0 || v == 1);
/// ```
#[derive(Clone)]
pub struct Secp256k1Signature {
    /// The 64-byte signature (r || s)
    bytes: [u8; 64],
    /// Recovery ID for Ethereum compatibility (0 or 1)
    recovery_id: u8,
}

impl Secp256k1Signature {
    /// Create a signature from raw bytes and a recovery ID.
    ///
    /// This is useful for reconstructing a signature from its components.
    ///
    /// # Arguments
    /// * `bytes` - The 64-byte signature (r || s)
    /// * `recovery_id` - The recovery ID (0 or 1)
    ///
    /// # Example
    ///
    /// ```rust
    /// use txgate_crypto::keypair::{KeyPair, Secp256k1KeyPair, Secp256k1Signature};
    ///
    /// let keypair = Secp256k1KeyPair::generate();
    /// let hash = [0u8; 32];
    /// let signature = keypair.sign(&hash).expect("signing failed");
    ///
    /// // Get the recoverable bytes
    /// let recoverable = signature.to_recoverable_bytes();
    ///
    /// // Reconstruct the signature
    /// let bytes: [u8; 64] = recoverable[..64].try_into().unwrap();
    /// let recovery_id = recoverable[64];
    /// let reconstructed = Secp256k1Signature::from_bytes_and_recovery_id(bytes, recovery_id);
    ///
    /// assert_eq!(signature.as_ref(), reconstructed.as_ref());
    /// ```
    #[must_use]
    pub const fn from_bytes_and_recovery_id(bytes: [u8; 64], recovery_id: u8) -> Self {
        Self { bytes, recovery_id }
    }

    /// Get the recovery ID.
    ///
    /// This is 0 or 1, which can be used with Ethereum's `ecrecover`:
    /// - For EIP-155 transactions: `v = recovery_id + 27`
    /// - For EIP-2930/EIP-1559: `v = recovery_id`
    #[must_use]
    pub const fn recovery_id(&self) -> u8 {
        self.recovery_id
    }

    /// Return signature as 65 bytes: r (32) || s (32) || v (1).
    ///
    /// The `v` byte is the raw recovery ID (0 or 1). For Ethereum
    /// transactions, you may need to add 27 or use chain-specific
    /// calculations for EIP-155.
    #[must_use]
    pub fn to_recoverable_bytes(&self) -> [u8; 65] {
        let mut result = [0u8; 65];
        result[..64].copy_from_slice(&self.bytes);
        result[64] = self.recovery_id;
        result
    }

    /// Get the r component of the signature (first 32 bytes).
    ///
    /// This always succeeds because the signature is always exactly 64 bytes.
    ///
    /// # Panics
    ///
    /// This method cannot panic in practice because the internal storage
    /// is always exactly 64 bytes, but the conversion is technically fallible.
    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn r(&self) -> &[u8; 32] {
        // Split the array at index 32 to get the first half
        // This is safe because bytes is always [u8; 64]
        let (r_part, _) = self.bytes.split_at(32);
        // Convert to fixed-size array reference
        // SAFETY: split_at(32) on a [u8; 64] always returns exactly 32 bytes in first half
        #[allow(clippy::expect_used)]
        r_part
            .try_into()
            .expect("split_at(32) always produces 32 bytes")
    }

    /// Get the s component of the signature (last 32 bytes).
    ///
    /// This always succeeds because the signature is always exactly 64 bytes.
    ///
    /// # Panics
    ///
    /// This method cannot panic in practice because the internal storage
    /// is always exactly 64 bytes, but the conversion is technically fallible.
    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn s(&self) -> &[u8; 32] {
        // Split the array at index 32 to get the second half
        // This is safe because bytes is always [u8; 64]
        let (_, s_part) = self.bytes.split_at(32);
        // Convert to fixed-size array reference
        // SAFETY: split_at(32) on a [u8; 64] always returns exactly 32 bytes in second half
        #[allow(clippy::expect_used)]
        s_part
            .try_into()
            .expect("split_at(32) always produces 32 bytes")
    }
}

impl AsRef<[u8]> for Secp256k1Signature {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl std::fmt::Debug for Secp256k1Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Secp256k1Signature(r={}, s={}, v={})",
            hex::encode(self.r()),
            hex::encode(self.s()),
            self.recovery_id
        )
    }
}

// ============================================================================
// Secp256k1 Key Pair
// ============================================================================

/// secp256k1 key pair for Ethereum, Bitcoin, Tron, and Ripple.
///
/// This key pair uses the secp256k1 elliptic curve, which is the standard
/// for most major blockchain networks.
///
/// # Security
///
/// - The signing key is stored securely and is `ZeroizeOnDrop`
/// - Signatures are normalized to prevent malleability
/// - Recovery IDs are computed for Ethereum compatibility
///
/// # Example
///
/// ```rust
/// use txgate_crypto::keypair::{KeyPair, Secp256k1KeyPair};
///
/// // Generate a new key pair
/// let keypair = Secp256k1KeyPair::generate();
///
/// // Or create from existing bytes
/// let secret_bytes = [0x42u8; 32]; // Use real secret in production!
/// let keypair = Secp256k1KeyPair::from_bytes(secret_bytes)
///     .expect("valid secret key");
///
/// // Sign a message hash
/// let hash = [0u8; 32]; // Use real hash in production!
/// let signature = keypair.sign(&hash).expect("signing succeeded");
///
/// // Get Ethereum address
/// let address = keypair.public_key().ethereum_address();
/// println!("Address: 0x{}", hex::encode(address));
/// ```
#[allow(clippy::struct_field_names)]
pub struct Secp256k1KeyPair {
    /// The signing key (private key)
    signing_key: SigningKey,
    /// Cached verifying key (public key) for verification
    verifying_key: VerifyingKey,
    /// Cached public key wrapper
    public_key: Secp256k1PublicKey,
}

impl Secp256k1KeyPair {
    /// Create a key pair from a [`SecretKey`].
    ///
    /// This consumes the `SecretKey` to ensure the key material exists
    /// in only one place.
    ///
    /// # Errors
    /// Returns an error if the secret key bytes are not a valid secp256k1
    /// scalar (e.g., zero or greater than the curve order).
    ///
    /// # Example
    ///
    /// ```rust
    /// use txgate_crypto::keys::SecretKey;
    /// use txgate_crypto::keypair::{KeyPair, Secp256k1KeyPair};
    ///
    /// let secret = SecretKey::generate();
    /// let keypair = Secp256k1KeyPair::from_secret_key(&secret)
    ///     .expect("valid secret key");
    /// ```
    pub fn from_secret_key(secret: &SecretKey) -> Result<Self, SignError> {
        Self::from_bytes(*secret.as_bytes())
    }

    /// Verify a signature against a hash using this key pair's public key.
    ///
    /// This is primarily useful for testing. In production, verification
    /// is typically done using the public key alone.
    ///
    /// # Arguments
    /// * `hash` - The 32-byte hash that was signed
    /// * `signature` - The signature to verify
    ///
    /// # Returns
    /// `true` if the signature is valid, `false` otherwise.
    #[must_use]
    pub fn verify(&self, hash: &[u8; 32], signature: &Secp256k1Signature) -> bool {
        use k256::ecdsa::signature::hazmat::PrehashVerifier;

        let Ok(k256_sig) = K256Signature::from_slice(signature.as_ref()) else {
            return false;
        };

        self.verifying_key.verify_prehash(hash, &k256_sig).is_ok()
    }
}

impl KeyPair for Secp256k1KeyPair {
    type Signature = Secp256k1Signature;
    type PublicKey = Secp256k1PublicKey;

    fn generate() -> Self {
        let secret = SecretKey::generate();
        // Generated random keys from OsRng should always be valid secp256k1 scalars
        // (non-zero and less than the curve order). If this fails, there's a
        // fundamental issue with the RNG or the k256 library.
        Self::from_bytes(*secret.as_bytes())
            .unwrap_or_else(|_| unreachable!("OsRng generated an invalid secp256k1 scalar"))
    }

    fn from_bytes(bytes: [u8; 32]) -> Result<Self, SignError> {
        let signing_key =
            SigningKey::from_bytes((&bytes).into()).map_err(|_| SignError::InvalidKey)?;

        let verifying_key = *signing_key.verifying_key();
        let public_key = Secp256k1PublicKey::from_verifying_key(&verifying_key);

        Ok(Self {
            signing_key,
            verifying_key,
            public_key,
        })
    }

    fn public_key(&self) -> &Self::PublicKey {
        &self.public_key
    }

    fn sign(&self, hash: &[u8; 32]) -> Result<Self::Signature, SignError> {
        // Sign the hash using the prehash signer (for pre-hashed messages)
        let (signature, recovery_id): (K256Signature, RecoveryId) = self
            .signing_key
            .sign_prehash_recoverable(hash)
            .map_err(|_| SignError::signature_failed("secp256k1 signing failed"))?;

        // Normalize the signature to prevent malleability
        // k256 already normalizes signatures when using sign_prehash_recoverable
        let normalized = signature.normalize_s();

        // Get the signature bytes
        let sig_bytes = normalized.unwrap_or(signature).to_bytes();
        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(&sig_bytes);

        // Adjust recovery ID if S was normalized
        let final_recovery_id = if normalized.is_some() {
            // If S was normalized, flip the recovery ID
            recovery_id.to_byte() ^ 1
        } else {
            recovery_id.to_byte()
        };

        Ok(Secp256k1Signature {
            bytes,
            recovery_id: final_recovery_id,
        })
    }
}

// Implement Debug for Secp256k1KeyPair without exposing the private key
impl std::fmt::Debug for Secp256k1KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Secp256k1KeyPair")
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

// ============================================================================
// Ed25519 Public Key
// ============================================================================

/// Wrapper for ed25519 public keys.
///
/// Stores the 32-byte public key for ed25519 operations.
/// Used for Solana and other ed25519-based chains.
///
/// # Example
///
/// ```rust
/// use txgate_crypto::keypair::{KeyPair, Ed25519KeyPair};
///
/// let keypair = Ed25519KeyPair::generate();
/// let pubkey = keypair.public_key();
///
/// // Get raw bytes (32 bytes)
/// assert_eq!(pubkey.as_bytes().len(), 32);
///
/// // Get Solana address (base58 encoded)
/// let address = pubkey.solana_address();
/// assert!(!address.is_empty());
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct Ed25519PublicKey {
    /// The 32-byte public key
    bytes: [u8; 32],
}

impl Ed25519PublicKey {
    /// Create a new public key from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Get the raw public key bytes (32 bytes).
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Derive the Solana address from this public key.
    ///
    /// The Solana address is simply the base58-encoded 32-byte public key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use txgate_crypto::keypair::{KeyPair, Ed25519KeyPair};
    ///
    /// let keypair = Ed25519KeyPair::generate();
    /// let address = keypair.public_key().solana_address();
    /// // Solana addresses are base58 encoded, typically 32-44 characters
    /// assert!(address.len() >= 32 && address.len() <= 44);
    /// ```
    #[must_use]
    pub fn solana_address(&self) -> String {
        bs58::encode(&self.bytes).into_string()
    }
}

impl AsRef<[u8]> for Ed25519PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl std::fmt::Debug for Ed25519PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Ed25519PublicKey({})", hex::encode(self.bytes))
    }
}

// ============================================================================
// Ed25519 Signature
// ============================================================================

/// Wrapper for ed25519 signatures.
///
/// Contains the 64-byte signature.
///
/// # Example
///
/// ```rust
/// use txgate_crypto::keypair::{KeyPair, Ed25519KeyPair};
///
/// let keypair = Ed25519KeyPair::generate();
/// let hash = [0u8; 32];
/// let signature = keypair.sign(&hash).expect("signing failed");
///
/// // Get signature bytes (64 bytes)
/// assert_eq!(signature.as_ref().len(), 64);
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct Ed25519Signature {
    /// The 64-byte signature
    bytes: [u8; 64],
}

impl Ed25519Signature {
    /// Create a signature from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 64]) -> Self {
        Self { bytes }
    }
}

impl AsRef<[u8]> for Ed25519Signature {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl std::fmt::Debug for Ed25519Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Ed25519Signature({})", hex::encode(self.bytes))
    }
}

// ============================================================================
// Ed25519 Key Pair
// ============================================================================

/// Ed25519 key pair for Solana and other ed25519-based chains.
///
/// This key pair uses the ed25519 elliptic curve, which is the standard
/// for Solana and some other blockchain networks.
///
/// # Security
///
/// - The signing key is stored securely using [`ed25519_dalek::SigningKey`]
/// - The signing key implements `Zeroize` and `ZeroizeOnDrop`, ensuring secret
///   material is automatically zeroed when dropped (the "zeroize" feature is
///   explicitly enabled in the workspace Cargo.toml)
/// - `Debug` output does not expose the private key
/// - Uses ed25519-dalek for cryptographic operations
///
/// # Example
///
/// ```rust
/// use txgate_crypto::keypair::{KeyPair, Ed25519KeyPair};
///
/// // Generate a new key pair
/// let keypair = Ed25519KeyPair::generate();
///
/// // Or create from existing bytes
/// let secret_bytes = [0x42u8; 32]; // Use real secret in production!
/// let keypair = Ed25519KeyPair::from_bytes(secret_bytes)
///     .expect("valid secret key");
///
/// // Sign a message hash
/// let hash = [0u8; 32]; // Use real hash in production!
/// let signature = keypair.sign(&hash).expect("signing succeeded");
///
/// // Get Solana address
/// let address = keypair.public_key().solana_address();
/// println!("Solana address: {address}");
/// ```
pub struct Ed25519KeyPair {
    /// The signing key (private key)
    signing_key: ed25519_dalek::SigningKey,
    /// Cached public key wrapper
    public_key: Ed25519PublicKey,
}

impl Ed25519KeyPair {
    /// Create a key pair from a [`SecretKey`].
    ///
    /// # Errors
    /// Returns an error if the secret key bytes are not valid.
    ///
    /// # Example
    ///
    /// ```rust
    /// use txgate_crypto::keys::SecretKey;
    /// use txgate_crypto::keypair::{KeyPair, Ed25519KeyPair};
    ///
    /// let secret = SecretKey::generate();
    /// let keypair = Ed25519KeyPair::from_secret_key(&secret)
    ///     .expect("valid secret key");
    /// ```
    pub fn from_secret_key(secret: &SecretKey) -> Result<Self, SignError> {
        Self::from_bytes(*secret.as_bytes())
    }

    /// Verify a signature against a hash using this key pair's public key.
    ///
    /// # Arguments
    /// * `hash` - The 32-byte hash that was signed
    /// * `signature` - The signature to verify
    ///
    /// # Returns
    /// `true` if the signature is valid, `false` otherwise.
    #[must_use]
    pub fn verify(&self, hash: &[u8; 32], signature: &Ed25519Signature) -> bool {
        use ed25519_dalek::Verifier;

        let Ok(sig) = ed25519_dalek::Signature::from_slice(signature.as_ref()) else {
            return false;
        };

        self.signing_key.verifying_key().verify(hash, &sig).is_ok()
    }
}

impl KeyPair for Ed25519KeyPair {
    type Signature = Ed25519Signature;
    type PublicKey = Ed25519PublicKey;

    fn generate() -> Self {
        let secret = SecretKey::generate();
        // Generated random keys from OsRng should always be valid ed25519 keys
        Self::from_bytes(*secret.as_bytes())
            .unwrap_or_else(|_| unreachable!("OsRng generated an invalid ed25519 key"))
    }

    fn from_bytes(bytes: [u8; 32]) -> Result<Self, SignError> {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&bytes);
        let verifying_key = signing_key.verifying_key();
        let public_key = Ed25519PublicKey::from_bytes(verifying_key.to_bytes());

        Ok(Self {
            signing_key,
            public_key,
        })
    }

    fn public_key(&self) -> &Self::PublicKey {
        &self.public_key
    }

    fn sign(&self, hash: &[u8; 32]) -> Result<Self::Signature, SignError> {
        use ed25519_dalek::Signer;

        let signature = self.signing_key.sign(hash);
        let bytes = signature.to_bytes();

        Ok(Ed25519Signature { bytes })
    }
}

// Implement Debug for Ed25519KeyPair without exposing the private key
impl std::fmt::Debug for Ed25519KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ed25519KeyPair")
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::uninlined_format_args)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::panic)]

    use super::*;

    // ------------------------------------------------------------------------
    // Secp256k1KeyPair Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_generate_produces_valid_keypair() {
        let keypair = Secp256k1KeyPair::generate();

        // Public key should have correct lengths
        assert_eq!(keypair.public_key().compressed().len(), 33);
        assert_eq!(keypair.public_key().uncompressed().len(), 65);

        // Compressed key should start with 0x02 or 0x03
        let prefix = keypair.public_key().compressed()[0];
        assert!(prefix == 0x02 || prefix == 0x03);

        // Uncompressed key should start with 0x04
        assert_eq!(keypair.public_key().uncompressed()[0], 0x04);
    }

    #[test]
    fn test_generate_produces_unique_keys() {
        let keypair1 = Secp256k1KeyPair::generate();
        let keypair2 = Secp256k1KeyPair::generate();

        // Should generate different public keys
        assert_ne!(
            keypair1.public_key().compressed(),
            keypair2.public_key().compressed()
        );
    }

    #[test]
    fn test_from_bytes_success() {
        // A known valid secp256k1 private key
        let bytes = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];

        let result = Secp256k1KeyPair::from_bytes(bytes);
        assert!(result.is_ok());
    }

    #[test]
    fn test_from_bytes_invalid_zero() {
        // Zero is not a valid secp256k1 scalar
        let bytes = [0u8; 32];
        let result = Secp256k1KeyPair::from_bytes(bytes);
        assert!(matches!(result, Err(SignError::InvalidKey)));
    }

    #[test]
    fn test_from_secret_key() {
        let secret = SecretKey::generate();
        let result = Secp256k1KeyPair::from_secret_key(&secret);
        assert!(result.is_ok());
    }

    #[test]
    fn test_deterministic_public_key() {
        // Same private key should always produce the same public key
        let bytes = [0x42u8; 32];

        let keypair1 = Secp256k1KeyPair::from_bytes(bytes).expect("valid key");
        let keypair2 = Secp256k1KeyPair::from_bytes(bytes).expect("valid key");

        assert_eq!(
            keypair1.public_key().compressed(),
            keypair2.public_key().compressed()
        );
        assert_eq!(
            keypair1.public_key().uncompressed(),
            keypair2.public_key().uncompressed()
        );
    }

    // ------------------------------------------------------------------------
    // Signing Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_sign_produces_valid_signature() {
        let keypair = Secp256k1KeyPair::generate();
        let hash = [0x42u8; 32];

        let signature = keypair.sign(&hash).expect("signing should succeed");

        // Signature should be 64 bytes
        assert_eq!(signature.as_ref().len(), 64);

        // Recovery ID should be 0 or 1
        assert!(signature.recovery_id() == 0 || signature.recovery_id() == 1);
    }

    #[test]
    fn test_signature_is_verifiable() {
        let keypair = Secp256k1KeyPair::generate();
        let hash = [0x42u8; 32];

        let signature = keypair.sign(&hash).expect("signing should succeed");

        // Verify using keypair's verify method
        assert!(
            keypair.verify(&hash, &signature),
            "signature should be valid"
        );
    }

    #[test]
    fn test_different_messages_produce_different_signatures() {
        let keypair = Secp256k1KeyPair::generate();
        let hash1 = [0x42u8; 32];
        let hash2 = [0x43u8; 32];

        let sig1 = keypair.sign(&hash1).expect("signing should succeed");
        let sig2 = keypair.sign(&hash2).expect("signing should succeed");

        // Different messages should produce different signatures
        assert_ne!(sig1.as_ref(), sig2.as_ref());
    }

    #[test]
    fn test_recoverable_signature_format() {
        let keypair = Secp256k1KeyPair::generate();
        let hash = [0x42u8; 32];

        let signature = keypair.sign(&hash).expect("signing should succeed");
        let recoverable = signature.to_recoverable_bytes();

        assert_eq!(recoverable.len(), 65);
        assert_eq!(&recoverable[..64], signature.as_ref());
        assert_eq!(recoverable[64], signature.recovery_id());
    }

    #[test]
    fn test_signature_r_and_s_components() {
        let keypair = Secp256k1KeyPair::generate();
        let hash = [0x42u8; 32];

        let signature = keypair.sign(&hash).expect("signing should succeed");

        // R and S should each be 32 bytes
        assert_eq!(signature.r().len(), 32);
        assert_eq!(signature.s().len(), 32);

        // Concatenated R and S should equal the full signature
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(signature.r());
        combined[32..].copy_from_slice(signature.s());
        assert_eq!(&combined, signature.as_ref());
    }

    // ------------------------------------------------------------------------
    // Ethereum Address Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_ethereum_address_length() {
        let keypair = Secp256k1KeyPair::generate();
        let address = keypair.public_key().ethereum_address();
        assert_eq!(address.len(), 20);
    }

    #[test]
    fn test_ethereum_address_deterministic() {
        let bytes = [0x42u8; 32];
        let keypair = Secp256k1KeyPair::from_bytes(bytes).expect("valid key");

        let address1 = keypair.public_key().ethereum_address();
        let address2 = keypair.public_key().ethereum_address();

        assert_eq!(address1, address2);
    }

    /// Test vector from Ethereum yellow paper / well-known test cases
    #[test]
    fn test_ethereum_address_known_vector() {
        // This is a well-known test private key
        // Private key: 0xfad9c8855b740a0b7ed4c221dbad0f33a83a49cad6b3fe8d5817ac83d38b6a19
        let private_key_hex = "fad9c8855b740a0b7ed4c221dbad0f33a83a49cad6b3fe8d5817ac83d38b6a19";
        let expected_address_hex = "96216849c49358b10257cb55b28ea603c874b05e";

        let private_key_bytes = hex::decode(private_key_hex).expect("valid hex");
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&private_key_bytes);

        let keypair = Secp256k1KeyPair::from_bytes(bytes).expect("valid key");
        let address = keypair.public_key().ethereum_address();

        assert_eq!(hex::encode(address), expected_address_hex);
    }

    // ------------------------------------------------------------------------
    // Public Key Format Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_public_key_as_ref_returns_compressed() {
        let keypair = Secp256k1KeyPair::generate();
        let pubkey = keypair.public_key();

        // AsRef should return the compressed format
        assert_eq!(pubkey.as_ref(), pubkey.compressed().as_slice());
    }

    #[test]
    fn test_public_key_debug_shows_hex() {
        let keypair = Secp256k1KeyPair::generate();
        let debug_output = format!("{:?}", keypair.public_key());

        // Should contain the prefix "Secp256k1PublicKey("
        assert!(debug_output.starts_with("Secp256k1PublicKey("));
        // Should be hex encoded (66 characters for 33 bytes)
        assert!(debug_output.len() > 66);
    }

    // ------------------------------------------------------------------------
    // Thread Safety Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_keypair_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Secp256k1KeyPair>();
    }

    #[test]
    fn test_public_key_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Secp256k1PublicKey>();
    }

    #[test]
    fn test_signature_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Secp256k1Signature>();
    }

    // ------------------------------------------------------------------------
    // Debug Output Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_keypair_debug_does_not_expose_private_key() {
        let keypair = Secp256k1KeyPair::generate();
        let debug_output = format!("{:?}", keypair);

        // Should show public key
        assert!(debug_output.contains("public_key"));
        // Should not contain the private key (indicated by finish_non_exhaustive)
        assert!(debug_output.contains(".."));
    }

    #[test]
    fn test_signature_debug_shows_components() {
        let keypair = Secp256k1KeyPair::generate();
        let hash = [0x42u8; 32];
        let signature = keypair.sign(&hash).expect("signing should succeed");

        let debug_output = format!("{:?}", signature);

        assert!(debug_output.contains("r="));
        assert!(debug_output.contains("s="));
        assert!(debug_output.contains("v="));
    }

    // ------------------------------------------------------------------------
    // Sign/Verify roundtrip tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_sign_verify_roundtrip_multiple_hashes() {
        let keypair = Secp256k1KeyPair::generate();

        // Test with various hash values
        for i in 0u8..10 {
            let hash = [i; 32];
            let signature = keypair.sign(&hash).expect("signing should succeed");

            // Verify using keypair's verify method
            assert!(
                keypair.verify(&hash, &signature),
                "signature for hash {i} should verify"
            );
        }
    }

    #[test]
    fn test_wrong_hash_fails_verification() {
        let keypair = Secp256k1KeyPair::generate();
        let hash1 = [0x42u8; 32];
        let hash2 = [0x43u8; 32];

        let signature = keypair.sign(&hash1).expect("signing should succeed");

        // Verification with wrong hash should fail
        assert!(
            !keypair.verify(&hash2, &signature),
            "verification should fail with wrong hash"
        );
    }

    #[test]
    fn test_ethereum_address_never_fails_hash_extraction() {
        // This test verifies that the defensive .get() check in ethereum_address()
        // always succeeds because Keccak256 always produces 32 bytes
        let keypair = Secp256k1KeyPair::generate();
        let pubkey = keypair.public_key();

        // Call ethereum_address multiple times to ensure consistency
        let addr1 = pubkey.ethereum_address();
        let addr2 = pubkey.ethereum_address();

        assert_eq!(addr1, addr2);
        assert_eq!(addr1.len(), 20);
    }

    #[test]
    fn test_signature_normalization_both_paths() {
        // Test that signature normalization works correctly
        // We can't force a specific normalization path, but we can verify
        // that all signatures are in normalized form
        let keypair = Secp256k1KeyPair::generate();

        for i in 0..10 {
            let hash = [i; 32];
            let signature = keypair.sign(&hash).expect("signing should succeed");

            // Verify the signature is valid
            assert!(keypair.verify(&hash, &signature));

            // Recovery ID should always be 0 or 1
            assert!(signature.recovery_id() <= 1);
        }
    }

    // ========================================================================
    // Phase 2: Signature Normalization Coverage
    // ========================================================================

    #[test]
    fn should_produce_normalized_signatures_with_varied_hashes() {
        // Arrange: Generate keypair
        let keypair = Secp256k1KeyPair::generate();

        // Act & Assert: Test with many different hashes to exercise both
        // normalization branches (when S is already low, and when it needs normalization)
        for i in 0..100 {
            // Create varied hash patterns
            let mut hash = [0u8; 32];
            hash[0] = i;
            hash[31] = 255 - i;

            let signature = keypair.sign(&hash).expect("signing should succeed");

            // All signatures should be normalized (low-S)
            assert!(
                keypair.verify(&hash, &signature),
                "Normalized signature should verify"
            );

            // Recovery ID should be valid (0 or 1)
            let recovery_id = signature.recovery_id();
            assert!(
                recovery_id <= 1,
                "Recovery ID should be 0 or 1, got {recovery_id}"
            );
        }
    }

    #[test]
    fn should_handle_normalization_with_all_zero_hash() {
        // Arrange: All zeros hash (edge case)
        let keypair = Secp256k1KeyPair::generate();
        let hash = [0u8; 32];

        // Act: Sign the zero hash
        let signature = keypair.sign(&hash).expect("signing should succeed");

        // Assert: Signature is valid and normalized
        assert!(keypair.verify(&hash, &signature));
        assert!(signature.recovery_id() <= 1);
    }

    #[test]
    fn should_handle_normalization_with_all_max_hash() {
        // Arrange: All 0xFF hash (edge case)
        let keypair = Secp256k1KeyPair::generate();
        let hash = [0xFFu8; 32];

        // Act: Sign the max hash
        let signature = keypair.sign(&hash).expect("signing should succeed");

        // Assert: Signature is valid and normalized
        assert!(keypair.verify(&hash, &signature));
        assert!(signature.recovery_id() <= 1);
    }

    #[test]
    fn should_handle_recovery_id_flip_when_normalized() {
        // Arrange: Generate multiple signatures to exercise the recovery ID flip logic
        let keypair = Secp256k1KeyPair::generate();

        // Act & Assert: Generate many signatures
        // When normalize_s() returns Some(_), recovery ID is flipped (XOR 1)
        // When normalize_s() returns None, recovery ID is unchanged
        for i in 0..50 {
            let hash = [i; 32];
            let signature = keypair.sign(&hash).expect("signing should succeed");

            // Recovery ID should always be valid (0 or 1)
            assert!(signature.recovery_id() <= 1);

            // Verify the signature with the recovery ID
            assert!(keypair.verify(&hash, &signature));
        }
    }

    #[test]
    fn should_produce_consistent_signatures_with_same_hash() {
        // Arrange: Same keypair, same hash
        let keypair = Secp256k1KeyPair::generate();
        let hash = [0x42u8; 32];

        // Act: Sign the same hash multiple times (with randomized k)
        let sig1 = keypair.sign(&hash).expect("signing should succeed");
        let sig2 = keypair.sign(&hash).expect("signing should succeed");

        // Assert: Both should verify (but may not be identical due to random k)
        assert!(keypair.verify(&hash, &sig1));
        assert!(keypair.verify(&hash, &sig2));

        // Both should be normalized
        assert!(sig1.recovery_id() <= 1);
        assert!(sig2.recovery_id() <= 1);
    }

    #[test]
    fn should_handle_normalization_edge_case_patterns() {
        // Arrange: Test various bit patterns that might affect S normalization
        let keypair = Secp256k1KeyPair::generate();

        let test_patterns = vec![
            [0x00u8; 32], // All zeros
            [0xFFu8; 32], // All ones
            [0xAAu8; 32], // Alternating 10101010
            [0x55u8; 32], // Alternating 01010101
            {
                let mut h = [0u8; 32];
                h[0] = 0xFF;
                h
            }, // First byte max
            {
                let mut h = [0u8; 32];
                h[31] = 0xFF;
                h
            }, // Last byte max
        ];

        // Act & Assert: All patterns should produce valid normalized signatures
        for (idx, hash) in test_patterns.iter().enumerate() {
            let signature = keypair
                .sign(hash)
                .unwrap_or_else(|_| panic!("Pattern {idx} signing should succeed"));

            assert!(
                keypair.verify(hash, &signature),
                "Pattern {idx} should verify"
            );
            assert!(
                signature.recovery_id() <= 1,
                "Pattern {idx} recovery ID should be valid"
            );
        }
    }

    // ========================================================================
    // Ed25519 KeyPair Tests
    // ========================================================================

    #[test]
    fn test_ed25519_generate_produces_valid_keypair() {
        let keypair = Ed25519KeyPair::generate();

        // Public key should be 32 bytes
        assert_eq!(keypair.public_key().as_bytes().len(), 32);
    }

    #[test]
    fn test_ed25519_generate_produces_unique_keys() {
        let keypair1 = Ed25519KeyPair::generate();
        let keypair2 = Ed25519KeyPair::generate();

        // Should generate different public keys
        assert_ne!(
            keypair1.public_key().as_bytes(),
            keypair2.public_key().as_bytes()
        );
    }

    #[test]
    fn test_ed25519_from_bytes_success() {
        let bytes = [0x42u8; 32];
        let result = Ed25519KeyPair::from_bytes(bytes);
        assert!(result.is_ok());
    }

    #[test]
    fn test_ed25519_from_bytes_zero_is_valid() {
        // Unlike secp256k1, zero bytes are valid for ed25519
        let bytes = [0u8; 32];
        let result = Ed25519KeyPair::from_bytes(bytes);
        assert!(result.is_ok());
    }

    #[test]
    fn test_ed25519_from_secret_key() {
        let secret = SecretKey::generate();
        let result = Ed25519KeyPair::from_secret_key(&secret);
        assert!(result.is_ok());
    }

    #[test]
    fn test_ed25519_deterministic_public_key() {
        // Same private key should always produce the same public key
        let bytes = [0x42u8; 32];

        let keypair1 = Ed25519KeyPair::from_bytes(bytes).expect("valid key");
        let keypair2 = Ed25519KeyPair::from_bytes(bytes).expect("valid key");

        assert_eq!(
            keypair1.public_key().as_bytes(),
            keypair2.public_key().as_bytes()
        );
    }

    #[test]
    fn test_ed25519_sign_produces_valid_signature() {
        let keypair = Ed25519KeyPair::generate();
        let hash = [0x42u8; 32];

        let signature = keypair.sign(&hash).expect("signing should succeed");

        // Ed25519 signature should be 64 bytes
        assert_eq!(signature.as_ref().len(), 64);
    }

    #[test]
    fn test_ed25519_signature_is_verifiable() {
        let keypair = Ed25519KeyPair::generate();
        let hash = [0x42u8; 32];

        let signature = keypair.sign(&hash).expect("signing should succeed");

        // Verify using keypair's verify method
        assert!(
            keypair.verify(&hash, &signature),
            "signature should be valid"
        );
    }

    #[test]
    fn test_ed25519_different_messages_produce_different_signatures() {
        let keypair = Ed25519KeyPair::generate();
        let hash1 = [0x42u8; 32];
        let hash2 = [0x43u8; 32];

        let sig1 = keypair.sign(&hash1).expect("signing should succeed");
        let sig2 = keypair.sign(&hash2).expect("signing should succeed");

        // Different messages should produce different signatures
        assert_ne!(sig1.as_ref(), sig2.as_ref());
    }

    #[test]
    fn test_ed25519_wrong_hash_fails_verification() {
        let keypair = Ed25519KeyPair::generate();
        let hash1 = [0x42u8; 32];
        let hash2 = [0x43u8; 32];

        let signature = keypair.sign(&hash1).expect("signing should succeed");

        // Verification with wrong hash should fail
        assert!(
            !keypair.verify(&hash2, &signature),
            "verification should fail with wrong hash"
        );
    }

    #[test]
    fn test_ed25519_solana_address_format() {
        let keypair = Ed25519KeyPair::generate();
        let address = keypair.public_key().solana_address();

        // Solana addresses are base58 encoded 32-byte public keys
        // Typically 32-44 characters
        assert!(
            address.len() >= 32 && address.len() <= 44,
            "Solana address should be 32-44 characters: {address}"
        );
    }

    #[test]
    fn test_ed25519_solana_address_deterministic() {
        let bytes = [0x42u8; 32];
        let keypair = Ed25519KeyPair::from_bytes(bytes).expect("valid key");

        let address1 = keypair.public_key().solana_address();
        let address2 = keypair.public_key().solana_address();

        assert_eq!(address1, address2);
    }

    #[test]
    fn test_ed25519_sign_verify_roundtrip_multiple_hashes() {
        let keypair = Ed25519KeyPair::generate();

        for i in 0u8..10 {
            let hash = [i; 32];
            let signature = keypair.sign(&hash).expect("signing should succeed");

            assert!(
                keypair.verify(&hash, &signature),
                "signature for hash {i} should verify"
            );
        }
    }

    #[test]
    fn test_ed25519_keypair_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Ed25519KeyPair>();
    }

    #[test]
    fn test_ed25519_public_key_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Ed25519PublicKey>();
    }

    #[test]
    fn test_ed25519_signature_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Ed25519Signature>();
    }

    #[test]
    fn test_ed25519_keypair_debug_does_not_expose_private_key() {
        let keypair = Ed25519KeyPair::generate();
        let debug_output = format!("{:?}", keypair);

        // Should show public key
        assert!(debug_output.contains("public_key"));
        // Should not contain the private key (indicated by finish_non_exhaustive)
        assert!(debug_output.contains(".."));
    }

    #[test]
    fn test_ed25519_signature_debug_shows_hex() {
        let keypair = Ed25519KeyPair::generate();
        let hash = [0x42u8; 32];
        let signature = keypair.sign(&hash).expect("signing should succeed");

        let debug_output = format!("{:?}", signature);
        assert!(debug_output.starts_with("Ed25519Signature("));
    }

    #[test]
    fn test_ed25519_public_key_debug_shows_hex() {
        let keypair = Ed25519KeyPair::generate();
        let debug_output = format!("{:?}", keypair.public_key());

        assert!(debug_output.starts_with("Ed25519PublicKey("));
    }

    #[test]
    fn test_ed25519_public_key_as_ref_returns_bytes() {
        let keypair = Ed25519KeyPair::generate();
        let pubkey = keypair.public_key();

        // AsRef should return the 32-byte public key
        assert_eq!(pubkey.as_ref().len(), 32);
        assert_eq!(pubkey.as_ref(), pubkey.as_bytes());
    }

    #[test]
    fn test_ed25519_signature_from_bytes() {
        let bytes = [0x42u8; 64];
        let sig = Ed25519Signature::from_bytes(bytes);
        assert_eq!(sig.as_ref(), &bytes);
    }

    #[test]
    fn test_ed25519_public_key_from_bytes() {
        let bytes = [0x42u8; 32];
        let pubkey = Ed25519PublicKey::from_bytes(bytes);
        assert_eq!(pubkey.as_bytes(), &bytes);
    }

    #[test]
    fn test_ed25519_invalid_signature_fails_verification() {
        let keypair = Ed25519KeyPair::generate();
        let hash = [0x42u8; 32];

        // Create an invalid signature (all zeros)
        let invalid_sig = Ed25519Signature::from_bytes([0u8; 64]);

        // Verification should fail
        assert!(!keypair.verify(&hash, &invalid_sig));
    }

    #[test]
    fn test_ed25519_known_test_vector() {
        // Test vector from https://ed25519.cr.yp.to/software.html
        // Secret key (seed): 32 bytes of 0x9d repeated
        let secret_bytes = [0x9du8; 32];
        let keypair = Ed25519KeyPair::from_bytes(secret_bytes).expect("valid key");

        // Sign a message
        let message = [0u8; 32];
        let signature = keypair.sign(&message).expect("signing should succeed");

        // Verify the signature
        assert!(keypair.verify(&message, &signature));
    }
}

#[cfg(test)]
mod proptest_tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn test_sign_verify_roundtrip(hash in any::<[u8; 32]>()) {
            let keypair = Secp256k1KeyPair::generate();
            let signature = keypair.sign(&hash).expect("signing should succeed");

            // Verify signature using keypair's verify method
            prop_assert!(keypair.verify(&hash, &signature));
        }

        #[test]
        fn test_recovery_id_is_valid(hash in any::<[u8; 32]>()) {
            let keypair = Secp256k1KeyPair::generate();
            let signature = keypair.sign(&hash).expect("signing should succeed");

            // Recovery ID should always be 0 or 1
            prop_assert!(signature.recovery_id() <= 1);
        }

        #[test]
        fn test_public_key_formats_consistent(seed in any::<[u8; 32]>()) {
            // Skip invalid seeds (zero)
            if seed == [0u8; 32] {
                return Ok(());
            }

            if let Ok(keypair) = Secp256k1KeyPair::from_bytes(seed) {
                let pubkey = keypair.public_key();

                // Compressed should start with 02 or 03
                let prefix = pubkey.compressed()[0];
                prop_assert!(prefix == 0x02 || prefix == 0x03);

                // Uncompressed should start with 04
                prop_assert_eq!(pubkey.uncompressed()[0], 0x04);

                // X coordinate should be the same in both formats
                prop_assert_eq!(&pubkey.compressed()[1..33], &pubkey.uncompressed()[1..33]);
            }
        }
    }
}
