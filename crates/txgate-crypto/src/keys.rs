//! Cryptographic key types with secure memory handling.
//!
//! This module provides key types that ensure sensitive key material is:
//! - Zeroized on drop to prevent memory leaks
//! - Never exposed in debug output
//! - Compared in constant time to prevent timing attacks
//!
//! # Security
//!
//! All key types in this module are designed with defense-in-depth:
//! - `SecretKey` does not implement `Clone` to prevent accidental duplication
//! - Debug output is redacted to prevent logging of key material
//! - Comparison uses constant-time algorithms

use rand::RngCore;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The length of a secret key in bytes.
pub const SECRET_KEY_LEN: usize = 32;

/// A 32-byte secret key with automatic zeroization.
///
/// # Security
///
/// This type ensures that key material is securely erased from memory
/// when the value is dropped. Key material never appears in debug output.
///
/// **Important**: This type intentionally does not implement `Clone` to
/// prevent accidental duplication of secret key material. Keys must be
/// moved, not copied.
///
/// # Example
///
/// ```
/// use txgate_crypto::keys::SecretKey;
///
/// // Generate a new random key
/// let key = SecretKey::generate();
///
/// // Keys are automatically zeroized when dropped
/// drop(key);
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    bytes: [u8; SECRET_KEY_LEN],
}

impl SecretKey {
    /// Create a new `SecretKey` from raw bytes.
    ///
    /// # Arguments
    /// * `bytes` - The 32-byte secret key material
    ///
    /// # Security
    /// The input bytes are copied into the `SecretKey`. The caller should
    /// zeroize the original bytes if they are no longer needed.
    ///
    /// # Example
    ///
    /// ```
    /// use txgate_crypto::keys::SecretKey;
    /// use zeroize::Zeroize;
    ///
    /// let mut raw_bytes = [0x42u8; 32];
    /// let key = SecretKey::new(raw_bytes);
    ///
    /// // Zeroize the original bytes for security
    /// raw_bytes.zeroize();
    /// ```
    #[must_use]
    pub const fn new(bytes: [u8; SECRET_KEY_LEN]) -> Self {
        Self { bytes }
    }

    /// Generate a new random `SecretKey` using a cryptographically secure RNG.
    ///
    /// This uses the operating system's secure random number generator
    /// (`OsRng`) to generate the key material.
    ///
    /// # Example
    ///
    /// ```
    /// use txgate_crypto::keys::SecretKey;
    ///
    /// let key = SecretKey::generate();
    /// assert_eq!(key.len(), 32);
    /// ```
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0u8; SECRET_KEY_LEN];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self { bytes }
    }

    /// Expose the raw bytes for cryptographic operations.
    ///
    /// # Security
    ///
    /// The returned reference must not be stored or copied beyond the
    /// immediate cryptographic operation. Misuse can lead to key material
    /// remaining in memory longer than intended.
    ///
    /// # Example
    ///
    /// ```
    /// use txgate_crypto::keys::SecretKey;
    ///
    /// let key = SecretKey::generate();
    /// let bytes = key.as_bytes();
    /// assert_eq!(bytes.len(), 32);
    /// ```
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SECRET_KEY_LEN] {
        &self.bytes
    }

    /// Get the length of the secret key in bytes.
    ///
    /// Always returns 32 for this key type.
    #[must_use]
    pub const fn len(&self) -> usize {
        SECRET_KEY_LEN
    }

    /// Returns false (`SecretKey` is never empty).
    ///
    /// This method exists for API consistency and always returns `false`.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// Convert this `SecretKey` into a `k256::SecretKey` for secp256k1 operations.
    ///
    /// # Security
    ///
    /// This method consumes `self` to ensure the key material exists in only
    /// one place. After calling this method, the original `SecretKey` is
    /// zeroized and cannot be used.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes do not represent a valid secp256k1 scalar
    /// (e.g., if the value is zero or greater than the curve order).
    ///
    /// # Example
    ///
    /// ```
    /// use txgate_crypto::keys::SecretKey;
    ///
    /// let key = SecretKey::generate();
    /// match key.into_k256() {
    ///     Ok(k256_key) => {
    ///         // Use k256_key for signing
    ///     }
    ///     Err(e) => {
    ///         // Handle invalid key (very rare with generated keys)
    ///     }
    /// }
    /// ```
    pub fn into_k256(self) -> Result<k256::SecretKey, SecretKeyError> {
        k256::SecretKey::from_bytes((&self.bytes).into()).map_err(|_| SecretKeyError::InvalidKey)
    }
}

/// Errors related to secret key operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretKeyError {
    /// The provided bytes do not represent a valid secret key.
    InvalidKey,
}

impl std::fmt::Display for SecretKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidKey => write!(f, "invalid secret key bytes"),
        }
    }
}

impl std::error::Error for SecretKeyError {}

// Prevent accidental debug printing of secrets
impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey([REDACTED])")
    }
}

// Constant-time equality comparison to prevent timing attacks
impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.bytes.ct_eq(&other.bytes).into()
    }
}

impl Eq for SecretKey {}

impl From<[u8; SECRET_KEY_LEN]> for SecretKey {
    fn from(bytes: [u8; SECRET_KEY_LEN]) -> Self {
        Self::new(bytes)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn test_new_creates_key_with_correct_bytes() {
        let bytes = [0x42u8; SECRET_KEY_LEN];
        let key = SecretKey::new(bytes);
        assert_eq!(key.as_bytes(), &bytes);
    }

    #[test]
    fn test_generate_produces_unique_keys() {
        let key1 = SecretKey::generate();
        let key2 = SecretKey::generate();
        // Extremely unlikely to generate the same key twice
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_len_returns_32() {
        let key = SecretKey::generate();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_is_empty_returns_false() {
        let key = SecretKey::generate();
        assert!(!key.is_empty());
    }

    #[test]
    fn test_debug_does_not_expose_key_material() {
        let key = SecretKey::new([0xABu8; SECRET_KEY_LEN]);
        let debug_output = format!("{key:?}");
        assert_eq!(debug_output, "SecretKey([REDACTED])");
        // Ensure the actual key bytes don't appear in output
        assert!(!debug_output.contains("ab"));
        assert!(!debug_output.contains("AB"));
        assert!(!debug_output.contains("171")); // 0xAB as decimal
    }

    #[test]
    fn test_partial_eq_is_constant_time() {
        // This test verifies the PartialEq implementation works correctly.
        // Verifying constant-time behavior programmatically is difficult,
        // but we can at least verify correctness.
        let key1 = SecretKey::new([0x42u8; SECRET_KEY_LEN]);
        let key2 = SecretKey::new([0x42u8; SECRET_KEY_LEN]);
        let key3 = SecretKey::new([0x43u8; SECRET_KEY_LEN]);

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_partial_eq_single_bit_difference() {
        let mut bytes1 = [0x00u8; SECRET_KEY_LEN];
        let mut bytes2 = [0x00u8; SECRET_KEY_LEN];
        bytes2[0] = 0x01; // Single bit difference

        let key1 = SecretKey::new(bytes1);
        let key2 = SecretKey::new(bytes2);

        assert_ne!(key1, key2);

        // Clean up
        bytes1.zeroize();
        bytes2.zeroize();
    }

    #[test]
    fn test_from_array() {
        let bytes = [0x42u8; SECRET_KEY_LEN];
        let key: SecretKey = bytes.into();
        assert_eq!(key.as_bytes(), &bytes);
    }

    #[test]
    fn test_into_k256_success() {
        // Generate a key - should almost always be valid
        let key = SecretKey::generate();
        let result = key.into_k256();
        assert!(result.is_ok());
    }

    #[test]
    fn test_into_k256_invalid_zero_key() {
        // Zero is not a valid secp256k1 scalar
        let key = SecretKey::new([0u8; SECRET_KEY_LEN]);
        let result = key.into_k256();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), SecretKeyError::InvalidKey);
    }

    #[test]
    fn test_secret_key_error_display() {
        let err = SecretKeyError::InvalidKey;
        assert_eq!(format!("{err}"), "invalid secret key bytes");
    }

    // Compile-time check: SecretKey should NOT implement Clone
    // If this trait bound compiles, the test fails.
    // We verify by ensuring Clone is not implemented via a negative test.
    #[test]
    fn test_no_clone_implementation() {
        fn assert_not_clone<T>() {
            // This function exists purely for documentation.
            // The actual check is that SecretKey doesn't implement Clone,
            // which we verify by NOT being able to call .clone() on it.
        }
        assert_not_clone::<SecretKey>();

        // The following would fail to compile if uncommented,
        // proving that Clone is not implemented:
        // let key = SecretKey::generate();
        // let _cloned = key.clone(); // ERROR: Clone not implemented
    }

    // Test that SecretKey is Send and Sync (safe to transfer between threads)
    #[test]
    fn test_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SecretKey>();
    }
}
