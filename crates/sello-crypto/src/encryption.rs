//! AEAD encryption for key material at rest.
//!
//! This module provides ChaCha20-Poly1305 AEAD encryption with Argon2id key derivation
//! for protecting secret key material at rest.
//!
//! # Security Properties
//!
//! - **Authenticated Encryption**: ChaCha20-Poly1305 provides both confidentiality and
//!   integrity protection. Any tampering with the ciphertext will be detected during decryption.
//!
//! - **Key Derivation**: Argon2id is used to derive encryption keys from passphrases,
//!   providing resistance against both GPU/ASIC attacks (memory-hard) and side-channel
//!   attacks (data-independent memory access in the second phase).
//!
//! - **Random Salt and Nonce**: Each encryption operation generates fresh random salt
//!   and nonce using the operating system's secure RNG, ensuring that:
//!   - The same passphrase produces different ciphertexts
//!   - Nonce reuse is avoided
//!
//! - **Zeroization**: Derived encryption keys are zeroized immediately after use.
//!
//! # Encrypted Key Format
//!
//! The encrypted key is serialized as follows (77 bytes total):
//!
//! ```text
//! ┌─────────────────────────────────────┐
//! │ version: 1 (1 byte)                 │
//! │ salt: [u8; 16]                      │
//! │ nonce: [u8; 12]                     │
//! │ ciphertext: [u8; 32]                │
//! │ tag: [u8; 16]                       │
//! └─────────────────────────────────────┘
//! ```
//!
//! The ciphertext and tag are combined in the serialized format (48 bytes total for
//! 32-byte plaintext + 16-byte authentication tag).
//!
//! # Example
//!
//! ```rust
//! use sello_crypto::keys::SecretKey;
//! use sello_crypto::encryption::{encrypt_key, decrypt_key};
//!
//! // Generate a key to encrypt
//! let secret_key = SecretKey::generate();
//! let passphrase = "my secure passphrase";
//!
//! // Encrypt the key
//! let encrypted = encrypt_key(&secret_key, passphrase).expect("encryption failed");
//!
//! // Serialize for storage
//! let bytes = encrypted.to_bytes();
//!
//! // Later, deserialize and decrypt
//! use sello_crypto::encryption::EncryptedKey;
//! let encrypted = EncryptedKey::from_bytes(&bytes).expect("invalid format");
//! let decrypted = decrypt_key(&encrypted, passphrase).expect("decryption failed");
//! ```
//!
//! # Security Considerations
//!
//! - Use strong, unique passphrases for each key
//! - Store the encrypted key file with appropriate file system permissions
//! - The passphrase should be obtained securely (e.g., from a secure input mechanism)
//! - Do not log or display the passphrase or decrypted key material

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use sello_core::error::StoreError;
use zeroize::Zeroize;

use crate::keys::SecretKey;

// ============================================================================
// Constants
// ============================================================================

/// Current encryption format version.
///
/// This allows for future format changes while maintaining backward compatibility.
pub const ENCRYPTION_VERSION: u8 = 1;

/// Length of the salt in bytes.
pub const SALT_LEN: usize = 16;

/// Length of the nonce in bytes.
pub const NONCE_LEN: usize = 12;

/// Length of the authentication tag in bytes.
pub const TAG_LEN: usize = 16;

/// Length of the plaintext secret key in bytes.
pub const PLAINTEXT_LEN: usize = 32;

/// Total length of the encrypted key file in bytes.
///
/// Layout: version (1) + salt (16) + nonce (12) + ciphertext (32) + tag (16) = 77
pub const ENCRYPTED_KEY_LEN: usize = 1 + SALT_LEN + NONCE_LEN + PLAINTEXT_LEN + TAG_LEN;

// Argon2id parameters (OWASP recommended for password hashing)
// See: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
const ARGON2_MEMORY_KIB: u32 = 65536; // 64 MiB
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 4;
const ARGON2_OUTPUT_LEN: usize = 32;

// ============================================================================
// Types
// ============================================================================

/// An encrypted secret key container.
///
/// This structure holds all the data needed to decrypt a secret key:
/// - Version byte for format compatibility
/// - Salt used for key derivation
/// - Nonce used for encryption
/// - Ciphertext containing the encrypted key material and authentication tag
///
/// # Security
///
/// The salt and nonce are randomly generated for each encryption operation.
/// The ciphertext includes a 16-byte authentication tag appended by ChaCha20-Poly1305.
#[derive(Debug, Clone)]
pub struct EncryptedKey {
    /// Format version (currently always 1).
    pub version: u8,
    /// Random salt used for Argon2id key derivation.
    pub salt: [u8; SALT_LEN],
    /// Random nonce used for ChaCha20-Poly1305 encryption.
    pub nonce: [u8; NONCE_LEN],
    /// Encrypted key material with authentication tag (48 bytes: 32 + 16).
    pub ciphertext: Vec<u8>,
}

impl EncryptedKey {
    /// Serialize the encrypted key to bytes.
    ///
    /// The output is 77 bytes in the format:
    /// `version || salt || nonce || ciphertext || tag`
    ///
    /// # Example
    ///
    /// ```rust
    /// use sello_crypto::keys::SecretKey;
    /// use sello_crypto::encryption::encrypt_key;
    ///
    /// let secret_key = SecretKey::generate();
    /// let encrypted = encrypt_key(&secret_key, "passphrase").expect("encryption failed");
    ///
    /// let bytes = encrypted.to_bytes();
    /// assert_eq!(bytes.len(), 77);
    /// ```
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(ENCRYPTED_KEY_LEN);
        bytes.push(self.version);
        bytes.extend_from_slice(&self.salt);
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.ciphertext);
        bytes
    }

    /// Deserialize an encrypted key from bytes.
    ///
    /// # Errors
    ///
    /// Returns `StoreError::InvalidFormat` if:
    /// - The input length is not exactly 77 bytes
    /// - The version byte is not recognized
    ///
    /// # Example
    ///
    /// ```rust
    /// use sello_crypto::encryption::EncryptedKey;
    ///
    /// // Invalid length will return an error
    /// let result = EncryptedKey::from_bytes(&[0u8; 10]);
    /// assert!(result.is_err());
    /// ```
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, StoreError> {
        if bytes.len() != ENCRYPTED_KEY_LEN {
            return Err(StoreError::InvalidFormat);
        }

        // Parse version (safe: length already validated)
        let version = *bytes.first().ok_or(StoreError::InvalidFormat)?;
        if version != ENCRYPTION_VERSION {
            return Err(StoreError::InvalidFormat);
        }

        // Define byte ranges (safe: length already validated as ENCRYPTED_KEY_LEN = 77)
        let salt_start = 1;
        let salt_end = salt_start + SALT_LEN;
        let nonce_start = salt_end;
        let nonce_end = nonce_start + NONCE_LEN;
        let ciphertext_start = nonce_end;

        // Parse salt (safe: using .get() with validated ranges)
        let salt_slice = bytes
            .get(salt_start..salt_end)
            .ok_or(StoreError::InvalidFormat)?;
        let salt: [u8; SALT_LEN] = salt_slice
            .try_into()
            .map_err(|_| StoreError::InvalidFormat)?;

        // Parse nonce (safe: using .get() with validated ranges)
        let nonce_slice = bytes
            .get(nonce_start..nonce_end)
            .ok_or(StoreError::InvalidFormat)?;
        let nonce: [u8; NONCE_LEN] = nonce_slice
            .try_into()
            .map_err(|_| StoreError::InvalidFormat)?;

        // Parse ciphertext (safe: using .get() with validated range)
        let ciphertext = bytes
            .get(ciphertext_start..)
            .ok_or(StoreError::InvalidFormat)?
            .to_vec();

        Ok(Self {
            version,
            salt,
            nonce,
            ciphertext,
        })
    }
}

// ============================================================================
// Key Derivation
// ============================================================================

/// Derive an encryption key from a passphrase using Argon2id.
///
/// # Arguments
///
/// * `passphrase` - The user's passphrase
/// * `salt` - A 16-byte random salt
///
/// # Returns
///
/// A 32-byte derived key suitable for use with ChaCha20-Poly1305.
///
/// # Security
///
/// - Uses Argon2id with OWASP-recommended parameters:
///   - Memory: 64 MiB
///   - Iterations: 3
///   - Parallelism: 4
/// - The caller is responsible for zeroizing the returned key after use
fn derive_key(passphrase: &str, salt: &[u8; SALT_LEN]) -> Result<[u8; 32], StoreError> {
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(ARGON2_OUTPUT_LEN),
    )
    .map_err(|_| StoreError::EncryptionFailed)?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut output)
        .map_err(|_| StoreError::EncryptionFailed)?;

    Ok(output)
}

// ============================================================================
// Encryption / Decryption
// ============================================================================

/// Encrypt a secret key with a passphrase.
///
/// # Arguments
///
/// * `secret_key` - The secret key to encrypt
/// * `passphrase` - The passphrase to use for key derivation
///
/// # Returns
///
/// An `EncryptedKey` containing the encrypted key material and all data
/// needed for decryption (salt, nonce).
///
/// # Errors
///
/// Returns `StoreError::EncryptionFailed` if:
/// - Key derivation fails
/// - Encryption fails (should not happen with valid inputs)
///
/// # Security
///
/// - Generates fresh random salt and nonce for each encryption
/// - Uses cryptographically secure OS random number generator
/// - Zeroizes the derived encryption key after use
///
/// # Example
///
/// ```rust
/// use sello_crypto::keys::SecretKey;
/// use sello_crypto::encryption::encrypt_key;
///
/// let secret_key = SecretKey::generate();
/// let encrypted = encrypt_key(&secret_key, "my passphrase").expect("encryption failed");
///
/// // The encrypted data can be serialized and stored
/// let bytes = encrypted.to_bytes();
/// ```
pub fn encrypt_key(secret_key: &SecretKey, passphrase: &str) -> Result<EncryptedKey, StoreError> {
    // 1. Generate random salt and nonce using OS RNG
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

    // 2. Derive encryption key
    let mut encryption_key = derive_key(passphrase, &salt)?;

    // 3. Encrypt with ChaCha20-Poly1305
    let cipher = ChaCha20Poly1305::new_from_slice(&encryption_key)
        .map_err(|_| StoreError::EncryptionFailed)?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, secret_key.as_bytes().as_ref())
        .map_err(|_| StoreError::EncryptionFailed)?;

    // 4. Zeroize the encryption key immediately
    encryption_key.zeroize();

    Ok(EncryptedKey {
        version: ENCRYPTION_VERSION,
        salt,
        nonce: nonce_bytes,
        ciphertext,
    })
}

/// Decrypt a secret key with a passphrase.
///
/// # Arguments
///
/// * `encrypted` - The encrypted key container
/// * `passphrase` - The passphrase used during encryption
///
/// # Returns
///
/// The decrypted `SecretKey`.
///
/// # Errors
///
/// Returns `StoreError::InvalidFormat` if:
/// - The version byte is not recognized
/// - The ciphertext length is invalid
///
/// Returns `StoreError::DecryptionFailed` if:
/// - The passphrase is incorrect
/// - The ciphertext has been tampered with
/// - The authentication tag verification fails
///
/// # Security
///
/// - ChaCha20-Poly1305 provides authenticated decryption, so any tampering
///   with the ciphertext will be detected
/// - Error messages are intentionally generic to avoid leaking information
/// - The derived encryption key is zeroized after use
///
/// # Example
///
/// ```rust
/// use sello_crypto::keys::SecretKey;
/// use sello_crypto::encryption::{encrypt_key, decrypt_key};
///
/// let original = SecretKey::generate();
/// let encrypted = encrypt_key(&original, "passphrase").expect("encryption failed");
///
/// let decrypted = decrypt_key(&encrypted, "passphrase").expect("decryption failed");
/// assert_eq!(original.as_bytes(), decrypted.as_bytes());
/// ```
pub fn decrypt_key(encrypted: &EncryptedKey, passphrase: &str) -> Result<SecretKey, StoreError> {
    // 1. Check version
    if encrypted.version != ENCRYPTION_VERSION {
        return Err(StoreError::InvalidFormat);
    }

    // 2. Validate ciphertext length (should be PLAINTEXT_LEN + TAG_LEN)
    let expected_ciphertext_len = PLAINTEXT_LEN + TAG_LEN;
    if encrypted.ciphertext.len() != expected_ciphertext_len {
        return Err(StoreError::InvalidFormat);
    }

    // 3. Derive encryption key
    let mut encryption_key = derive_key(passphrase, &encrypted.salt)?;

    // 4. Decrypt with ChaCha20-Poly1305
    let cipher = ChaCha20Poly1305::new_from_slice(&encryption_key)
        .map_err(|_| StoreError::DecryptionFailed)?;
    let nonce = Nonce::from_slice(&encrypted.nonce);

    let plaintext = cipher
        .decrypt(nonce, encrypted.ciphertext.as_ref())
        .map_err(|_| StoreError::DecryptionFailed)?;

    // 5. Zeroize the encryption key immediately
    encryption_key.zeroize();

    // 6. Convert to SecretKey
    let bytes: [u8; 32] = plaintext
        .try_into()
        .map_err(|_| StoreError::InvalidFormat)?;

    Ok(SecretKey::new(bytes))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::indexing_slicing)]

    use super::*;

    #[test]
    fn test_encrypt_decrypt_round_trip() {
        let original = SecretKey::generate();
        let passphrase = "test passphrase 123!";

        let encrypted = encrypt_key(&original, passphrase).expect("encryption should succeed");
        let decrypted = decrypt_key(&encrypted, passphrase).expect("decryption should succeed");

        assert_eq!(original.as_bytes(), decrypted.as_bytes());
    }

    #[test]
    fn test_different_passphrases_produce_different_ciphertexts() {
        let secret_key = SecretKey::new([0x42u8; 32]);

        let encrypted1 =
            encrypt_key(&secret_key, "passphrase1").expect("encryption should succeed");
        let encrypted2 =
            encrypt_key(&secret_key, "passphrase2").expect("encryption should succeed");

        // Different passphrases should produce different derived keys, thus different ciphertexts
        assert_ne!(encrypted1.ciphertext, encrypted2.ciphertext);
    }

    #[test]
    fn test_same_passphrase_different_salts() {
        let secret_key = SecretKey::new([0x42u8; 32]);
        let passphrase = "same passphrase";

        let encrypted1 = encrypt_key(&secret_key, passphrase).expect("encryption should succeed");
        let encrypted2 = encrypt_key(&secret_key, passphrase).expect("encryption should succeed");

        // Even with the same passphrase, random salts should produce different ciphertexts
        assert_ne!(encrypted1.salt, encrypted2.salt);
        assert_ne!(encrypted1.nonce, encrypted2.nonce);
        assert_ne!(encrypted1.ciphertext, encrypted2.ciphertext);
    }

    #[test]
    fn test_wrong_passphrase_fails_decryption() {
        let secret_key = SecretKey::generate();
        let correct_passphrase = "correct passphrase";
        let wrong_passphrase = "wrong passphrase";

        let encrypted =
            encrypt_key(&secret_key, correct_passphrase).expect("encryption should succeed");
        let result = decrypt_key(&encrypted, wrong_passphrase);

        assert!(result.is_err());
        assert!(matches!(result, Err(StoreError::DecryptionFailed)));
    }

    #[test]
    fn test_serialization_round_trip() {
        let secret_key = SecretKey::generate();
        let passphrase = "test passphrase";

        let encrypted = encrypt_key(&secret_key, passphrase).expect("encryption should succeed");
        let bytes = encrypted.to_bytes();

        assert_eq!(bytes.len(), ENCRYPTED_KEY_LEN);

        let deserialized =
            EncryptedKey::from_bytes(&bytes).expect("deserialization should succeed");
        let decrypted = decrypt_key(&deserialized, passphrase).expect("decryption should succeed");

        assert_eq!(secret_key.as_bytes(), decrypted.as_bytes());
    }

    #[test]
    fn test_invalid_format_wrong_length() {
        let too_short = vec![0u8; 10];
        let result = EncryptedKey::from_bytes(&too_short);
        assert!(result.is_err());
        assert!(matches!(result, Err(StoreError::InvalidFormat)));

        let too_long = vec![0u8; 100];
        let result = EncryptedKey::from_bytes(&too_long);
        assert!(result.is_err());
        assert!(matches!(result, Err(StoreError::InvalidFormat)));
    }

    #[test]
    fn test_invalid_format_wrong_version() {
        let mut bytes = vec![0u8; ENCRYPTED_KEY_LEN];
        bytes[0] = 99; // Invalid version

        let result = EncryptedKey::from_bytes(&bytes);
        assert!(result.is_err());
        assert!(matches!(result, Err(StoreError::InvalidFormat)));
    }

    #[test]
    fn test_tampered_ciphertext_fails_decryption() {
        let secret_key = SecretKey::generate();
        let passphrase = "test passphrase";

        let mut encrypted =
            encrypt_key(&secret_key, passphrase).expect("encryption should succeed");

        // Tamper with a byte in the ciphertext
        if let Some(byte) = encrypted.ciphertext.first_mut() {
            *byte ^= 0xFF;
        }

        let result = decrypt_key(&encrypted, passphrase);
        assert!(result.is_err());
        assert!(matches!(result, Err(StoreError::DecryptionFailed)));
    }

    #[test]
    fn test_tampered_tag_fails_decryption() {
        let secret_key = SecretKey::generate();
        let passphrase = "test passphrase";

        let mut encrypted =
            encrypt_key(&secret_key, passphrase).expect("encryption should succeed");

        // Tamper with the last byte (part of the auth tag)
        if let Some(byte) = encrypted.ciphertext.last_mut() {
            *byte ^= 0xFF;
        }

        let result = decrypt_key(&encrypted, passphrase);
        assert!(result.is_err());
        assert!(matches!(result, Err(StoreError::DecryptionFailed)));
    }

    #[test]
    fn test_tampered_nonce_fails_decryption() {
        let secret_key = SecretKey::generate();
        let passphrase = "test passphrase";

        let mut encrypted =
            encrypt_key(&secret_key, passphrase).expect("encryption should succeed");

        // Tamper with the nonce
        encrypted.nonce[0] ^= 0xFF;

        let result = decrypt_key(&encrypted, passphrase);
        assert!(result.is_err());
        assert!(matches!(result, Err(StoreError::DecryptionFailed)));
    }

    #[test]
    fn test_tampered_salt_fails_decryption() {
        let secret_key = SecretKey::generate();
        let passphrase = "test passphrase";

        let mut encrypted =
            encrypt_key(&secret_key, passphrase).expect("encryption should succeed");

        // Tamper with the salt (will derive a different key)
        encrypted.salt[0] ^= 0xFF;

        let result = decrypt_key(&encrypted, passphrase);
        assert!(result.is_err());
        assert!(matches!(result, Err(StoreError::DecryptionFailed)));
    }

    #[test]
    fn test_encrypted_key_to_bytes_format() {
        let secret_key = SecretKey::generate();
        let passphrase = "test passphrase";

        let encrypted = encrypt_key(&secret_key, passphrase).expect("encryption should succeed");
        let bytes = encrypted.to_bytes();

        // Verify format
        assert_eq!(bytes.len(), 77);
        assert_eq!(bytes[0], ENCRYPTION_VERSION);
        assert_eq!(&bytes[1..17], &encrypted.salt);
        assert_eq!(&bytes[17..29], &encrypted.nonce);
        assert_eq!(&bytes[29..], &encrypted.ciphertext[..]);
    }

    #[test]
    fn test_empty_passphrase() {
        let secret_key = SecretKey::generate();
        let passphrase = "";

        // Empty passphrase should still work (though not recommended)
        let encrypted = encrypt_key(&secret_key, passphrase).expect("encryption should succeed");
        let decrypted = decrypt_key(&encrypted, passphrase).expect("decryption should succeed");

        assert_eq!(secret_key.as_bytes(), decrypted.as_bytes());
    }

    #[test]
    fn test_unicode_passphrase() {
        let secret_key = SecretKey::generate();
        let passphrase = "test passphrase with unicode: \u{1F512}";

        let encrypted = encrypt_key(&secret_key, passphrase).expect("encryption should succeed");
        let decrypted = decrypt_key(&encrypted, passphrase).expect("decryption should succeed");

        assert_eq!(secret_key.as_bytes(), decrypted.as_bytes());
    }

    #[test]
    fn test_long_passphrase() {
        let secret_key = SecretKey::generate();
        let passphrase = "a".repeat(10000);

        let encrypted = encrypt_key(&secret_key, &passphrase).expect("encryption should succeed");
        let decrypted = decrypt_key(&encrypted, &passphrase).expect("decryption should succeed");

        assert_eq!(secret_key.as_bytes(), decrypted.as_bytes());
    }

    #[test]
    fn test_version_check_on_decrypt() {
        let encrypted = EncryptedKey {
            version: 2, // Unsupported version
            salt: [0u8; SALT_LEN],
            nonce: [0u8; NONCE_LEN],
            ciphertext: vec![0u8; PLAINTEXT_LEN + TAG_LEN],
        };

        let result = decrypt_key(&encrypted, "passphrase");
        assert!(result.is_err());
        assert!(matches!(result, Err(StoreError::InvalidFormat)));
    }

    #[test]
    fn test_ciphertext_length_validation() {
        let encrypted = EncryptedKey {
            version: ENCRYPTION_VERSION,
            salt: [0u8; SALT_LEN],
            nonce: [0u8; NONCE_LEN],
            ciphertext: vec![0u8; 10], // Too short
        };

        let result = decrypt_key(&encrypted, "passphrase");
        assert!(result.is_err());
        assert!(matches!(result, Err(StoreError::InvalidFormat)));
    }

    #[test]
    fn test_encrypted_key_debug() {
        let secret_key = SecretKey::generate();
        let encrypted = encrypt_key(&secret_key, "passphrase").expect("encryption should succeed");

        // Debug should not panic and should produce some output
        let debug_output = format!("{encrypted:?}");
        assert!(debug_output.contains("EncryptedKey"));
    }

    #[test]
    fn test_encrypted_key_clone() {
        let secret_key = SecretKey::generate();
        let encrypted = encrypt_key(&secret_key, "passphrase").expect("encryption should succeed");

        let cloned = encrypted.clone();
        assert_eq!(encrypted.version, cloned.version);
        assert_eq!(encrypted.salt, cloned.salt);
        assert_eq!(encrypted.nonce, cloned.nonce);
        assert_eq!(encrypted.ciphertext, cloned.ciphertext);
    }

    // Test Send + Sync traits
    #[test]
    fn test_encrypted_key_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<EncryptedKey>();
    }

    // Test that encryption constants are correct
    #[test]
    fn test_encryption_constants() {
        assert_eq!(ENCRYPTION_VERSION, 1);
        assert_eq!(SALT_LEN, 16);
        assert_eq!(NONCE_LEN, 12);
        assert_eq!(TAG_LEN, 16);
        assert_eq!(PLAINTEXT_LEN, 32);
        assert_eq!(ENCRYPTED_KEY_LEN, 77);
    }

    // ------------------------------------------------------------------------
    // Key Derivation Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_derive_key_deterministic() {
        // Same passphrase and salt should produce the same key
        let passphrase = "test passphrase";
        let salt = [0x42u8; SALT_LEN];

        let key1 = derive_key(passphrase, &salt).expect("derivation should succeed");
        let key2 = derive_key(passphrase, &salt).expect("derivation should succeed");

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_derive_key_different_salts() {
        let passphrase = "test passphrase";
        let salt1 = [0x42u8; SALT_LEN];
        let salt2 = [0x43u8; SALT_LEN];

        let key1 = derive_key(passphrase, &salt1).expect("derivation should succeed");
        let key2 = derive_key(passphrase, &salt2).expect("derivation should succeed");

        // Different salts should produce different keys
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_derive_key_different_passphrases() {
        let salt = [0x42u8; SALT_LEN];

        let key1 = derive_key("passphrase1", &salt).expect("derivation should succeed");
        let key2 = derive_key("passphrase2", &salt).expect("derivation should succeed");

        // Different passphrases should produce different keys
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_derive_key_empty_passphrase() {
        let salt = [0x42u8; SALT_LEN];

        // Empty passphrase should still work (though not recommended)
        let result = derive_key("", &salt);
        assert!(result.is_ok());
    }

    #[test]
    fn test_derive_key_output_length() {
        let passphrase = "test";
        let salt = [0x00u8; SALT_LEN];

        let key = derive_key(passphrase, &salt).expect("derivation should succeed");

        // Output should always be 32 bytes
        assert_eq!(key.len(), 32);
    }

    // ------------------------------------------------------------------------
    // Additional Edge Case Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_encrypted_key_from_bytes_empty() {
        let result = EncryptedKey::from_bytes(&[]);
        assert!(matches!(result, Err(StoreError::InvalidFormat)));
    }

    #[test]
    fn test_encrypted_key_version_field() {
        let secret_key = SecretKey::generate();
        let encrypted = encrypt_key(&secret_key, "test").expect("encryption should succeed");

        assert_eq!(encrypted.version, ENCRYPTION_VERSION);
    }

    #[test]
    fn test_decrypt_with_invalid_ciphertext_length() {
        let encrypted = EncryptedKey {
            version: ENCRYPTION_VERSION,
            salt: [0u8; SALT_LEN],
            nonce: [0u8; NONCE_LEN],
            ciphertext: vec![0u8; 10], // Wrong length (should be 48)
        };

        let result = decrypt_key(&encrypted, "passphrase");
        assert!(matches!(result, Err(StoreError::InvalidFormat)));
    }

    #[test]
    fn test_decrypt_with_valid_length_but_wrong_data() {
        let encrypted = EncryptedKey {
            version: ENCRYPTION_VERSION,
            salt: [0u8; SALT_LEN],
            nonce: [0u8; NONCE_LEN],
            ciphertext: vec![0u8; PLAINTEXT_LEN + TAG_LEN], // Correct length but garbage data
        };

        let result = decrypt_key(&encrypted, "passphrase");
        assert!(matches!(result, Err(StoreError::DecryptionFailed)));
    }
}
