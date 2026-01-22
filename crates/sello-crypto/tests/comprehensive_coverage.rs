//! Comprehensive integration tests for sello-crypto to achieve 100% coverage.
//!
//! This test suite focuses on:
//! - Edge cases and error paths
//! - Integration between modules
//! - Security-critical behavior verification
//! - Platform-specific code paths

#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use sello_core::error::{SignError, StoreError};
use sello_crypto::{
    decrypt_key, encrypt_key,
    keypair::{KeyPair, Secp256k1KeyPair, Secp256k1Signature},
    keys::{SecretKey, SecretKeyError},
    signer::{Chain, CurveType, Secp256k1Signer, Signer},
    store::{FileKeyStore, KeyStore},
    EncryptedKey, ENCRYPTED_KEY_LEN, ENCRYPTION_VERSION, NONCE_LEN, PLAINTEXT_LEN, SALT_LEN,
    TAG_LEN,
};
use tempfile::TempDir;

// ============================================================================
// SecretKeyError Coverage Tests
// ============================================================================

#[test]
fn test_secret_key_error_is_error_trait() {
    // Verify that SecretKeyError implements std::error::Error
    let error = SecretKeyError::InvalidKey;
    let _error_string = error.to_string();

    // Test that it can be used as a trait object
    let _boxed: Box<dyn std::error::Error> = Box::new(error);
}

#[test]
fn test_secret_key_error_clone() {
    let error = SecretKeyError::InvalidKey;
    let cloned = error;
    assert_eq!(error, cloned);
}

#[test]
fn test_secret_key_error_copy() {
    let error = SecretKeyError::InvalidKey;
    let copied = error;
    // Both should be usable
    assert_eq!(error, copied);
    assert_eq!(format!("{}", error), format!("{}", copied));
}

#[test]
fn test_secret_key_error_debug() {
    let error = SecretKeyError::InvalidKey;
    let debug_str = format!("{:?}", error);
    assert!(debug_str.contains("InvalidKey"));
}

// ============================================================================
// SecretKey Advanced Tests
// ============================================================================

#[test]
fn test_secret_key_into_k256_consumes_self() {
    // This test verifies that into_k256 consumes the SecretKey,
    // preventing accidental duplication of key material
    let key = SecretKey::generate();
    let _k256_key = key.into_k256().expect("valid key");
    // key is now consumed and cannot be used
}

#[test]
fn test_secret_key_from_array_explicit() {
    let bytes = [0x42u8; 32];
    let key: SecretKey = bytes.into();
    assert_eq!(key.as_bytes(), &bytes);
}

#[test]
fn test_secret_key_eq_trait_symmetric() {
    let key1 = SecretKey::new([0x42u8; 32]);
    let key2 = SecretKey::new([0x42u8; 32]);

    // Test symmetry of equality
    assert_eq!(key1, key2);
    assert_eq!(key2, key1);
}

#[test]
fn test_secret_key_eq_trait_transitive() {
    let key1 = SecretKey::new([0x42u8; 32]);
    let key2 = SecretKey::new([0x42u8; 32]);
    let key3 = SecretKey::new([0x42u8; 32]);

    // Test transitivity: if a == b and b == c, then a == c
    assert_eq!(key1, key2);
    assert_eq!(key2, key3);
    assert_eq!(key1, key3);
}

// ============================================================================
// KeyPair Signature Verification Edge Cases
// ============================================================================

#[test]
fn test_verify_with_invalid_signature_bytes() {
    let keypair = Secp256k1KeyPair::generate();
    let hash = [0x42u8; 32];

    // Create an invalid signature (all zeros, which is invalid)
    let invalid_sig = Secp256k1Signature::from_bytes_and_recovery_id([0u8; 64], 0);

    // Verification should fail
    assert!(!keypair.verify(&hash, &invalid_sig));
}

#[test]
fn test_verify_with_malformed_signature() {
    let keypair = Secp256k1KeyPair::generate();
    let hash = [0x42u8; 32];

    // Create a signature with invalid values (all 0xFF)
    let malformed_sig = Secp256k1Signature::from_bytes_and_recovery_id([0xFFu8; 64], 1);

    // Verification should fail gracefully
    assert!(!keypair.verify(&hash, &malformed_sig));
}

#[test]
fn test_verify_signature_from_different_key() {
    let keypair1 = Secp256k1KeyPair::generate();
    let keypair2 = Secp256k1KeyPair::generate();
    let hash = [0x42u8; 32];

    // Sign with keypair1
    let signature = keypair1.sign(&hash).expect("signing should succeed");

    // Verify with keypair2 should fail
    assert!(!keypair2.verify(&hash, &signature));
}

#[test]
fn test_signature_r_s_components_correctness() {
    let keypair = Secp256k1KeyPair::generate();
    let hash = [0x42u8; 32];
    let signature = keypair.sign(&hash).expect("signing should succeed");

    let r = signature.r();
    let s = signature.s();

    // Verify that r and s are exactly 32 bytes each
    assert_eq!(r.len(), 32);
    assert_eq!(s.len(), 32);

    // Verify they combine to form the full signature
    let mut combined = Vec::new();
    combined.extend_from_slice(r);
    combined.extend_from_slice(s);
    assert_eq!(combined.as_slice(), signature.as_ref());
}

// ============================================================================
// Signer Error Message Tests
// ============================================================================

#[test]
fn test_bitcoin_error_message_content() {
    let signer = Secp256k1Signer::generate();
    let result = signer.address(Chain::Bitcoin);

    match result {
        Err(SignError::SignatureFailed { context }) => {
            assert!(context.contains("Bitcoin"));
            assert!(context.contains("not yet implemented"));
        }
        _ => panic!("Expected SignatureFailed error"),
    }
}

#[test]
fn test_tron_error_message_content() {
    let signer = Secp256k1Signer::generate();
    let result = signer.address(Chain::Tron);

    match result {
        Err(SignError::SignatureFailed { context }) => {
            assert!(context.contains("Tron"));
            assert!(context.contains("not yet implemented"));
        }
        _ => panic!("Expected SignatureFailed error"),
    }
}

#[test]
fn test_ripple_error_message_content() {
    let signer = Secp256k1Signer::generate();
    let result = signer.address(Chain::Ripple);

    match result {
        Err(SignError::SignatureFailed { context }) => {
            assert!(context.contains("Ripple"));
            assert!(context.contains("not yet implemented"));
        }
        _ => panic!("Expected SignatureFailed error"),
    }
}

#[test]
fn test_solana_wrong_curve_error_details() {
    let signer = Secp256k1Signer::generate();
    let result = signer.address(Chain::Solana);

    match result {
        Err(SignError::WrongCurve { expected, actual }) => {
            assert_eq!(expected, "ed25519");
            assert_eq!(actual, "secp256k1");
        }
        _ => panic!("Expected WrongCurve error"),
    }
}

// ============================================================================
// Chain and CurveType Enum Coverage
// ============================================================================

#[test]
fn test_chain_enum_hash() {
    use std::collections::HashSet;

    let mut set = HashSet::new();
    set.insert(Chain::Ethereum);
    set.insert(Chain::Bitcoin);
    set.insert(Chain::Solana);

    assert!(set.contains(&Chain::Ethereum));
    assert!(!set.contains(&Chain::Tron));
}

#[test]
fn test_curve_type_enum_hash() {
    use std::collections::HashSet;

    let mut set = HashSet::new();
    set.insert(CurveType::Secp256k1);
    set.insert(CurveType::Ed25519);

    assert!(set.contains(&CurveType::Secp256k1));
    assert_eq!(set.len(), 2);
}

#[test]
fn test_curve_type_debug() {
    let debug_str = format!("{:?}", CurveType::Secp256k1);
    assert_eq!(debug_str, "Secp256k1");
}

// ============================================================================
// Encryption Edge Cases
// ============================================================================

#[test]
fn test_encrypted_key_from_bytes_exact_boundary() {
    // Test with exactly the right length but invalid version
    let mut bytes = vec![0u8; ENCRYPTED_KEY_LEN];
    bytes[0] = ENCRYPTION_VERSION;

    // This should parse successfully (though decryption will fail)
    let result = EncryptedKey::from_bytes(&bytes);
    assert!(result.is_ok());
}

#[test]
fn test_encrypted_key_from_bytes_off_by_one_short() {
    let bytes = vec![0u8; ENCRYPTED_KEY_LEN - 1];
    let result = EncryptedKey::from_bytes(&bytes);
    assert!(matches!(result, Err(StoreError::InvalidFormat)));
}

#[test]
fn test_encrypted_key_from_bytes_off_by_one_long() {
    let bytes = vec![0u8; ENCRYPTED_KEY_LEN + 1];
    let result = EncryptedKey::from_bytes(&bytes);
    assert!(matches!(result, Err(StoreError::InvalidFormat)));
}

#[test]
fn test_encrypted_key_constants_correctness() {
    // Verify that the constants add up correctly
    let expected_total = 1 + SALT_LEN + NONCE_LEN + PLAINTEXT_LEN + TAG_LEN;
    assert_eq!(ENCRYPTED_KEY_LEN, expected_total);
    assert_eq!(expected_total, 77);
}

#[test]
fn test_encrypt_decrypt_with_very_long_passphrase() {
    let key = SecretKey::generate();
    let long_passphrase = "a".repeat(100_000);

    let encrypted = encrypt_key(&key, &long_passphrase).expect("encryption should succeed");
    let decrypted = decrypt_key(&encrypted, &long_passphrase).expect("decryption should succeed");

    assert_eq!(key.as_bytes(), decrypted.as_bytes());
}

#[test]
fn test_encrypted_key_serialization_preserves_all_fields() {
    let key = SecretKey::generate();
    let encrypted = encrypt_key(&key, "test").expect("encryption should succeed");

    let bytes = encrypted.to_bytes();
    let deserialized = EncryptedKey::from_bytes(&bytes).expect("deserialization should succeed");

    assert_eq!(encrypted.version, deserialized.version);
    assert_eq!(encrypted.salt, deserialized.salt);
    assert_eq!(encrypted.nonce, deserialized.nonce);
    assert_eq!(encrypted.ciphertext, deserialized.ciphertext);
}

// ============================================================================
// KeyStore Edge Cases
// ============================================================================

#[test]
fn test_keystore_list_with_only_temp_files() {
    let temp_dir = TempDir::new().expect("failed to create temp dir");
    let store =
        FileKeyStore::with_path(temp_dir.path().to_path_buf()).expect("failed to create store");

    // Create only temp files (they should be ignored)
    std::fs::write(temp_dir.path().join(".temp1.tmp"), b"data").expect("write failed");
    std::fs::write(temp_dir.path().join(".temp2.tmp"), b"data").expect("write failed");

    let keys = store.list().expect("list should succeed");
    assert!(keys.is_empty());
}

#[test]
fn test_keystore_invalid_name_underscore_only() {
    let temp_dir = TempDir::new().expect("failed to create temp dir");
    let store =
        FileKeyStore::with_path(temp_dir.path().to_path_buf()).expect("failed to create store");

    // Single underscore should be valid
    let result = store.store("_", &SecretKey::generate(), "test");
    assert!(result.is_ok());
}

#[test]
fn test_keystore_invalid_name_hyphen_only() {
    let temp_dir = TempDir::new().expect("failed to create temp dir");
    let store =
        FileKeyStore::with_path(temp_dir.path().to_path_buf()).expect("failed to create store");

    // Single hyphen should be valid
    let result = store.store("-", &SecretKey::generate(), "test");
    assert!(result.is_ok());
}

#[test]
fn test_keystore_name_validation_comprehensive() {
    let temp_dir = TempDir::new().expect("failed to create temp dir");
    let store =
        FileKeyStore::with_path(temp_dir.path().to_path_buf()).expect("failed to create store");

    // Test various edge cases
    let test_cases = vec![
        ("a", true),        // Single letter - valid
        ("1", true),        // Single digit - valid
        ("a1", true),       // Alphanumeric - valid
        ("a-b", true),      // With hyphen - valid
        ("a_b", true),      // With underscore - valid
        ("ABC", true),      // Uppercase - valid
        ("test123", true),  // Mixed - valid
        ("", false),        // Empty - invalid
        (".", false),       // Just dot - invalid
        (".hidden", false), // Starts with dot - invalid
        ("a.b", false),     // Contains dot - invalid
        ("a b", false),     // Contains space - invalid
        ("a/b", false),     // Contains slash - invalid
        ("a\\b", false),    // Contains backslash - invalid
    ];

    for (name, should_succeed) in test_cases {
        let result = store.store(name, &SecretKey::generate(), "test");

        if should_succeed {
            assert!(result.is_ok(), "Name '{}' should be valid", name);
            // Clean up
            let _ = store.delete(name);
        } else {
            assert!(result.is_err(), "Name '{}' should be invalid", name);
        }
    }
}

#[test]
fn test_keystore_exists_with_deleted_key() {
    let temp_dir = TempDir::new().expect("failed to create temp dir");
    let store =
        FileKeyStore::with_path(temp_dir.path().to_path_buf()).expect("failed to create store");

    store
        .store("temp-key", &SecretKey::generate(), "test")
        .expect("store should succeed");

    assert!(store.exists("temp-key"));

    store.delete("temp-key").expect("delete should succeed");

    assert!(!store.exists("temp-key"));
}

#[test]
fn test_keystore_keys_dir_accessor() {
    let temp_dir = TempDir::new().expect("failed to create temp dir");
    let path = temp_dir.path().to_path_buf();
    let store = FileKeyStore::with_path(path.clone()).expect("failed to create store");

    assert_eq!(store.keys_dir(), &path);
}

// ============================================================================
// Integration Tests - Cross-Module Scenarios
// ============================================================================

#[test]
fn test_full_key_lifecycle_integration() {
    // This test exercises the full lifecycle of a key:
    // Generate -> Store -> Load -> Use for Signing -> Delete

    let temp_dir = TempDir::new().expect("failed to create temp dir");
    let store =
        FileKeyStore::with_path(temp_dir.path().to_path_buf()).expect("failed to create store");

    // 1. Generate a key
    let secret_key = SecretKey::generate();

    // 2. Store it
    store
        .store("lifecycle-test", &secret_key, "secure-passphrase")
        .expect("store should succeed");

    // 3. Load it back
    let loaded_key = store
        .load("lifecycle-test", "secure-passphrase")
        .expect("load should succeed");

    // 4. Use it for signing
    let signer =
        Secp256k1Signer::from_bytes(*loaded_key.as_bytes()).expect("failed to create signer");

    let hash = [0x42u8; 32];
    let signature = signer.sign(&hash).expect("signing should succeed");
    assert_eq!(signature.len(), 65);

    // 5. Get address
    let address = signer
        .address(Chain::Ethereum)
        .expect("address derivation should succeed");
    assert!(address.starts_with("0x"));

    // 6. Delete the key
    store
        .delete("lifecycle-test")
        .expect("delete should succeed");
    assert!(!store.exists("lifecycle-test"));
}

#[test]
fn test_multiple_keys_different_passphrases_integration() {
    let temp_dir = TempDir::new().expect("failed to create temp dir");
    let store =
        FileKeyStore::with_path(temp_dir.path().to_path_buf()).expect("failed to create store");

    // Store multiple keys with different passphrases
    let key1 = SecretKey::generate();
    let key2 = SecretKey::generate();
    let key3 = SecretKey::generate();

    store
        .store("key1", &key1, "pass1")
        .expect("store should succeed");
    store
        .store("key2", &key2, "pass2")
        .expect("store should succeed");
    store
        .store("key3", &key3, "pass3")
        .expect("store should succeed");

    // Load each with its correct passphrase
    let loaded1 = store.load("key1", "pass1").expect("load should succeed");
    let loaded2 = store.load("key2", "pass2").expect("load should succeed");
    let loaded3 = store.load("key3", "pass3").expect("load should succeed");

    assert_eq!(key1.as_bytes(), loaded1.as_bytes());
    assert_eq!(key2.as_bytes(), loaded2.as_bytes());
    assert_eq!(key3.as_bytes(), loaded3.as_bytes());

    // Verify wrong passphrases fail
    assert!(store.load("key1", "wrong").is_err());
    assert!(store.load("key2", "wrong").is_err());
    assert!(store.load("key3", "wrong").is_err());
}

#[test]
fn test_keypair_from_secret_key_integration() {
    let secret = SecretKey::generate();
    let keypair =
        Secp256k1KeyPair::from_secret_key(&secret).expect("keypair creation should succeed");

    // Verify we can use the keypair for signing
    let hash = [0x42u8; 32];
    let signature = keypair.sign(&hash).expect("signing should succeed");

    // Verify the signature
    assert!(keypair.verify(&hash, &signature));
}

#[test]
fn test_signer_key_pair_accessor() {
    let signer = Secp256k1Signer::generate();
    let keypair = signer.key_pair();

    // Verify that the keypair's public key matches the signer's
    assert_eq!(keypair.public_key().compressed(), signer.public_key());
}

#[test]
fn test_signature_components_roundtrip() {
    let keypair = Secp256k1KeyPair::generate();
    let hash = [0x42u8; 32];
    let signature = keypair.sign(&hash).expect("signing should succeed");

    // Extract components
    let r = *signature.r();
    let s = *signature.s();
    let v = signature.recovery_id();

    // Reconstruct
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(&r);
    bytes[32..].copy_from_slice(&s);

    let reconstructed = Secp256k1Signature::from_bytes_and_recovery_id(bytes, v);

    // Verify they're equivalent
    assert_eq!(signature.as_ref(), reconstructed.as_ref());
    assert_eq!(signature.recovery_id(), reconstructed.recovery_id());
}

// ============================================================================
// Public Key Format Tests
// ============================================================================

#[test]
fn test_public_key_clone() {
    use sello_crypto::keypair::Secp256k1PublicKey;

    let keypair = Secp256k1KeyPair::generate();
    let pubkey = keypair.public_key();

    // Secp256k1PublicKey implements Clone
    let cloned: Secp256k1PublicKey = pubkey.clone();

    assert_eq!(pubkey.compressed(), cloned.compressed());
    assert_eq!(pubkey.uncompressed(), cloned.uncompressed());
}

#[test]
fn test_signature_clone() {
    let keypair = Secp256k1KeyPair::generate();
    let hash = [0x42u8; 32];
    let signature = keypair.sign(&hash).expect("signing should succeed");

    // Secp256k1Signature implements Clone
    let cloned = signature.clone();

    assert_eq!(signature.as_ref(), cloned.as_ref());
    assert_eq!(signature.recovery_id(), cloned.recovery_id());
}

// ============================================================================
// Error Display Tests
// ============================================================================

#[test]
fn test_sign_error_wrong_curve_display() {
    let error = SignError::WrongCurve {
        expected: "ed25519".to_string(),
        actual: "secp256k1".to_string(),
    };

    let display_str = format!("{}", error);
    assert!(display_str.contains("ed25519"));
    assert!(display_str.contains("secp256k1"));
}

#[test]
fn test_sign_error_signature_failed_display() {
    let error = SignError::signature_failed("test failure");
    let display_str = format!("{}", error);
    assert!(display_str.contains("test failure"));
}

// ============================================================================
// Constant Verification Tests
// ============================================================================

#[test]
fn test_encryption_version_is_one() {
    assert_eq!(ENCRYPTION_VERSION, 1);
}

#[test]
fn test_salt_len_is_sixteen() {
    assert_eq!(SALT_LEN, 16);
}

#[test]
fn test_nonce_len_is_twelve() {
    assert_eq!(NONCE_LEN, 12);
}

#[test]
fn test_tag_len_is_sixteen() {
    assert_eq!(TAG_LEN, 16);
}

#[test]
fn test_plaintext_len_is_thirtytwo() {
    assert_eq!(PLAINTEXT_LEN, 32);
}
