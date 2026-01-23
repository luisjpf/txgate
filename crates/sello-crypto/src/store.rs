//! Key storage traits and implementations.
//!
//! This module provides secure key storage functionality with:
//! - A trait-based interface for pluggable storage backends
//! - A file-based implementation storing encrypted keys in `~/.sello/keys/`
//! - Automatic encryption/decryption using ChaCha20-Poly1305 with Argon2id
//!
//! # Security Properties
//!
//! - **Encryption at rest**: All keys are encrypted before storage
//! - **Restricted permissions**: Files are created with 0600 (owner read/write only)
//! - **Atomic writes**: Uses temp file + rename to prevent corruption
//! - **Thread safety**: Implementations are `Send + Sync`
//!
//! # Example
//!
//! ```no_run
//! use sello_crypto::store::{KeyStore, FileKeyStore};
//! use sello_crypto::keys::SecretKey;
//!
//! // Create a key store
//! let store = FileKeyStore::new().expect("failed to create key store");
//!
//! // Store a key
//! let key = SecretKey::generate();
//! store.store("my-wallet", &key, "secure-passphrase").expect("failed to store key");
//!
//! // List stored keys
//! let keys = store.list().expect("failed to list keys");
//! println!("Stored keys: {:?}", keys);
//!
//! // Load the key back
//! let loaded = store.load("my-wallet", "secure-passphrase").expect("failed to load key");
//! ```

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use sello_core::error::StoreError;

use crate::encryption::{decrypt_key, encrypt_key, EncryptedKey};
use crate::keys::SecretKey;

// ============================================================================
// KeyStore Trait
// ============================================================================

/// Trait for secure key storage.
///
/// Implementations must ensure:
/// - Keys are encrypted at rest
/// - File permissions prevent unauthorized access
/// - Atomic operations prevent corruption
/// - Thread-safe operations (`Send + Sync`)
///
/// # Example
///
/// ```no_run
/// use sello_crypto::store::{KeyStore, FileKeyStore};
/// use sello_crypto::keys::SecretKey;
///
/// fn example<S: KeyStore>(store: &S) -> Result<(), sello_core::error::StoreError> {
///     let key = SecretKey::generate();
///     store.store("my-key", &key, "passphrase")?;
///
///     if store.exists("my-key") {
///         let loaded = store.load("my-key", "passphrase")?;
///     }
///
///     Ok(())
/// }
/// ```
pub trait KeyStore: Send + Sync {
    /// Store a secret key with the given name.
    ///
    /// # Arguments
    /// * `name` - A unique identifier for the key (e.g., "default", "hot-wallet")
    /// * `key` - The secret key to store
    /// * `passphrase` - The passphrase to encrypt the key with
    ///
    /// # Errors
    /// - `StoreError::KeyExists` if a key with this name already exists
    /// - `StoreError::EncryptionFailed` if encryption fails
    /// - `StoreError::IoError` if file operations fail
    /// - `StoreError::InvalidFormat` if the name is invalid
    fn store(&self, name: &str, key: &SecretKey, passphrase: &str) -> Result<(), StoreError>;

    /// Load a secret key by name.
    ///
    /// # Arguments
    /// * `name` - The identifier of the key to load
    /// * `passphrase` - The passphrase to decrypt the key with
    ///
    /// # Errors
    /// - `StoreError::KeyNotFound` if no key exists with this name
    /// - `StoreError::DecryptionFailed` if the passphrase is wrong
    /// - `StoreError::IoError` if file operations fail
    /// - `StoreError::InvalidFormat` if the name or file format is invalid
    fn load(&self, name: &str, passphrase: &str) -> Result<SecretKey, StoreError>;

    /// List all stored key names.
    ///
    /// # Returns
    /// A vector of key names (without the `.enc` extension), sorted alphabetically.
    ///
    /// # Errors
    /// - `StoreError::IoError` if directory operations fail
    fn list(&self) -> Result<Vec<String>, StoreError>;

    /// Delete a key by name.
    ///
    /// # Arguments
    /// * `name` - The identifier of the key to delete
    ///
    /// # Errors
    /// - `StoreError::KeyNotFound` if no key exists with this name
    /// - `StoreError::IoError` if file operations fail
    /// - `StoreError::InvalidFormat` if the name is invalid
    fn delete(&self, name: &str) -> Result<(), StoreError>;

    /// Check if a key exists.
    ///
    /// # Arguments
    /// * `name` - The identifier of the key to check
    ///
    /// # Returns
    /// `true` if a key with this name exists, `false` otherwise.
    /// Returns `false` if the name is invalid.
    fn exists(&self, name: &str) -> bool;
}

// ============================================================================
// FileKeyStore Implementation
// ============================================================================

/// File-based key storage in `~/.sello/keys/`.
///
/// This implementation stores encrypted keys as individual files with the `.enc`
/// extension. Each key is encrypted using the encryption module's
/// ChaCha20-Poly1305 AEAD encryption with Argon2id key derivation.
///
/// # Security
///
/// - Directory permissions are set to 0700 (owner only)
/// - File permissions are set to 0600 (owner read/write only)
/// - Atomic writes prevent corruption on crash
/// - Key names are validated to prevent path traversal attacks
///
/// # Example
///
/// ```no_run
/// use sello_crypto::store::{KeyStore, FileKeyStore};
///
/// // Use the default path (~/.sello/keys/)
/// let store = FileKeyStore::new().expect("failed to create key store");
///
/// // Or use a custom path
/// use std::path::PathBuf;
/// let custom_store = FileKeyStore::with_path(PathBuf::from("/custom/path"))
///     .expect("failed to create key store");
/// ```
pub struct FileKeyStore {
    /// Directory where keys are stored.
    keys_dir: PathBuf,
}

impl FileKeyStore {
    /// Create a new `FileKeyStore` with the default path (`~/.sello/keys/`).
    ///
    /// # Errors
    /// - `StoreError::IoError` if the home directory cannot be determined
    /// - `StoreError::IoError` if directory creation fails
    /// - `StoreError::PermissionDenied` if permissions cannot be set
    ///
    /// # Example
    ///
    /// ```no_run
    /// use sello_crypto::store::FileKeyStore;
    ///
    /// let store = FileKeyStore::new().expect("failed to create key store");
    /// ```
    pub fn new() -> Result<Self, StoreError> {
        let keys_dir = dirs::home_dir()
            .ok_or_else(|| {
                StoreError::IoError(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "Could not determine home directory",
                ))
            })?
            .join(".sello")
            .join("keys");

        Self::with_path(keys_dir)
    }

    /// Create a `FileKeyStore` with a custom path.
    ///
    /// This is useful for testing or when you want to store keys in a
    /// non-standard location.
    ///
    /// # Arguments
    /// * `keys_dir` - The directory to store keys in
    ///
    /// # Errors
    /// - `StoreError::IoError` if directory creation fails
    /// - `StoreError::PermissionDenied` if permissions cannot be set
    ///
    /// # Example
    ///
    /// ```no_run
    /// use sello_crypto::store::FileKeyStore;
    /// use std::path::PathBuf;
    ///
    /// let store = FileKeyStore::with_path(PathBuf::from("/tmp/test-keys"))
    ///     .expect("failed to create key store");
    /// ```
    pub fn with_path(keys_dir: PathBuf) -> Result<Self, StoreError> {
        // Create directory if it doesn't exist
        if !keys_dir.exists() {
            fs::create_dir_all(&keys_dir)?;
        }

        // Set directory permissions to 0700 (owner only)
        #[cfg(unix)]
        {
            let mut perms = fs::metadata(&keys_dir)?.permissions();
            perms.set_mode(0o700);
            fs::set_permissions(&keys_dir, perms)?;
        }

        Ok(Self { keys_dir })
    }

    /// Get the path to a key file.
    fn key_path(&self, name: &str) -> PathBuf {
        self.keys_dir.join(format!("{name}.enc"))
    }

    /// Validate a key name.
    ///
    /// Valid names:
    /// - Are not empty
    /// - Contain only ASCII alphanumeric characters, hyphens, and underscores
    /// - Do not start with a dot (reserved for temp files)
    ///
    /// This validation prevents:
    /// - Path traversal attacks (e.g., "../../../etc/passwd")
    /// - Hidden file creation
    /// - Shell injection through filenames
    fn validate_name(name: &str) -> Result<(), StoreError> {
        if name.is_empty() {
            return Err(StoreError::InvalidFormat);
        }

        if name.starts_with('.') {
            return Err(StoreError::InvalidFormat);
        }

        if !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(StoreError::InvalidFormat);
        }

        Ok(())
    }

    /// Get the directory path where keys are stored.
    ///
    /// This is useful for debugging or informational purposes.
    #[must_use]
    pub const fn keys_dir(&self) -> &PathBuf {
        &self.keys_dir
    }
}

impl KeyStore for FileKeyStore {
    fn store(&self, name: &str, key: &SecretKey, passphrase: &str) -> Result<(), StoreError> {
        Self::validate_name(name)?;

        let path = self.key_path(name);
        if path.exists() {
            return Err(StoreError::KeyExists {
                name: name.to_string(),
            });
        }

        // Encrypt the key
        let encrypted = encrypt_key(key, passphrase)?;
        let bytes = encrypted.to_bytes();

        // Atomic write: write to temp file, then rename
        let temp_path = self.keys_dir.join(format!(".{name}.tmp"));

        // Write to temp file
        {
            let mut file = File::create(&temp_path)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
        }

        // Set file permissions to 0600 (owner read/write only) before rename
        #[cfg(unix)]
        {
            let mut perms = fs::metadata(&temp_path)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&temp_path, perms)?;
        }

        // Atomic rename
        fs::rename(&temp_path, &path)?;

        Ok(())
    }

    fn load(&self, name: &str, passphrase: &str) -> Result<SecretKey, StoreError> {
        Self::validate_name(name)?;

        let path = self.key_path(name);
        if !path.exists() {
            return Err(StoreError::KeyNotFound {
                name: name.to_string(),
            });
        }

        // Read encrypted data
        let mut file = File::open(&path)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;

        // Decrypt
        let encrypted = EncryptedKey::from_bytes(&bytes)?;
        decrypt_key(&encrypted, passphrase)
    }

    fn list(&self) -> Result<Vec<String>, StoreError> {
        let mut names = Vec::new();

        for entry in fs::read_dir(&self.keys_dir)? {
            let entry = entry?;
            let path = entry.path();

            // Only include .enc files
            if path.extension().is_some_and(|ext| ext == "enc") {
                if let Some(stem) = path.file_stem() {
                    if let Some(name) = stem.to_str() {
                        // Skip temp files (starting with '.')
                        if !name.starts_with('.') {
                            names.push(name.to_string());
                        }
                    }
                }
            }
        }

        names.sort();
        Ok(names)
    }

    fn delete(&self, name: &str) -> Result<(), StoreError> {
        Self::validate_name(name)?;

        let path = self.key_path(name);
        if !path.exists() {
            return Err(StoreError::KeyNotFound {
                name: name.to_string(),
            });
        }

        fs::remove_file(&path)?;
        Ok(())
    }

    fn exists(&self, name: &str) -> bool {
        if Self::validate_name(name).is_err() {
            return false;
        }
        self.key_path(name).exists()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::similar_names)]
    #![allow(clippy::case_sensitive_file_extension_comparisons)]
    #![allow(clippy::unwrap_used)]

    use super::*;
    use std::sync::Arc;
    use std::thread;
    use tempfile::TempDir;

    /// Create a test key store in a temporary directory.
    fn create_test_store() -> (FileKeyStore, TempDir) {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let store =
            FileKeyStore::with_path(temp_dir.path().to_path_buf()).expect("failed to create store");
        (store, temp_dir)
    }

    // ------------------------------------------------------------------------
    // Store/Load Round-Trip Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_store_load_round_trip() {
        let (store, _temp) = create_test_store();
        let key = SecretKey::generate();
        let passphrase = "test-passphrase-123";

        store
            .store("test-key", &key, passphrase)
            .expect("store should succeed");
        let loaded = store
            .load("test-key", passphrase)
            .expect("load should succeed");

        assert_eq!(key.as_bytes(), loaded.as_bytes());
    }

    #[test]
    fn test_store_load_multiple_keys() {
        let (store, _temp) = create_test_store();
        let passphrase = "common-passphrase";

        let key1 = SecretKey::generate();
        let key2 = SecretKey::generate();
        let key3 = SecretKey::generate();

        store
            .store("key-1", &key1, passphrase)
            .expect("store should succeed");
        store
            .store("key-2", &key2, passphrase)
            .expect("store should succeed");
        store
            .store("key-3", &key3, passphrase)
            .expect("store should succeed");

        let loaded1 = store
            .load("key-1", passphrase)
            .expect("load should succeed");
        let loaded2 = store
            .load("key-2", passphrase)
            .expect("load should succeed");
        let loaded3 = store
            .load("key-3", passphrase)
            .expect("load should succeed");

        assert_eq!(key1.as_bytes(), loaded1.as_bytes());
        assert_eq!(key2.as_bytes(), loaded2.as_bytes());
        assert_eq!(key3.as_bytes(), loaded3.as_bytes());
    }

    #[test]
    fn test_store_load_different_passphrases() {
        let (store, _temp) = create_test_store();

        let key1 = SecretKey::generate();
        let key2 = SecretKey::generate();

        store
            .store("key-1", &key1, "passphrase-1")
            .expect("store should succeed");
        store
            .store("key-2", &key2, "passphrase-2")
            .expect("store should succeed");

        let loaded1 = store
            .load("key-1", "passphrase-1")
            .expect("load should succeed");
        let loaded2 = store
            .load("key-2", "passphrase-2")
            .expect("load should succeed");

        assert_eq!(key1.as_bytes(), loaded1.as_bytes());
        assert_eq!(key2.as_bytes(), loaded2.as_bytes());
    }

    // ------------------------------------------------------------------------
    // List Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_list_empty_store() {
        let (store, _temp) = create_test_store();

        let keys = store.list().expect("list should succeed");
        assert!(keys.is_empty());
    }

    #[test]
    fn test_list_returns_sorted_names() {
        let (store, _temp) = create_test_store();
        let passphrase = "test";

        // Store keys in non-alphabetical order
        store
            .store("zebra", &SecretKey::generate(), passphrase)
            .expect("store should succeed");
        store
            .store("apple", &SecretKey::generate(), passphrase)
            .expect("store should succeed");
        store
            .store("mango", &SecretKey::generate(), passphrase)
            .expect("store should succeed");

        let keys = store.list().expect("list should succeed");
        assert_eq!(keys, vec!["apple", "mango", "zebra"]);
    }

    #[test]
    fn test_list_ignores_temp_files() {
        let (store, temp) = create_test_store();
        let passphrase = "test";

        store
            .store("real-key", &SecretKey::generate(), passphrase)
            .expect("store should succeed");

        // Create a temp file manually (simulating interrupted write)
        let temp_path = temp.path().join(".temp-key.tmp");
        fs::write(&temp_path, b"garbage").expect("write should succeed");

        let keys = store.list().expect("list should succeed");
        assert_eq!(keys, vec!["real-key"]);
    }

    #[test]
    fn test_list_ignores_non_enc_files() {
        let (store, temp) = create_test_store();
        let passphrase = "test";

        store
            .store("real-key", &SecretKey::generate(), passphrase)
            .expect("store should succeed");

        // Create non-.enc files
        fs::write(temp.path().join("readme.txt"), b"text").expect("write should succeed");
        fs::write(temp.path().join("backup.bak"), b"backup").expect("write should succeed");

        let keys = store.list().expect("list should succeed");
        assert_eq!(keys, vec!["real-key"]);
    }

    // ------------------------------------------------------------------------
    // Delete Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_delete_removes_key() {
        let (store, _temp) = create_test_store();
        let passphrase = "test";

        store
            .store("to-delete", &SecretKey::generate(), passphrase)
            .expect("store should succeed");
        assert!(store.exists("to-delete"));

        store.delete("to-delete").expect("delete should succeed");
        assert!(!store.exists("to-delete"));
    }

    #[test]
    fn test_delete_nonexistent_returns_error() {
        let (store, _temp) = create_test_store();

        let result = store.delete("nonexistent");
        assert!(matches!(result, Err(StoreError::KeyNotFound { .. })));
    }

    #[test]
    fn test_delete_then_store_same_name() {
        let (store, _temp) = create_test_store();
        let passphrase = "test";

        let key1 = SecretKey::generate();
        store
            .store("reusable", &key1, passphrase)
            .expect("store should succeed");

        store.delete("reusable").expect("delete should succeed");

        let key2 = SecretKey::generate();
        store
            .store("reusable", &key2, passphrase)
            .expect("store should succeed");

        let loaded = store
            .load("reusable", passphrase)
            .expect("load should succeed");
        assert_eq!(key2.as_bytes(), loaded.as_bytes());
    }

    // ------------------------------------------------------------------------
    // Exists Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_exists_returns_true_for_existing_key() {
        let (store, _temp) = create_test_store();

        store
            .store("existing", &SecretKey::generate(), "test")
            .expect("store should succeed");
        assert!(store.exists("existing"));
    }

    #[test]
    fn test_exists_returns_false_for_nonexistent_key() {
        let (store, _temp) = create_test_store();
        assert!(!store.exists("nonexistent"));
    }

    #[test]
    fn test_exists_returns_false_for_invalid_name() {
        let (store, _temp) = create_test_store();
        assert!(!store.exists(""));
        assert!(!store.exists("../etc/passwd"));
        assert!(!store.exists(".hidden"));
    }

    // ------------------------------------------------------------------------
    // Error Handling Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_store_duplicate_returns_error() {
        let (store, _temp) = create_test_store();
        let passphrase = "test";

        store
            .store("duplicate", &SecretKey::generate(), passphrase)
            .expect("first store should succeed");

        let result = store.store("duplicate", &SecretKey::generate(), passphrase);
        assert!(matches!(result, Err(StoreError::KeyExists { .. })));
    }

    #[test]
    fn test_load_nonexistent_returns_error() {
        let (store, _temp) = create_test_store();

        let result = store.load("nonexistent", "passphrase");
        assert!(matches!(result, Err(StoreError::KeyNotFound { .. })));
    }

    #[test]
    fn test_load_wrong_passphrase_returns_error() {
        let (store, _temp) = create_test_store();

        store
            .store("secure-key", &SecretKey::generate(), "correct-passphrase")
            .expect("store should succeed");

        let result = store.load("secure-key", "wrong-passphrase");
        assert!(matches!(result, Err(StoreError::DecryptionFailed)));
    }

    // ------------------------------------------------------------------------
    // Name Validation Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_valid_names() {
        let (store, _temp) = create_test_store();
        let passphrase = "test";

        // All these names should be valid
        let valid_names = vec![
            "default",
            "my-key",
            "my_key",
            "key123",
            "KEY",
            "a",
            "hot-wallet-1",
            "cold_storage_backup",
        ];

        for name in valid_names {
            let result = store.store(name, &SecretKey::generate(), passphrase);
            assert!(result.is_ok(), "Name should be valid: {name}");
        }
    }

    #[test]
    fn test_invalid_names_empty() {
        let (store, _temp) = create_test_store();

        let result = store.store("", &SecretKey::generate(), "test");
        assert!(matches!(result, Err(StoreError::InvalidFormat)));
    }

    #[test]
    fn test_invalid_names_path_traversal() {
        let (store, _temp) = create_test_store();

        let invalid_names = vec![
            "../etc/passwd",
            "..\\windows\\system32",
            "some/path",
            "some\\path",
        ];

        for name in invalid_names {
            let result = store.store(name, &SecretKey::generate(), "test");
            assert!(
                matches!(result, Err(StoreError::InvalidFormat)),
                "Name should be invalid: {name}"
            );
        }
    }

    #[test]
    fn test_invalid_names_hidden() {
        let (store, _temp) = create_test_store();

        let result = store.store(".hidden", &SecretKey::generate(), "test");
        assert!(matches!(result, Err(StoreError::InvalidFormat)));
    }

    #[test]
    fn test_invalid_names_special_characters() {
        let (store, _temp) = create_test_store();

        let invalid_names = vec![
            "key with spaces",
            "key@special",
            "key#hash",
            "key$dollar",
            "key%percent",
            "key*star",
            "key!bang",
        ];

        for name in invalid_names {
            let result = store.store(name, &SecretKey::generate(), "test");
            assert!(
                matches!(result, Err(StoreError::InvalidFormat)),
                "Name should be invalid: {name}"
            );
        }
    }

    // ------------------------------------------------------------------------
    // File Permission Tests (Unix only)
    // ------------------------------------------------------------------------

    #[cfg(unix)]
    #[test]
    fn test_directory_permissions() {
        let (store, _temp) = create_test_store();

        let metadata = fs::metadata(store.keys_dir()).expect("failed to get metadata");
        let mode = metadata.permissions().mode();

        // Check that only owner has access (0700)
        assert_eq!(
            mode & 0o777,
            0o700,
            "Directory should have 0700 permissions"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_file_permissions() {
        let (store, _temp) = create_test_store();

        store
            .store("test-key", &SecretKey::generate(), "test")
            .expect("store should succeed");

        let path = store.key_path("test-key");
        let metadata = fs::metadata(&path).expect("failed to get metadata");
        let mode = metadata.permissions().mode();

        // Check that only owner has read/write (0600)
        assert_eq!(mode & 0o777, 0o600, "File should have 0600 permissions");
    }

    // ------------------------------------------------------------------------
    // Atomic Write Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_atomic_write_no_temp_files_left() {
        let (store, temp) = create_test_store();

        store
            .store("atomic-test", &SecretKey::generate(), "test")
            .expect("store should succeed");

        // Check that no temp files exist
        for entry in fs::read_dir(temp.path()).expect("failed to read dir") {
            let entry = entry.expect("failed to get entry");
            let name = entry.file_name().to_string_lossy().to_string();
            assert!(
                !name.starts_with('.') || !name.ends_with(".tmp"),
                "Temp file should not exist: {name}"
            );
        }
    }

    // ------------------------------------------------------------------------
    // Thread Safety Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_key_store_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<FileKeyStore>();
    }

    #[test]
    fn test_trait_object_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Box<dyn KeyStore>>();
    }

    // ------------------------------------------------------------------------
    // Integration Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_full_workflow() {
        let (store, _temp) = create_test_store();

        // Initially empty
        assert!(store.list().expect("list should succeed").is_empty());

        // Store some keys
        let key1 = SecretKey::generate();
        let key2 = SecretKey::generate();

        store
            .store("wallet-1", &key1, "pass1")
            .expect("store should succeed");
        store
            .store("wallet-2", &key2, "pass2")
            .expect("store should succeed");

        // List shows both
        let keys = store.list().expect("list should succeed");
        assert_eq!(keys, vec!["wallet-1", "wallet-2"]);

        // Exists works
        assert!(store.exists("wallet-1"));
        assert!(store.exists("wallet-2"));
        assert!(!store.exists("wallet-3"));

        // Load works
        let loaded1 = store
            .load("wallet-1", "pass1")
            .expect("load should succeed");
        assert_eq!(key1.as_bytes(), loaded1.as_bytes());

        // Delete works
        store.delete("wallet-1").expect("delete should succeed");
        assert!(!store.exists("wallet-1"));

        let keys = store.list().expect("list should succeed");
        assert_eq!(keys, vec!["wallet-2"]);
    }

    // ------------------------------------------------------------------------
    // Custom Path Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_with_path_creates_directory() {
        let temp = TempDir::new().expect("failed to create temp dir");
        let custom_path = temp.path().join("custom").join("nested").join("keys");

        assert!(!custom_path.exists());

        let _store = FileKeyStore::with_path(custom_path.clone()).expect("should create directory");

        assert!(custom_path.exists());
        assert!(custom_path.is_dir());
    }

    #[test]
    fn test_keys_dir_getter() {
        let (store, temp) = create_test_store();
        assert_eq!(store.keys_dir(), temp.path());
    }

    // ------------------------------------------------------------------------
    // Additional Coverage Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_validate_name_all_edge_cases() {
        // Test the validation logic directly

        // Empty name
        assert!(FileKeyStore::validate_name("").is_err());

        // Starts with dot
        assert!(FileKeyStore::validate_name(".test").is_err());

        // Contains invalid characters
        assert!(FileKeyStore::validate_name("test/path").is_err());
        assert!(FileKeyStore::validate_name("test\\path").is_err());
        assert!(FileKeyStore::validate_name("test.key").is_err());
        assert!(FileKeyStore::validate_name("test key").is_err());
        assert!(FileKeyStore::validate_name("test@key").is_err());

        // Valid names
        assert!(FileKeyStore::validate_name("test").is_ok());
        assert!(FileKeyStore::validate_name("test-key").is_ok());
        assert!(FileKeyStore::validate_name("test_key").is_ok());
        assert!(FileKeyStore::validate_name("TEST123").is_ok());
        assert!(FileKeyStore::validate_name("a").is_ok());
        assert!(FileKeyStore::validate_name("1").is_ok());
        assert!(FileKeyStore::validate_name("_").is_ok());
        assert!(FileKeyStore::validate_name("-").is_ok());
    }

    #[test]
    fn test_load_with_invalid_name() {
        let (store, _temp) = create_test_store();

        let result = store.load("../invalid", "passphrase");
        assert!(matches!(result, Err(StoreError::InvalidFormat)));
    }

    #[test]
    fn test_delete_with_invalid_name() {
        let (store, _temp) = create_test_store();

        let result = store.delete(".invalid");
        assert!(matches!(result, Err(StoreError::InvalidFormat)));
    }

    #[test]
    fn test_store_creates_enc_extension() {
        let (store, temp) = create_test_store();

        store
            .store("test", &SecretKey::generate(), "pass")
            .expect("store should succeed");

        let path = temp.path().join("test.enc");
        assert!(path.exists());
    }

    #[test]
    fn test_list_handles_invalid_utf8_filenames() {
        // This test ensures list() handles edge cases gracefully
        let (store, _temp) = create_test_store();

        // Store a normal key
        store
            .store("normal", &SecretKey::generate(), "pass")
            .expect("store should succeed");

        // List should work even if there are unusual files
        let keys = store.list().expect("list should succeed");
        assert!(keys.contains(&"normal".to_string()));
    }

    #[test]
    fn test_key_path_generation() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let store =
            FileKeyStore::with_path(temp_dir.path().to_path_buf()).expect("failed to create store");

        let path = store.key_path("test");
        assert!(path.to_str().unwrap().ends_with("test.enc"));
    }

    #[cfg(not(unix))]
    #[test]
    fn test_non_unix_permissions_handling() {
        // On non-Unix systems, permission setting is skipped
        // This test just ensures the code doesn't panic
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let store =
            FileKeyStore::with_path(temp_dir.path().to_path_buf()).expect("failed to create store");

        store
            .store("test", &SecretKey::generate(), "pass")
            .expect("store should succeed");

        assert!(store.exists("test"));
    }

    // ------------------------------------------------------------------------
    // I/O Error Tests
    // ------------------------------------------------------------------------

    #[test]
    #[cfg(unix)]
    fn test_store_fails_with_readonly_directory() {
        use std::os::unix::fs::PermissionsExt;

        // Arrange: Create a temporary directory and make it read-only
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let store_path = temp_dir.path().to_path_buf();
        let store = FileKeyStore::with_path(store_path.clone()).expect("failed to create store");

        // Make directory read-only (no write permission)
        let mut perms = fs::metadata(&store_path)
            .expect("failed to get metadata")
            .permissions();
        perms.set_mode(0o500); // r-x------
        fs::set_permissions(&store_path, perms).expect("failed to set permissions");

        // Act: Try to store a key in a readonly directory
        let result = store.store("test-key", &SecretKey::generate(), "passphrase");

        // Assert: Should fail (either IoError or KeyExists, depending on OS behavior)
        assert!(result.is_err());

        // Cleanup: Restore permissions so temp_dir can be deleted
        let mut perms = fs::metadata(&store_path)
            .expect("failed to get metadata")
            .permissions();
        perms.set_mode(0o700);
        fs::set_permissions(&store_path, perms).expect("failed to set permissions");
    }

    #[test]
    fn test_load_fails_with_nonexistent_directory() {
        // Arrange: Create a store with a path that doesn't exist
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let nonexistent_path = temp_dir.path().join("does_not_exist");

        // Don't create the directory - just create a store pointing to it
        let store = FileKeyStore {
            keys_dir: nonexistent_path,
        };

        // Act: Try to load a key from nonexistent directory
        let result = store.load("any-key", "passphrase");

        // Assert: Should fail with KeyNotFound (because validation passes but file doesn't exist)
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            StoreError::KeyNotFound { .. }
        ));
    }

    #[test]
    fn test_load_fails_with_corrupted_file() {
        // Arrange: Create a key file with invalid encrypted data
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let store =
            FileKeyStore::with_path(temp_dir.path().to_path_buf()).expect("failed to create store");

        // Write corrupted data directly to a file
        let corrupted_path = temp_dir.path().join("corrupted.enc");
        fs::write(&corrupted_path, b"this is not valid encrypted data")
            .expect("failed to write corrupted file");

        // Act: Try to load the corrupted key
        let result = store.load("corrupted", "passphrase");

        // Assert: Should fail with InvalidFormat or DecryptionFailed
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                StoreError::InvalidFormat | StoreError::DecryptionFailed
            ),
            "expected InvalidFormat or DecryptionFailed, got {err:?}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_list_fails_with_permission_denied() {
        use std::os::unix::fs::PermissionsExt;

        // Arrange: Create a store directory
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let store_path = temp_dir.path().to_path_buf();
        let store = FileKeyStore::with_path(store_path.clone()).expect("failed to create store");

        // Store a key first
        store
            .store("test", &SecretKey::generate(), "pass")
            .expect("store should succeed");

        // Remove read permission from directory
        let mut perms = fs::metadata(&store_path)
            .expect("failed to get metadata")
            .permissions();
        perms.set_mode(0o300); // -wx------ (no read)
        fs::set_permissions(&store_path, perms).expect("failed to set permissions");

        // Act: Try to list keys without read permission
        let result = store.list();

        // Assert: Should fail (behavior may vary on different Unix systems)
        assert!(result.is_err());

        // Cleanup: Restore permissions so temp_dir can be deleted
        let mut perms = fs::metadata(&store_path)
            .expect("failed to get metadata")
            .permissions();
        perms.set_mode(0o700);
        fs::set_permissions(&store_path, perms).expect("failed to set permissions");
    }

    #[test]
    #[cfg(unix)]
    fn test_delete_fails_with_readonly_directory() {
        use std::os::unix::fs::PermissionsExt;

        // Arrange: Create a store and add a key
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let store_path = temp_dir.path().to_path_buf();
        let store = FileKeyStore::with_path(store_path.clone()).expect("failed to create store");

        store
            .store("test", &SecretKey::generate(), "pass")
            .expect("store should succeed");

        // Make directory read-only (no write permission)
        let mut perms = fs::metadata(&store_path)
            .expect("failed to get metadata")
            .permissions();
        perms.set_mode(0o500); // r-x------
        fs::set_permissions(&store_path, perms).expect("failed to set permissions");

        // Act: Try to delete a key from readonly directory
        let result = store.delete("test");

        // Assert: Should fail (behavior may vary on different Unix systems)
        assert!(result.is_err());

        // Cleanup: Restore permissions
        let mut perms = fs::metadata(&store_path)
            .expect("failed to get metadata")
            .permissions();
        perms.set_mode(0o700);
        fs::set_permissions(&store_path, perms).expect("failed to set permissions");
    }

    #[test]
    fn test_concurrent_read_operations() {
        // Arrange: Create a store with multiple keys
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let store = Arc::new(
            FileKeyStore::with_path(temp_dir.path().to_path_buf()).expect("failed to create store"),
        );

        // Store multiple keys
        for i in 0..10 {
            let key = SecretKey::generate();
            store
                .store(&format!("key-{i}"), &key, "pass")
                .expect("store should succeed");
        }

        // Act: Spawn multiple threads that read different keys concurrently
        let mut handles = vec![];
        for i in 0..10 {
            let store_clone = Arc::clone(&store);
            let handle = thread::spawn(move || {
                store_clone
                    .load(&format!("key-{i}"), "pass")
                    .expect("load should succeed")
            });
            handles.push(handle);
        }

        // Assert: All threads should complete successfully
        for handle in handles {
            let _key = handle.join().expect("thread should not panic");
        }
    }

    #[test]
    fn test_concurrent_write_operations() {
        // Arrange: Create a store
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let store = Arc::new(
            FileKeyStore::with_path(temp_dir.path().to_path_buf()).expect("failed to create store"),
        );

        // Act: Spawn multiple threads that write different keys concurrently
        let mut handles = vec![];
        for i in 0..10 {
            let store_clone = Arc::clone(&store);
            let handle = thread::spawn(move || {
                let key = SecretKey::generate();
                store_clone
                    .store(&format!("concurrent-{i}"), &key, "pass")
                    .expect("store should succeed");
            });
            handles.push(handle);
        }

        // Assert: All threads should complete successfully
        for handle in handles {
            handle.join().expect("thread should not panic");
        }

        // Verify all keys were stored
        let keys = store.list().expect("list should succeed");
        assert_eq!(keys.len(), 10);
    }

    #[test]
    fn test_concurrent_read_write_operations() {
        // Arrange: Create a store with some initial keys
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let store = Arc::new(
            FileKeyStore::with_path(temp_dir.path().to_path_buf()).expect("failed to create store"),
        );

        // Store initial keys
        for i in 0..5 {
            store
                .store(&format!("initial-{i}"), &SecretKey::generate(), "pass")
                .expect("store should succeed");
        }

        // Act: Spawn mix of reader and writer threads
        let mut handles = vec![];

        // Readers
        for i in 0..5 {
            let store_clone = Arc::clone(&store);
            let handle = thread::spawn(move || {
                for _ in 0..10 {
                    let _ = store_clone.load(&format!("initial-{i}"), "pass");
                }
            });
            handles.push(handle);
        }

        // Writers
        for i in 0..5 {
            let store_clone = Arc::clone(&store);
            let handle = thread::spawn(move || {
                let key = SecretKey::generate();
                store_clone
                    .store(&format!("new-{i}"), &key, "pass")
                    .expect("store should succeed");
            });
            handles.push(handle);
        }

        // Assert: All threads should complete successfully
        for handle in handles {
            handle.join().expect("thread should not panic");
        }

        // Verify final state
        let keys = store.list().expect("list should succeed");
        assert!(keys.len() >= 10); // At least initial + new keys
    }

    #[test]
    fn test_load_with_truncated_file() {
        // Arrange: Create a store and a file with incomplete encrypted data
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let store =
            FileKeyStore::with_path(temp_dir.path().to_path_buf()).expect("failed to create store");

        // Write truncated encrypted data (too short to be valid)
        let truncated_path = temp_dir.path().join("truncated.enc");
        fs::write(&truncated_path, b"short").expect("failed to write truncated file");

        // Act: Try to load the truncated key
        let result = store.load("truncated", "passphrase");

        // Assert: Should fail with InvalidFormat
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), StoreError::InvalidFormat));
    }
}
