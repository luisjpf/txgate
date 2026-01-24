//! Transaction history tracking with `SQLite` persistence.
//!
//! This module provides a transaction history system backed by `SQLite` for tracking
//! daily spending and enabling rate limiting in the policy engine.
//!
//! # Features
//!
//! - Persistent storage using `SQLite`
//! - Connection pooling via `r2d2`
//! - LRU caching with TTL for daily totals
//! - Thread-safe operations
//! - Automatic cleanup of old transactions
//!
//! # Example
//!
//! ```no_run
//! use sello_policy::history::TransactionHistory;
//! use alloy_primitives::U256;
//! use std::path::Path;
//!
//! // Create history with file-based database
//! let history = TransactionHistory::new(Path::new("/path/to/history.db")).unwrap();
//!
//! // Record a transaction
//! history.record("ETH", U256::from(1_000_000_000_000_000_000u64), "0xabc123").unwrap();
//!
//! // Get daily total
//! let total = history.daily_total("ETH").unwrap();
//! ```

use alloy_primitives::U256;
use lru::LruCache;
use r2d2::{Pool, PooledConnection};
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::params;
use sello_core::error::StoreError;
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Cache entry containing the daily total and when it was last updated.
type CacheEntry = (U256, Instant);

/// Default cache capacity (maximum number of tokens to cache).
const DEFAULT_CACHE_CAPACITY: usize = 100;

/// Cache TTL in seconds.
const CACHE_TTL_SECS: u64 = 60;

/// 24 hours in seconds.
const SECONDS_IN_DAY: i64 = 24 * 60 * 60;

/// A record of a single transaction in the history.
#[derive(Debug, Clone)]
pub struct TransactionRecord {
    /// Unique identifier for this record.
    pub id: i64,
    /// Token symbol (e.g., "ETH", "USDC").
    pub token: String,
    /// Transaction amount in the token's smallest unit.
    pub amount: U256,
    /// Unix timestamp when the transaction was recorded.
    pub timestamp: i64,
    /// Transaction hash for reference.
    pub tx_hash: String,
}

/// Transaction history tracker backed by `SQLite`.
///
/// Provides persistent storage for transaction history with connection pooling
/// and caching for efficient daily total queries.
///
/// # Thread Safety
///
/// This struct is `Send + Sync` and can be safely shared across threads.
/// The connection pool handles concurrent database access, and the LRU cache
/// is protected by a mutex.
pub struct TransactionHistory {
    /// Connection pool for `SQLite` database access.
    pool: Pool<SqliteConnectionManager>,
    /// LRU cache for daily totals, protected by a mutex.
    /// Key: token symbol, Value: (`daily_total`, `last_updated`)
    cache: Mutex<LruCache<String, CacheEntry>>,
}

impl TransactionHistory {
    /// Creates a new transaction history with a file-based database.
    ///
    /// # Arguments
    ///
    /// * `db_path` - Path to the `SQLite` database file
    ///
    /// # Errors
    ///
    /// Returns `StoreError::IoError` if the database cannot be opened or initialized.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use sello_policy::history::TransactionHistory;
    /// use std::path::Path;
    ///
    /// let history = TransactionHistory::new(Path::new("~/.sello/history.db")).unwrap();
    /// ```
    pub fn new(db_path: &Path) -> Result<Self, StoreError> {
        let manager = SqliteConnectionManager::file(db_path);
        Self::from_manager(manager)
    }

    /// Creates a new transaction history with an in-memory database.
    ///
    /// This is primarily useful for testing, as the database will not persist
    /// after the `TransactionHistory` is dropped.
    ///
    /// # Errors
    ///
    /// Returns `StoreError::IoError` if the database cannot be initialized.
    ///
    /// # Example
    ///
    /// ```
    /// use sello_policy::history::TransactionHistory;
    ///
    /// let history = TransactionHistory::in_memory().unwrap();
    /// ```
    pub fn in_memory() -> Result<Self, StoreError> {
        let manager = SqliteConnectionManager::memory();
        Self::from_manager(manager)
    }

    /// Internal constructor from a connection manager.
    fn from_manager(manager: SqliteConnectionManager) -> Result<Self, StoreError> {
        let pool = Pool::builder()
            .max_size(10)
            .build(manager)
            .map_err(|e| StoreError::IoError(std::io::Error::other(e.to_string())))?;

        let history = Self {
            pool,
            cache: Mutex::new(LruCache::new(
                NonZeroUsize::new(DEFAULT_CACHE_CAPACITY).unwrap_or(NonZeroUsize::MIN),
            )),
        };

        history.init_schema()?;
        Ok(history)
    }

    /// Gets a connection from the pool.
    fn get_conn(&self) -> Result<PooledConnection<SqliteConnectionManager>, StoreError> {
        self.pool
            .get()
            .map_err(|e| StoreError::IoError(std::io::Error::other(e.to_string())))
    }

    /// Initializes the database schema.
    fn init_schema(&self) -> Result<(), StoreError> {
        let conn = self.get_conn()?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT NOT NULL,
                amount TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                tx_hash TEXT NOT NULL
            )",
            [],
        )
        .map_err(|e| StoreError::IoError(std::io::Error::other(e.to_string())))?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_token_timestamp ON history(token, timestamp)",
            [],
        )
        .map_err(|e| StoreError::IoError(std::io::Error::other(e.to_string())))?;

        Ok(())
    }

    /// Records a transaction in the history.
    ///
    /// This method also invalidates the cache for the affected token to ensure
    /// subsequent `daily_total` calls return accurate results.
    ///
    /// # Arguments
    ///
    /// * `token` - Token symbol (e.g., "ETH", "USDC")
    /// * `amount` - Transaction amount in the token's smallest unit
    /// * `tx_hash` - Transaction hash for reference
    ///
    /// # Errors
    ///
    /// Returns `StoreError::IoError` if the database operation fails.
    ///
    /// # Example
    ///
    /// ```
    /// use sello_policy::history::TransactionHistory;
    /// use alloy_primitives::U256;
    ///
    /// let history = TransactionHistory::in_memory().unwrap();
    /// history.record("ETH", U256::from(1_000_000_000_000_000_000u64), "0xabc123").unwrap();
    /// ```
    pub fn record(&self, token: &str, amount: U256, tx_hash: &str) -> Result<(), StoreError> {
        let conn = self.get_conn()?;
        let timestamp = current_unix_timestamp();
        let amount_hex = format!("{amount:#x}");

        conn.execute(
            "INSERT INTO history (token, amount, timestamp, tx_hash) VALUES (?1, ?2, ?3, ?4)",
            params![token, amount_hex, timestamp, tx_hash],
        )
        .map_err(|e| StoreError::IoError(std::io::Error::other(e.to_string())))?;

        // Invalidate cache for this token
        if let Ok(mut cache) = self.cache.lock() {
            cache.pop(token);
        }

        Ok(())
    }

    /// Gets the total amount for a token in the last 24 hours.
    ///
    /// This method uses caching to improve performance. Cached values are
    /// returned if they are less than 60 seconds old.
    ///
    /// # Arguments
    ///
    /// * `token` - Token symbol to query
    ///
    /// # Errors
    ///
    /// Returns `StoreError::IoError` if the database operation fails.
    ///
    /// # Example
    ///
    /// ```
    /// use sello_policy::history::TransactionHistory;
    /// use alloy_primitives::U256;
    ///
    /// let history = TransactionHistory::in_memory().unwrap();
    /// history.record("ETH", U256::from(1_000_000_000_000_000_000u64), "0xabc123").unwrap();
    ///
    /// let total = history.daily_total("ETH").unwrap();
    /// assert_eq!(total, U256::from(1_000_000_000_000_000_000u64));
    /// ```
    pub fn daily_total(&self, token: &str) -> Result<U256, StoreError> {
        // Check cache first
        if let Ok(mut cache) = self.cache.lock() {
            if let Some((total, last_updated)) = cache.get(token) {
                if last_updated.elapsed() < Duration::from_secs(CACHE_TTL_SECS) {
                    return Ok(*total);
                }
            }
        }

        // Cache miss or expired, query database
        let conn = self.get_conn()?;
        let cutoff = current_unix_timestamp() - SECONDS_IN_DAY;

        let mut stmt = conn
            .prepare("SELECT amount FROM history WHERE token = ?1 AND timestamp > ?2")
            .map_err(|e| StoreError::IoError(std::io::Error::other(e.to_string())))?;

        let amounts = stmt
            .query_map(params![token, cutoff], |row| {
                let amount_hex: String = row.get(0)?;
                Ok(amount_hex)
            })
            .map_err(|e| StoreError::IoError(std::io::Error::other(e.to_string())))?;

        let mut total = U256::ZERO;
        for amount_result in amounts {
            let amount_hex = amount_result
                .map_err(|e| StoreError::IoError(std::io::Error::other(e.to_string())))?;

            let amount = parse_u256_hex(&amount_hex)
                .map_err(|e| StoreError::IoError(std::io::Error::other(e)))?;

            total = total.saturating_add(amount);
        }

        // Update cache
        if let Ok(mut cache) = self.cache.lock() {
            cache.put(token.to_string(), (total, Instant::now()));
        }

        Ok(total)
    }

    /// Cleans up transactions older than 24 hours.
    ///
    /// # Returns
    ///
    /// The number of transactions that were removed.
    ///
    /// # Errors
    ///
    /// Returns `StoreError::IoError` if the database operation fails.
    ///
    /// # Example
    ///
    /// ```
    /// use sello_policy::history::TransactionHistory;
    ///
    /// let history = TransactionHistory::in_memory().unwrap();
    /// let removed = history.cleanup().unwrap();
    /// ```
    pub fn cleanup(&self) -> Result<usize, StoreError> {
        let conn = self.get_conn()?;
        let cutoff = current_unix_timestamp() - SECONDS_IN_DAY;

        let removed = conn
            .execute("DELETE FROM history WHERE timestamp <= ?1", params![cutoff])
            .map_err(|e| StoreError::IoError(std::io::Error::other(e.to_string())))?;

        Ok(removed)
    }

    /// Gets all transactions for a token, limited to the most recent entries.
    ///
    /// Transactions are returned in descending order by timestamp (newest first).
    ///
    /// # Arguments
    ///
    /// * `token` - Token symbol to query
    /// * `limit` - Maximum number of transactions to return
    ///
    /// # Errors
    ///
    /// Returns `StoreError::IoError` if the database operation fails.
    ///
    /// # Example
    ///
    /// ```
    /// use sello_policy::history::TransactionHistory;
    /// use alloy_primitives::U256;
    ///
    /// let history = TransactionHistory::in_memory().unwrap();
    /// history.record("ETH", U256::from(1_000_000_000_000_000_000u64), "0xabc123").unwrap();
    ///
    /// let transactions = history.get_transactions("ETH", 10).unwrap();
    /// assert_eq!(transactions.len(), 1);
    /// ```
    pub fn get_transactions(
        &self,
        token: &str,
        limit: usize,
    ) -> Result<Vec<TransactionRecord>, StoreError> {
        let conn = self.get_conn()?;

        let mut stmt = conn
            .prepare(
                "SELECT id, token, amount, timestamp, tx_hash
                 FROM history
                 WHERE token = ?1
                 ORDER BY timestamp DESC
                 LIMIT ?2",
            )
            .map_err(|e| StoreError::IoError(std::io::Error::other(e.to_string())))?;

        let limit_i64 = i64::try_from(limit).unwrap_or(i64::MAX);

        let records = stmt
            .query_map(params![token, limit_i64], |row| {
                let id: i64 = row.get(0)?;
                let token: String = row.get(1)?;
                let amount_hex: String = row.get(2)?;
                let timestamp: i64 = row.get(3)?;
                let tx_hash: String = row.get(4)?;

                Ok((id, token, amount_hex, timestamp, tx_hash))
            })
            .map_err(|e| StoreError::IoError(std::io::Error::other(e.to_string())))?;

        let mut transactions = Vec::new();
        for record_result in records {
            let (id, token, amount_hex, timestamp, tx_hash) = record_result
                .map_err(|e| StoreError::IoError(std::io::Error::other(e.to_string())))?;

            let amount = parse_u256_hex(&amount_hex)
                .map_err(|e| StoreError::IoError(std::io::Error::other(e)))?;

            transactions.push(TransactionRecord {
                id,
                token,
                amount,
                timestamp,
                tx_hash,
            });
        }

        Ok(transactions)
    }
}

/// Gets the current Unix timestamp in seconds.
fn current_unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Parses a U256 from a hex string (with or without 0x prefix).
fn parse_u256_hex(hex_str: &str) -> Result<U256, String> {
    let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    U256::from_str_radix(stripped, 16)
        .map_err(|e| format!("failed to parse U256 from hex '{hex_str}': {e}"))
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
        clippy::unreadable_literal,
        clippy::stable_sort_primitive,
        clippy::useless_vec
    )]

    use super::*;
    use std::thread;
    use tempfile::tempdir;

    #[test]
    fn test_record_and_daily_total() {
        let history = TransactionHistory::in_memory().unwrap();

        // Record some transactions
        history
            .record("ETH", U256::from(1_000_000_000_000_000_000u64), "0xabc123")
            .unwrap();
        history
            .record("ETH", U256::from(500_000_000_000_000_000u64), "0xdef456")
            .unwrap();
        history
            .record("USDC", U256::from(1_000_000u64), "0x789abc")
            .unwrap();

        // Check daily totals
        let eth_total = history.daily_total("ETH").unwrap();
        assert_eq!(eth_total, U256::from(1_500_000_000_000_000_000u64));

        let usdc_total = history.daily_total("USDC").unwrap();
        assert_eq!(usdc_total, U256::from(1_000_000u64));

        // Non-existent token should return zero
        let btc_total = history.daily_total("BTC").unwrap();
        assert_eq!(btc_total, U256::ZERO);
    }

    #[test]
    fn test_cleanup_removes_old_transactions() {
        let history = TransactionHistory::in_memory().unwrap();

        // Insert a transaction with an old timestamp directly
        let conn = history.get_conn().unwrap();
        let old_timestamp = current_unix_timestamp() - SECONDS_IN_DAY - 1;
        conn.execute(
            "INSERT INTO history (token, amount, timestamp, tx_hash) VALUES (?1, ?2, ?3, ?4)",
            params!["ETH", "0x1", old_timestamp, "0xold"],
        )
        .unwrap();

        // Record a current transaction
        history
            .record("ETH", U256::from(1_000_000_000_000_000_000u64), "0xnew")
            .unwrap();

        // Verify both exist
        let transactions = history.get_transactions("ETH", 10).unwrap();
        assert_eq!(transactions.len(), 2);

        // Cleanup
        let removed = history.cleanup().unwrap();
        assert_eq!(removed, 1);

        // Verify only new transaction remains
        let transactions = history.get_transactions("ETH", 10).unwrap();
        assert_eq!(transactions.len(), 1);
        assert_eq!(transactions.first().unwrap().tx_hash, "0xnew");
    }

    #[test]
    fn test_in_memory_database_works() {
        let history = TransactionHistory::in_memory().unwrap();

        history.record("ETH", U256::from(1u64), "0x123").unwrap();

        let total = history.daily_total("ETH").unwrap();
        assert_eq!(total, U256::from(1u64));
    }

    #[test]
    fn test_persistence() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("history.db");

        // Write data
        {
            let history = TransactionHistory::new(&db_path).unwrap();
            history
                .record("ETH", U256::from(1_000_000_000_000_000_000u64), "0xabc123")
                .unwrap();
        }

        // Read data in new instance
        {
            let history = TransactionHistory::new(&db_path).unwrap();
            let total = history.daily_total("ETH").unwrap();
            assert_eq!(total, U256::from(1_000_000_000_000_000_000u64));
        }
    }

    #[test]
    fn test_concurrent_access() {
        use std::sync::Arc;

        let history = Arc::new(TransactionHistory::in_memory().unwrap());
        let mut handles = vec![];

        // Spawn multiple threads recording transactions
        for i in 0..10 {
            let history_clone = Arc::clone(&history);
            let handle = thread::spawn(move || {
                history_clone
                    .record("ETH", U256::from(100u64), &format!("0x{i:032x}"))
                    .unwrap();
            });
            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }

        // Verify total
        let total = history.daily_total("ETH").unwrap();
        assert_eq!(total, U256::from(1000u64));
    }

    #[test]
    fn test_cache_invalidation() {
        let history = TransactionHistory::in_memory().unwrap();

        // Record first transaction
        history.record("ETH", U256::from(100u64), "0x1").unwrap();

        // Get cached total
        let total1 = history.daily_total("ETH").unwrap();
        assert_eq!(total1, U256::from(100u64));

        // Record another transaction (should invalidate cache)
        history.record("ETH", U256::from(200u64), "0x2").unwrap();

        // Total should reflect new transaction
        let total2 = history.daily_total("ETH").unwrap();
        assert_eq!(total2, U256::from(300u64));
    }

    #[test]
    fn test_get_transactions() {
        let history = TransactionHistory::in_memory().unwrap();

        // Record multiple transactions
        history.record("ETH", U256::from(100u64), "0x1").unwrap();
        history.record("ETH", U256::from(200u64), "0x2").unwrap();
        history.record("ETH", U256::from(300u64), "0x3").unwrap();

        // Get all transactions
        let transactions = history.get_transactions("ETH", 10).unwrap();
        assert_eq!(transactions.len(), 3);

        // Verify newest is first
        assert_eq!(transactions.first().unwrap().tx_hash, "0x3");
        assert_eq!(transactions.first().unwrap().amount, U256::from(300u64));

        // Test limit
        let limited = history.get_transactions("ETH", 2).unwrap();
        assert_eq!(limited.len(), 2);
    }

    #[test]
    fn test_transaction_record_fields() {
        let history = TransactionHistory::in_memory().unwrap();

        history
            .record("USDC", U256::from(1_000_000u64), "0xdeadbeef")
            .unwrap();

        let transactions = history.get_transactions("USDC", 1).unwrap();
        let record = transactions.first().unwrap();

        assert!(record.id > 0);
        assert_eq!(record.token, "USDC");
        assert_eq!(record.amount, U256::from(1_000_000u64));
        assert!(record.timestamp > 0);
        assert_eq!(record.tx_hash, "0xdeadbeef");
    }

    #[test]
    fn test_large_amounts() {
        let history = TransactionHistory::in_memory().unwrap();

        // Test with very large U256 values
        let large_amount = U256::from(u128::MAX);
        history.record("ETH", large_amount, "0xlarge").unwrap();

        let total = history.daily_total("ETH").unwrap();
        assert_eq!(total, large_amount);

        // Test saturating addition
        history.record("ETH", large_amount, "0xlarge2").unwrap();

        let total2 = history.daily_total("ETH").unwrap();
        assert_eq!(total2, large_amount.saturating_add(large_amount));
    }

    #[test]
    fn test_empty_database() {
        let history = TransactionHistory::in_memory().unwrap();

        // Daily total for non-existent token
        let total = history.daily_total("NONEXISTENT").unwrap();
        assert_eq!(total, U256::ZERO);

        // Get transactions for non-existent token
        let transactions = history.get_transactions("NONEXISTENT", 10).unwrap();
        assert!(transactions.is_empty());

        // Cleanup on empty database
        let removed = history.cleanup().unwrap();
        assert_eq!(removed, 0);
    }

    #[test]
    fn test_parse_u256_hex() {
        // With 0x prefix
        assert_eq!(parse_u256_hex("0x1").unwrap(), U256::from(1u64));
        assert_eq!(parse_u256_hex("0xff").unwrap(), U256::from(255u64));
        assert_eq!(
            parse_u256_hex("0xde0b6b3a7640000").unwrap(),
            U256::from(1_000_000_000_000_000_000u64)
        );

        // Without prefix
        assert_eq!(parse_u256_hex("1").unwrap(), U256::from(1u64));
        assert_eq!(parse_u256_hex("ff").unwrap(), U256::from(255u64));

        // Invalid hex
        assert!(parse_u256_hex("0xGGG").is_err());
        assert!(parse_u256_hex("not_hex").is_err());
    }

    // =========================================================================
    // Additional coverage tests
    // =========================================================================

    mod additional_coverage_tests {
        use super::*;

        #[test]
        fn test_zero_amount_recording() {
            let history = TransactionHistory::in_memory().unwrap();

            // Record zero amount
            history.record("ETH", U256::ZERO, "0xzero").unwrap();

            let total = history.daily_total("ETH").unwrap();
            assert_eq!(total, U256::ZERO);

            let transactions = history.get_transactions("ETH", 1).unwrap();
            assert_eq!(transactions.len(), 1);
            assert_eq!(transactions.first().unwrap().amount, U256::ZERO);
        }

        #[test]
        fn test_multiple_tokens_isolated() {
            let history = TransactionHistory::in_memory().unwrap();

            // Record transactions for different tokens
            history.record("ETH", U256::from(100u64), "0xeth1").unwrap();
            history
                .record("USDC", U256::from(200u64), "0xusdc1")
                .unwrap();
            history.record("DAI", U256::from(300u64), "0xdai1").unwrap();
            history.record("ETH", U256::from(50u64), "0xeth2").unwrap();

            // Verify each token's total is isolated
            assert_eq!(history.daily_total("ETH").unwrap(), U256::from(150u64));
            assert_eq!(history.daily_total("USDC").unwrap(), U256::from(200u64));
            assert_eq!(history.daily_total("DAI").unwrap(), U256::from(300u64));
        }

        #[test]
        fn test_get_transactions_limit_zero() {
            let history = TransactionHistory::in_memory().unwrap();

            history.record("ETH", U256::from(100u64), "0x1").unwrap();
            history.record("ETH", U256::from(200u64), "0x2").unwrap();

            // Request 0 transactions
            let transactions = history.get_transactions("ETH", 0).unwrap();
            assert!(transactions.is_empty());
        }

        #[test]
        fn test_get_transactions_limit_exceeds_available() {
            let history = TransactionHistory::in_memory().unwrap();

            history.record("ETH", U256::from(100u64), "0x1").unwrap();
            history.record("ETH", U256::from(200u64), "0x2").unwrap();

            // Request more than available
            let transactions = history.get_transactions("ETH", 100).unwrap();
            assert_eq!(transactions.len(), 2);
        }

        #[test]
        fn test_get_transactions_large_limit() {
            let history = TransactionHistory::in_memory().unwrap();

            history.record("ETH", U256::from(100u64), "0x1").unwrap();

            // Request with very large limit (tests i64::MAX fallback)
            let transactions = history.get_transactions("ETH", usize::MAX).unwrap();
            assert_eq!(transactions.len(), 1);
        }

        #[test]
        fn test_cache_expiry_behavior() {
            let history = TransactionHistory::in_memory().unwrap();

            // Record a transaction
            history.record("ETH", U256::from(100u64), "0x1").unwrap();

            // First call populates cache
            let total1 = history.daily_total("ETH").unwrap();
            assert_eq!(total1, U256::from(100u64));

            // Second call within TTL uses cache (we can't easily test this without waiting,
            // but we can verify it doesn't error)
            let total2 = history.daily_total("ETH").unwrap();
            assert_eq!(total2, U256::from(100u64));

            // Record another transaction (invalidates cache)
            history.record("ETH", U256::from(50u64), "0x2").unwrap();

            // Next call should see updated total
            let total3 = history.daily_total("ETH").unwrap();
            assert_eq!(total3, U256::from(150u64));
        }

        #[test]
        fn test_cleanup_with_no_old_transactions() {
            let history = TransactionHistory::in_memory().unwrap();

            // Record current transactions
            history.record("ETH", U256::from(100u64), "0x1").unwrap();
            history.record("ETH", U256::from(200u64), "0x2").unwrap();

            // Cleanup should remove 0 transactions
            let removed = history.cleanup().unwrap();
            assert_eq!(removed, 0);

            // Transactions should still be there
            let total = history.daily_total("ETH").unwrap();
            assert_eq!(total, U256::from(300u64));
        }

        #[test]
        fn test_record_same_hash_multiple_times() {
            let history = TransactionHistory::in_memory().unwrap();

            // Record the same hash multiple times (should be allowed)
            history.record("ETH", U256::from(100u64), "0xsame").unwrap();
            history.record("ETH", U256::from(200u64), "0xsame").unwrap();

            // Both should be recorded
            let total = history.daily_total("ETH").unwrap();
            assert_eq!(total, U256::from(300u64));

            let transactions = history.get_transactions("ETH", 10).unwrap();
            assert_eq!(transactions.len(), 2);
        }

        #[test]
        fn test_transaction_record_id_increments() {
            let history = TransactionHistory::in_memory().unwrap();

            history.record("ETH", U256::from(100u64), "0x1").unwrap();
            history.record("ETH", U256::from(200u64), "0x2").unwrap();
            history.record("ETH", U256::from(300u64), "0x3").unwrap();

            let transactions = history.get_transactions("ETH", 10).unwrap();

            // IDs should be positive and unique
            let ids: Vec<i64> = transactions.iter().map(|t| t.id).collect();
            assert_eq!(ids.len(), 3);
            assert!(ids.iter().all(|&id| id > 0));

            // All IDs should be unique
            let mut sorted_ids = ids.clone();
            sorted_ids.sort();
            sorted_ids.dedup();
            assert_eq!(sorted_ids.len(), 3);
        }

        #[test]
        fn test_transaction_timestamp_is_current() {
            let history = TransactionHistory::in_memory().unwrap();

            let before = current_unix_timestamp();
            history.record("ETH", U256::from(100u64), "0x1").unwrap();
            let after = current_unix_timestamp();

            let transactions = history.get_transactions("ETH", 1).unwrap();
            let record = transactions.first().unwrap();

            // Timestamp should be between before and after
            assert!(record.timestamp >= before);
            assert!(record.timestamp <= after);
        }

        #[test]
        fn test_daily_total_accumulation_precision() {
            let history = TransactionHistory::in_memory().unwrap();

            // Record many small transactions to test accumulation
            for i in 1..=100 {
                history
                    .record("ETH", U256::from(i), &format!("0x{i:032x}"))
                    .unwrap();
            }

            // Sum of 1..=100 is 5050
            let total = history.daily_total("ETH").unwrap();
            assert_eq!(total, U256::from(5050u64));
        }

        #[test]
        fn test_parse_u256_hex_edge_cases() {
            // Zero
            assert_eq!(parse_u256_hex("0x0").unwrap(), U256::ZERO);
            assert_eq!(parse_u256_hex("0").unwrap(), U256::ZERO);

            // Leading zeros
            assert_eq!(parse_u256_hex("0x00001").unwrap(), U256::from(1u64));
            assert_eq!(parse_u256_hex("00001").unwrap(), U256::from(1u64));

            // Mixed case
            assert_eq!(parse_u256_hex("0xAbCdEf").unwrap(), U256::from(11259375u64));
            assert_eq!(parse_u256_hex("AbCdEf").unwrap(), U256::from(11259375u64));

            // Empty string (strip_prefix returns empty string, which parses as 0)
            assert_eq!(parse_u256_hex("").unwrap(), U256::ZERO);
            assert_eq!(parse_u256_hex("0x").unwrap(), U256::ZERO);

            // Special characters should error
            assert!(parse_u256_hex("0x-123").is_err());
            assert!(parse_u256_hex("0x+123").is_err());
            assert!(parse_u256_hex("0x 123").is_err());
        }

        #[test]
        fn test_parse_u256_hex_large_values() {
            // Test with max U256 value
            let max_hex = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
            assert_eq!(parse_u256_hex(&format!("0x{max_hex}")).unwrap(), U256::MAX);
            assert_eq!(parse_u256_hex(max_hex).unwrap(), U256::MAX);
        }

        #[test]
        fn test_transaction_record_clone() {
            let record = TransactionRecord {
                id: 1,
                token: "ETH".to_string(),
                amount: U256::from(100u64),
                timestamp: 123456789,
                tx_hash: "0xabc".to_string(),
            };

            let cloned = record.clone();
            assert_eq!(record.id, cloned.id);
            assert_eq!(record.token, cloned.token);
            assert_eq!(record.amount, cloned.amount);
            assert_eq!(record.timestamp, cloned.timestamp);
            assert_eq!(record.tx_hash, cloned.tx_hash);
        }

        #[test]
        fn test_transaction_record_debug() {
            let record = TransactionRecord {
                id: 42,
                token: "USDC".to_string(),
                amount: U256::from(1_000_000u64),
                timestamp: 1234567890,
                tx_hash: "0xdeadbeef".to_string(),
            };

            let debug_str = format!("{record:?}");
            assert!(debug_str.contains("TransactionRecord"));
            assert!(debug_str.contains("42"));
            assert!(debug_str.contains("USDC"));
            assert!(debug_str.contains("0xdeadbeef"));
        }

        #[test]
        fn test_special_token_names() {
            let history = TransactionHistory::in_memory().unwrap();

            // Test with various token name formats
            let tokens = vec![
                "ETH",
                "BTC",
                "USDC",
                "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                "wrapped-eth",
                "token.with.dots",
                "TOKEN_WITH_UNDERSCORES",
            ];

            for (i, token) in tokens.iter().enumerate() {
                history
                    .record(token, U256::from((i + 1) as u64 * 100), &format!("0x{i}"))
                    .unwrap();
            }

            // Verify each token total
            for (i, token) in tokens.iter().enumerate() {
                let total = history.daily_total(token).unwrap();
                assert_eq!(total, U256::from((i + 1) as u64 * 100));
            }
        }

        #[test]
        fn test_get_transactions_ordering() {
            let history = TransactionHistory::in_memory().unwrap();

            // Record transactions with slight delays to ensure ordering
            history
                .record("ETH", U256::from(100u64), "0xfirst")
                .unwrap();
            history
                .record("ETH", U256::from(200u64), "0xsecond")
                .unwrap();
            history
                .record("ETH", U256::from(300u64), "0xthird")
                .unwrap();

            let transactions = history.get_transactions("ETH", 10).unwrap();

            // Should be in descending timestamp order (newest first)
            assert_eq!(transactions.len(), 3);
            assert_eq!(transactions.first().unwrap().tx_hash, "0xthird");
            assert_eq!(transactions.last().unwrap().tx_hash, "0xfirst");

            // Timestamps should be descending
            assert!(
                transactions.first().unwrap().timestamp >= transactions.last().unwrap().timestamp
            );
        }

        #[test]
        fn test_daily_total_for_multiple_tokens_with_same_prefix() {
            let history = TransactionHistory::in_memory().unwrap();

            // Use tokens that share prefixes to test proper isolation
            history.record("ETH", U256::from(100u64), "0x1").unwrap();
            history.record("ETHX", U256::from(200u64), "0x2").unwrap();
            history
                .record("ETHEREUM", U256::from(300u64), "0x3")
                .unwrap();

            assert_eq!(history.daily_total("ETH").unwrap(), U256::from(100u64));
            assert_eq!(history.daily_total("ETHX").unwrap(), U256::from(200u64));
            assert_eq!(history.daily_total("ETHEREUM").unwrap(), U256::from(300u64));
        }

        #[test]
        fn test_current_unix_timestamp_is_positive() {
            let timestamp = current_unix_timestamp();
            assert!(timestamp > 0);

            // Should be a reasonable value (after 2020)
            assert!(timestamp > 1577836800); // Jan 1, 2020
        }

        #[test]
        fn test_saturating_addition_in_daily_total() {
            let history = TransactionHistory::in_memory().unwrap();

            // Record transactions that would overflow if not using saturating_add
            let large_value = U256::MAX - U256::from(100u64);
            history.record("ETH", large_value, "0x1").unwrap();
            history.record("ETH", U256::from(200u64), "0x2").unwrap();

            // Total should saturate at MAX, not wrap around
            let total = history.daily_total("ETH").unwrap();
            assert_eq!(total, U256::MAX);
        }
    }
}
