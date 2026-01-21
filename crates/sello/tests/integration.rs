//! # Integration Tests for Sello
//!
//! This module contains integration tests that verify the behavior of Sello
//! components working together.
//!
//! ## Test Organization
//!
//! - `common/` - Shared test utilities and helpers
//! - `e2e/` - End-to-end integration tests
//!   - `sign_flow_test` - Full init -> sign flow tests
//!   - `policy_test` - Policy enforcement tests
//!
//! ## Running Tests
//!
//! ```bash
//! # Run all tests
//! cargo test
//!
//! # Run only integration tests
//! cargo test --test integration
//!
//! # Run specific integration test modules
//! cargo test --test integration sign_flow
//! cargo test --test integration policy_test
//!
//! # Run with coverage
//! cargo llvm-cov --html
//! ```

// Allow expect() in tests since panicking on failures is acceptable
#![allow(clippy::expect_used)]

mod common;
mod e2e;

#[cfg(test)]
mod tests {
    use super::common;

    #[test]
    fn test_fixture_loading() {
        // This test verifies that the fixture loading mechanism works correctly.
        // It loads a sample fixture and ensures the JSON is properly parsed.

        let fixture_path = "ethereum/legacy_transfer.json";
        let result = common::load_fixture(fixture_path);

        // Verify the fixture was loaded successfully
        assert!(result.is_ok(), "Failed to load fixture: {:?}", result.err());

        let fixture = result.expect("Fixture should be loaded");

        // Verify required fields exist
        assert!(
            fixture.get("description").is_some(),
            "Fixture should have 'description' field"
        );
        assert!(
            fixture.get("raw_tx").is_some(),
            "Fixture should have 'raw_tx' field"
        );
        assert!(
            fixture.get("expected").is_some(),
            "Fixture should have 'expected' field"
        );
    }

    #[test]
    fn test_temp_data_dir_creation() {
        // This test verifies that temporary data directories are created correctly
        // and are properly isolated for each test.

        let temp_dir = common::temp_data_dir();
        let path = temp_dir.path();

        // Verify the directory exists
        assert!(path.exists(), "Temp directory should exist");
        assert!(path.is_dir(), "Temp path should be a directory");

        // Verify we can write to it
        let test_file = path.join("test.txt");
        std::fs::write(&test_file, "test content").expect("Should be able to write to temp dir");
        assert!(test_file.exists(), "Test file should exist after writing");

        // Directory will be cleaned up when temp_dir is dropped
    }

    #[test]
    fn test_all_ethereum_fixtures_valid() {
        // This test ensures all Ethereum fixtures in the fixtures directory
        // have the correct structure and can be loaded.

        let ethereum_fixtures = ["legacy_transfer", "eip1559_transfer", "erc20_transfer"];

        for fixture_name in ethereum_fixtures {
            let path = format!("ethereum/{fixture_name}.json");
            let result = common::load_fixture(&path);
            assert!(
                result.is_ok(),
                "Failed to load fixture {path}: {:?}",
                result.err()
            );

            let fixture = result.expect("Fixture should load");

            // Validate expected structure
            let expected = fixture
                .get("expected")
                .expect("Fixture should have 'expected' field");

            assert!(
                expected.get("tx_type").is_some(),
                "Expected should have 'tx_type' in {path}"
            );
            assert!(
                expected.get("recipient").is_some() || expected.get("contract_address").is_some(),
                "Expected should have 'recipient' or 'contract_address' in {path}"
            );
            assert!(
                expected.get("amount").is_some(),
                "Expected should have 'amount' in {path}"
            );
        }
    }
}
