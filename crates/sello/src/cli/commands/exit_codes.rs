//! Exit code constants for CLI commands.
//!
//! These exit codes are used consistently across all sign commands
//! to indicate the result of the operation.

/// Successful operation.
pub const EXIT_SUCCESS: i32 = 0;

/// Policy denied the transaction.
///
/// This indicates that the transaction was rejected by the policy engine
/// (e.g., blacklisted address, exceeds limits, not whitelisted).
pub const EXIT_POLICY_DENIED: i32 = 1;

/// General error (configuration, I/O, invalid input, etc.).
pub const EXIT_ERROR: i32 = 2;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exit_codes_values() {
        assert_eq!(EXIT_SUCCESS, 0);
        assert_eq!(EXIT_POLICY_DENIED, 1);
        assert_eq!(EXIT_ERROR, 2);
    }

    #[test]
    fn test_exit_codes_are_distinct() {
        assert_ne!(EXIT_SUCCESS, EXIT_POLICY_DENIED);
        assert_ne!(EXIT_SUCCESS, EXIT_ERROR);
        assert_ne!(EXIT_POLICY_DENIED, EXIT_ERROR);
    }
}
