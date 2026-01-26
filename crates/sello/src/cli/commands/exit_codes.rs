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
