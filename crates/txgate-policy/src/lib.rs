//! # txgate-policy
//!
//! Policy engine for transaction approval rules in the `TxGate` signing service.
//!
//! ## Internal Crate Warning
//!
//! **This crate is an internal implementation detail of [`txgate`](https://crates.io/crates/txgate).**
//!
//! It is published to crates.io only because Cargo requires all dependencies to be
//! published. The API is **unstable** and may change without notice between any versions,
//! including patch releases.
//!
//! **Do not depend on this crate directly.** Instead:
//! - For the signing server binary: `cargo install txgate`
//! - For programmatic access: Open an issue at <https://github.com/txgate-project/txgate>
//!   to discuss a stable public API.
//!
//! This crate provides the policy evaluation and rule management system:
//!
//! ## Modules
//!
//! - [`config`] - Policy configuration types
//! - [`history`] - Transaction history tracking with `SQLite`
//!
//! ## Modules (planned)
//!
//! - `engine` - Policy evaluation engine
//! - `rules` - Rule definitions and parsing
//! - `conditions` - Condition types (amount limits, address allowlists, etc.)
//! - `actions` - Policy actions (approve, deny, `require_approval`)
//!
//! ## Policy Features (planned)
//!
//! - Transaction amount limits (per-tx, daily, monthly)
//! - Address allowlists and blocklists
//! - Contract function restrictions
//! - Time-based rules (business hours, rate limiting)
//! - Multi-signature approval workflows
//! - Chain-specific policies
//!
//! ## Policy Format
//!
//! Policies are defined in YAML/JSON format and can be:
//! - Loaded from files
//! - Fetched from remote configuration servers
//! - Defined programmatically
//!
//! ## Example Policy (conceptual)
//!
//! ```yaml
//! policies:
//!   - name: "high_value_transfer"
//!     conditions:
//!       - type: "amount_greater_than"
//!         value: "10 ETH"
//!     action: "require_approval"
//!     approvers: ["admin@company.com"]
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]

pub mod config;
pub mod engine;
pub mod history;

pub use config::PolicyConfig;
pub use engine::{DefaultPolicyEngine, PolicyCheckResult, PolicyEngine};
pub use history::{TransactionHistory, TransactionRecord};

// Placeholder for future modules
// pub mod rules;
// pub mod conditions;
// pub mod actions;
