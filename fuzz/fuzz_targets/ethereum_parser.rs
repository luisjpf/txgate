//! Fuzz target for Ethereum transaction parser.
//!
//! This fuzz target exercises the Ethereum transaction parsing code with
//! arbitrary byte sequences to find potential panics, crashes, or unexpected
//! behavior in the parser implementation.
//!
//! # Running
//!
//! ```bash
//! cargo +nightly fuzz run ethereum_parser
//! ```
//!
//! # Coverage-guided fuzzing
//!
//! The fuzzer will automatically discover interesting inputs that exercise
//! new code paths. These inputs are stored in `fuzz/corpus/ethereum_parser/`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sello_chain::{Chain, EthereumParser};

fuzz_target!(|data: &[u8]| {
    // Create the parser once (it's stateless)
    let parser = EthereumParser::new();

    // Try to parse the arbitrary data as an Ethereum transaction.
    // The parser should handle all inputs gracefully without panicking.
    // Valid transactions will be parsed, invalid ones will return errors.
    let _ = parser.parse(data);

    // Also test the Chain trait methods for consistency
    let _ = parser.id();
    let _ = parser.curve();

    // Test version support checks with various type bytes
    if let Some(&first_byte) = data.first() {
        let _ = parser.supports_version(first_byte);
    }
});
