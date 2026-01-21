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

// Import alloy types for RLP decoding once parser is implemented
// use alloy_consensus::TxEnvelope;
// use alloy_rlp::Decodable;

fuzz_target!(|data: &[u8]| {
    // TODO: Once EthereumParser is implemented in sello-chain, uncomment:
    //
    // ```rust
    // // Try to parse as a signed transaction envelope
    // let _ = TxEnvelope::decode(&mut &data[..]);
    //
    // // Also try the sello-chain parser
    // let _ = sello_chain::ethereum::EthereumParser::parse(data);
    // ```
    //
    // For now, perform basic sanity checks to ensure the fuzzing
    // infrastructure is working correctly:

    // Verify we can handle empty input
    if data.is_empty() {
        return;
    }

    // Verify we can handle any length input without panicking
    let _len = data.len();

    // Verify we can safely access bytes (bounds checking)
    let _first = data.first();
    let _last = data.last();

    // Simulate basic RLP-like length prefix check
    // (This exercises the kind of parsing logic that will be used)
    if let Some(&first_byte) = data.first() {
        match first_byte {
            // Single byte value
            0x00..=0x7f => {
                let _value = first_byte;
            }
            // Short string (0-55 bytes)
            0x80..=0xb7 => {
                let len = (first_byte - 0x80) as usize;
                let _slice = data.get(1..1 + len);
            }
            // Long string (>55 bytes)
            0xb8..=0xbf => {
                let len_of_len = (first_byte - 0xb7) as usize;
                let _len_bytes = data.get(1..1 + len_of_len);
            }
            // Short list
            0xc0..=0xf7 => {
                let len = (first_byte - 0xc0) as usize;
                let _items = data.get(1..1 + len);
            }
            // Long list
            0xf8..=0xff => {
                let len_of_len = (first_byte - 0xf7) as usize;
                let _len_bytes = data.get(1..1 + len_of_len);
            }
        }
    }
});
