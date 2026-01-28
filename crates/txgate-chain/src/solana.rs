//! Solana transaction parser.
//!
//! This module provides the [`SolanaParser`] implementation for parsing
//! Solana transactions into the common [`ParsedTx`] format.
//!
//! # Supported Message Types
//!
//! - **Legacy**: Original Solana message format
//! - **Versioned (V0)**: New message format with address lookup tables
//!
//! # Supported Instructions
//!
//! - **System Program**: SOL transfers
//! - **SPL Token**: Token transfers, approvals
//! - **Token-2022**: Extended token operations
//!
//! # Example
//!
//! ```ignore
//! use txgate_chain::{Chain, SolanaParser};
//!
//! let parser = SolanaParser::new();
//!
//! // Parse a raw Solana transaction
//! let raw_tx = base64::decode("...").unwrap();
//! let parsed = parser.parse(&raw_tx)?;
//!
//! println!("Fee payer: {:?}", parsed.recipient);
//! println!("Amount: {:?}", parsed.amount);
//! ```

use solana_sdk::message::VersionedMessage;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::transaction::VersionedTransaction;
use std::collections::HashMap;
use std::str::FromStr;
use txgate_core::error::ParseError;
use txgate_core::{ParsedTx, TxType, U256};
use txgate_crypto::CurveType;

use crate::Chain;

/// System Program ID
const SYSTEM_PROGRAM_ID: &str = "11111111111111111111111111111111";

/// SPL Token Program ID
const TOKEN_PROGRAM_ID: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

/// Token-2022 Program ID
const TOKEN_2022_PROGRAM_ID: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

/// Solana transaction parser.
///
/// Parses raw Solana transactions into the common [`ParsedTx`] format
/// for policy evaluation.
///
/// # Thread Safety
///
/// `SolanaParser` is `Send + Sync` and can be safely shared across threads.
#[derive(Debug, Clone, Copy, Default)]
pub struct SolanaParser;

impl SolanaParser {
    /// Create a new Solana parser.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Parse a SOL transfer instruction.
    fn parse_system_transfer(data: &[u8], accounts: &[Pubkey]) -> Option<(String, u64)> {
        // System transfer instruction layout:
        // - 4 bytes: instruction type (2 = transfer)
        // - 8 bytes: lamports (u64, little-endian)
        if data.len() < 12 {
            return None;
        }

        let instruction_type =
            u32::from_le_bytes([*data.first()?, *data.get(1)?, *data.get(2)?, *data.get(3)?]);

        // 2 = Transfer instruction
        if instruction_type != 2 {
            return None;
        }

        let lamports = u64::from_le_bytes([
            *data.get(4)?,
            *data.get(5)?,
            *data.get(6)?,
            *data.get(7)?,
            *data.get(8)?,
            *data.get(9)?,
            *data.get(10)?,
            *data.get(11)?,
        ]);

        // accounts[0] = source, accounts[1] = destination
        let destination = accounts.get(1)?;
        Some((destination.to_string(), lamports))
    }

    /// Check if instruction is a token transfer.
    fn is_token_instruction(program_id: &Pubkey) -> bool {
        let program_str = program_id.to_string();
        program_str == TOKEN_PROGRAM_ID || program_str == TOKEN_2022_PROGRAM_ID
    }

    /// Parse a token transfer instruction.
    fn parse_token_transfer(data: &[u8], accounts: &[Pubkey]) -> Option<(String, u64, bool)> {
        if data.is_empty() {
            return None;
        }

        let instruction_type = *data.first()?;

        match instruction_type {
            // Transfer (instruction 3)
            3 => {
                if data.len() < 9 {
                    return None;
                }
                let amount = u64::from_le_bytes([
                    *data.get(1)?,
                    *data.get(2)?,
                    *data.get(3)?,
                    *data.get(4)?,
                    *data.get(5)?,
                    *data.get(6)?,
                    *data.get(7)?,
                    *data.get(8)?,
                ]);
                // accounts: [source, destination, owner]
                let destination = accounts.get(1)?;
                Some((destination.to_string(), amount, false))
            }
            // TransferChecked (instruction 12)
            12 => {
                if data.len() < 10 {
                    return None;
                }
                let amount = u64::from_le_bytes([
                    *data.get(1)?,
                    *data.get(2)?,
                    *data.get(3)?,
                    *data.get(4)?,
                    *data.get(5)?,
                    *data.get(6)?,
                    *data.get(7)?,
                    *data.get(8)?,
                ]);
                // accounts: [source, mint, destination, owner]
                let destination = accounts.get(2)?;
                Some((destination.to_string(), amount, true))
            }
            _ => None,
        }
    }

    /// Determine transaction type from instructions.
    /// Reserved for future use with legacy message analysis.
    #[allow(dead_code)]
    fn _determine_tx_type(message: &solana_sdk::message::Message) -> TxType {
        let system_program = Pubkey::from_str(SYSTEM_PROGRAM_ID).ok();
        let token_program = Pubkey::from_str(TOKEN_PROGRAM_ID).ok();
        let token_2022_program = Pubkey::from_str(TOKEN_2022_PROGRAM_ID).ok();

        for instruction in &message.instructions {
            let program_idx = instruction.program_id_index as usize;
            let program_id = message.account_keys.get(program_idx);

            if let Some(program_id) = program_id {
                // Check for SOL transfer
                if system_program.as_ref() == Some(program_id) && !instruction.data.is_empty() {
                    let instr_type = u32::from_le_bytes([
                        instruction.data.first().copied().unwrap_or(0),
                        instruction.data.get(1).copied().unwrap_or(0),
                        instruction.data.get(2).copied().unwrap_or(0),
                        instruction.data.get(3).copied().unwrap_or(0),
                    ]);
                    if instr_type == 2 {
                        return TxType::Transfer;
                    }
                }

                // Check for token transfer
                if (token_program.as_ref() == Some(program_id)
                    || token_2022_program.as_ref() == Some(program_id))
                    && !instruction.data.is_empty()
                {
                    let instr_type = instruction.data.first().copied().unwrap_or(0);
                    if instr_type == 3 || instr_type == 12 {
                        return TxType::TokenTransfer;
                    }
                    if instr_type == 4 {
                        return TxType::TokenApproval;
                    }
                }
            }
        }

        // Default to contract call if we can't determine the type
        TxType::ContractCall
    }

    /// Extract account keys based on message type.
    fn get_account_keys(message: &VersionedMessage) -> &[Pubkey] {
        match message {
            VersionedMessage::Legacy(msg) => &msg.account_keys,
            VersionedMessage::V0(msg) => &msg.account_keys,
        }
    }

    /// Get instructions from message.
    fn get_instructions(message: &VersionedMessage) -> Vec<(Pubkey, Vec<Pubkey>, Vec<u8>)> {
        let account_keys = Self::get_account_keys(message);

        let instructions = match message {
            VersionedMessage::Legacy(msg) => &msg.instructions,
            VersionedMessage::V0(msg) => &msg.instructions,
        };

        instructions
            .iter()
            .filter_map(|instr| {
                let program_id = account_keys.get(instr.program_id_index as usize)?;
                let accounts: Vec<Pubkey> = instr
                    .accounts
                    .iter()
                    .filter_map(|&idx| account_keys.get(idx as usize).copied())
                    .collect();
                Some((*program_id, accounts, instr.data.clone()))
            })
            .collect()
    }
}

impl Chain for SolanaParser {
    fn id(&self) -> &'static str {
        "solana"
    }

    fn parse(&self, raw: &[u8]) -> Result<ParsedTx, ParseError> {
        if raw.is_empty() {
            return Err(ParseError::MalformedTransaction {
                context: "empty transaction data".to_string(),
            });
        }

        // Try to decode as VersionedTransaction
        let tx: VersionedTransaction =
            bincode::deserialize(raw).map_err(|e| ParseError::MalformedTransaction {
                context: format!("failed to decode Solana transaction: {e}"),
            })?;

        // Get the message hash for signing
        let message_bytes = tx.message.serialize();
        let message_hash = solana_sdk::hash::hash(&message_bytes);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(message_hash.as_ref());

        // Get account keys
        let account_keys = Self::get_account_keys(&tx.message);

        // Fee payer is always the first account
        let fee_payer = account_keys.first().map(Pubkey::to_string);

        // Get recent blockhash
        let recent_blockhash = match &tx.message {
            VersionedMessage::Legacy(msg) => msg.recent_blockhash,
            VersionedMessage::V0(msg) => msg.recent_blockhash,
        };

        // Parse instructions to find transfers
        let instructions = Self::get_instructions(&tx.message);

        let mut recipient = None;
        let mut amount: Option<u64> = None;
        let mut token_address = None;
        let mut tx_type = TxType::ContractCall;

        let system_program = Pubkey::from_str(SYSTEM_PROGRAM_ID).ok();

        for (program_id, accounts, data) in &instructions {
            // Check for SOL transfer
            if system_program.as_ref() == Some(program_id) {
                if let Some((dest, lamports)) = Self::parse_system_transfer(data, accounts) {
                    recipient = Some(dest);
                    amount = Some(lamports);
                    tx_type = TxType::Transfer;
                    break;
                }
            }

            // Check for token transfer
            if Self::is_token_instruction(program_id) {
                if let Some((dest, amt, _checked)) = Self::parse_token_transfer(data, accounts) {
                    recipient = Some(dest);
                    amount = Some(amt);
                    token_address = Some(program_id.to_string());
                    tx_type = TxType::TokenTransfer;
                    break;
                }
            }
        }

        // Build metadata
        let mut metadata = HashMap::new();

        // Add fee payer
        if let Some(ref payer) = fee_payer {
            metadata.insert(
                "fee_payer".to_string(),
                serde_json::Value::String(payer.clone()),
            );
        }

        // Add recent blockhash
        metadata.insert(
            "recent_blockhash".to_string(),
            serde_json::Value::String(recent_blockhash.to_string()),
        );

        // Add signature count
        metadata.insert(
            "signature_count".to_string(),
            serde_json::Value::Number(tx.signatures.len().into()),
        );

        // Add instruction count
        metadata.insert(
            "instruction_count".to_string(),
            serde_json::Value::Number(instructions.len().into()),
        );

        // Add message version
        let version = match &tx.message {
            VersionedMessage::Legacy(_) => "legacy",
            VersionedMessage::V0(_) => "v0",
        };
        metadata.insert(
            "message_version".to_string(),
            serde_json::Value::String(version.to_string()),
        );

        // Add all involved programs
        let programs: Vec<serde_json::Value> = instructions
            .iter()
            .map(|(program_id, _, _)| serde_json::Value::String(program_id.to_string()))
            .collect();
        metadata.insert("programs".to_string(), serde_json::Value::Array(programs));

        Ok(ParsedTx {
            hash,
            recipient,
            amount: amount.map(U256::from),
            token: if token_address.is_some() {
                None // Token symbol requires on-chain lookup
            } else {
                Some("SOL".to_string())
            },
            token_address,
            tx_type,
            chain: "solana".to_string(),
            nonce: None, // Solana uses recent blockhash instead of nonces
            chain_id: None,
            metadata,
        })
    }

    fn curve(&self) -> CurveType {
        CurveType::Ed25519
    }

    fn supports_version(&self, version: u8) -> bool {
        // Version 0 = legacy, 128+ = versioned (V0, etc.)
        version == 0 || version >= 128
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use super::*;

    #[test]
    fn test_solana_parser_id() {
        let parser = SolanaParser::new();
        assert_eq!(parser.id(), "solana");
    }

    #[test]
    fn test_solana_parser_curve() {
        let parser = SolanaParser::new();
        assert_eq!(parser.curve(), CurveType::Ed25519);
    }

    #[test]
    fn test_solana_parser_default() {
        let parser = SolanaParser::default();
        assert_eq!(parser.id(), "solana");
    }

    #[test]
    fn test_solana_parser_empty_input() {
        let parser = SolanaParser::new();
        let result = parser.parse(&[]);

        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(ParseError::MalformedTransaction { .. })
        ));
    }

    #[test]
    fn test_solana_parser_invalid_input() {
        let parser = SolanaParser::new();
        let result = parser.parse(&[0x00, 0x01, 0x02]);

        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(ParseError::MalformedTransaction { .. })
        ));
    }

    #[test]
    fn test_solana_parser_supports_version() {
        let parser = SolanaParser::new();

        assert!(parser.supports_version(0)); // Legacy
        assert!(parser.supports_version(128)); // V0
        assert!(parser.supports_version(129)); // Future versions
        assert!(!parser.supports_version(1)); // Invalid
        assert!(!parser.supports_version(127)); // Invalid
    }

    #[test]
    fn test_solana_parser_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SolanaParser>();
    }

    #[test]
    fn test_solana_parser_clone() {
        let parser = SolanaParser::new();
        let cloned = parser;
        assert_eq!(parser.id(), cloned.id());
    }

    #[test]
    fn test_solana_parser_debug() {
        let parser = SolanaParser::new();
        let debug_str = format!("{parser:?}");
        assert!(debug_str.contains("SolanaParser"));
    }

    // -------------------------------------------------------------------------
    // Real Transaction Parsing Tests
    // -------------------------------------------------------------------------

    use solana_sdk::hash::Hash;
    use solana_sdk::instruction::{AccountMeta, Instruction};
    use solana_sdk::signature::Keypair;
    use solana_sdk::signer::Signer;
    use solana_sdk::system_instruction;
    use solana_sdk::transaction::Transaction;

    /// Create a valid SOL transfer transaction for testing.
    fn create_sol_transfer_tx(lamports: u64) -> Vec<u8> {
        let from = Keypair::new();
        let to = Pubkey::new_unique();
        let recent_blockhash = Hash::new_unique();

        let instruction = system_instruction::transfer(&from.pubkey(), &to, lamports);
        let tx = Transaction::new_signed_with_payer(
            &[instruction],
            Some(&from.pubkey()),
            &[&from],
            recent_blockhash,
        );

        bincode::serialize(&tx).expect("failed to serialize transaction")
    }

    #[test]
    fn test_parse_sol_transfer() {
        let parser = SolanaParser::new();
        let lamports = 1_000_000_000u64; // 1 SOL
        let tx_bytes = create_sol_transfer_tx(lamports);

        let result = parser.parse(&tx_bytes);
        assert!(result.is_ok(), "Failed to parse SOL transfer: {:?}", result);

        let parsed = result.unwrap();
        assert_eq!(parsed.chain, "solana");
        assert!(matches!(parsed.tx_type, TxType::Transfer));
        assert!(parsed.recipient.is_some());
        assert!(parsed.amount.is_some());
        assert_eq!(parsed.amount.unwrap(), U256::from(lamports));
        assert_eq!(parsed.token, Some("SOL".to_string()));
    }

    #[test]
    fn test_parse_sol_transfer_small_amount() {
        let parser = SolanaParser::new();
        let lamports = 1u64; // 1 lamport
        let tx_bytes = create_sol_transfer_tx(lamports);

        let result = parser.parse(&tx_bytes);
        assert!(result.is_ok());

        let parsed = result.unwrap();
        assert_eq!(parsed.amount.unwrap(), U256::from(1u64));
    }

    #[test]
    fn test_parse_sol_transfer_large_amount() {
        let parser = SolanaParser::new();
        let lamports = u64::MAX; // Max lamports
        let tx_bytes = create_sol_transfer_tx(lamports);

        let result = parser.parse(&tx_bytes);
        assert!(result.is_ok());

        let parsed = result.unwrap();
        assert_eq!(parsed.amount.unwrap(), U256::from(u64::MAX));
    }

    #[test]
    fn test_parse_transaction_metadata() {
        let parser = SolanaParser::new();
        let tx_bytes = create_sol_transfer_tx(1_000_000);

        let result = parser.parse(&tx_bytes);
        assert!(result.is_ok());

        let parsed = result.unwrap();
        // Check metadata fields
        assert!(parsed.metadata.contains_key("fee_payer"));
        assert!(parsed.metadata.contains_key("recent_blockhash"));
        assert!(parsed.metadata.contains_key("signature_count"));
        assert!(parsed.metadata.contains_key("instruction_count"));
    }

    #[test]
    fn test_parse_transaction_hash() {
        let parser = SolanaParser::new();
        let tx_bytes = create_sol_transfer_tx(1_000_000);

        let result = parser.parse(&tx_bytes);
        assert!(result.is_ok());

        let parsed = result.unwrap();
        // Hash should be non-zero
        assert!(!parsed.hash.iter().all(|&b| b == 0));
    }

    /// Create a token transfer instruction for testing.
    /// The owner must be passed in so it can match the signer.
    fn create_token_transfer_instruction(amount: u64, owner: &Pubkey) -> Instruction {
        let token_program = Pubkey::from_str(TOKEN_PROGRAM_ID).unwrap();
        let source = Pubkey::new_unique();
        let destination = Pubkey::new_unique();

        // Token Transfer instruction: type 3 + amount (little-endian u64)
        let mut data = vec![3u8]; // instruction type
        data.extend_from_slice(&amount.to_le_bytes());

        Instruction {
            program_id: token_program,
            accounts: vec![
                AccountMeta::new(source, false),
                AccountMeta::new(destination, false),
                AccountMeta::new_readonly(*owner, true),
            ],
            data,
        }
    }

    #[test]
    fn test_parse_token_transfer() {
        let parser = SolanaParser::new();

        let from = Keypair::new();
        let recent_blockhash = Hash::new_unique();
        let token_amount = 1_000_000u64;

        // Use from.pubkey() as the owner so we only need one signer
        let instruction = create_token_transfer_instruction(token_amount, &from.pubkey());
        let tx = Transaction::new_signed_with_payer(
            &[instruction],
            Some(&from.pubkey()),
            &[&from],
            recent_blockhash,
        );

        let tx_bytes = bincode::serialize(&tx).expect("failed to serialize");
        let result = parser.parse(&tx_bytes);
        assert!(
            result.is_ok(),
            "Failed to parse token transfer: {:?}",
            result
        );

        let parsed = result.unwrap();
        assert_eq!(parsed.chain, "solana");
        assert!(matches!(parsed.tx_type, TxType::TokenTransfer));
        assert!(parsed.recipient.is_some());
        assert!(parsed.amount.is_some());
        assert_eq!(parsed.amount.unwrap(), U256::from(token_amount));
    }

    /// Create a TransferChecked instruction for testing.
    /// The owner must be passed in so it can match the signer.
    fn create_transfer_checked_instruction(
        amount: u64,
        decimals: u8,
        owner: &Pubkey,
    ) -> Instruction {
        let token_program = Pubkey::from_str(TOKEN_PROGRAM_ID).unwrap();
        let source = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let destination = Pubkey::new_unique();

        // TransferChecked instruction: type 12 + amount (u64) + decimals (u8)
        let mut data = vec![12u8]; // instruction type
        data.extend_from_slice(&amount.to_le_bytes());
        data.push(decimals);

        Instruction {
            program_id: token_program,
            accounts: vec![
                AccountMeta::new(source, false),
                AccountMeta::new_readonly(mint, false),
                AccountMeta::new(destination, false),
                AccountMeta::new_readonly(*owner, true),
            ],
            data,
        }
    }

    #[test]
    fn test_parse_transfer_checked() {
        let parser = SolanaParser::new();

        let from = Keypair::new();
        let recent_blockhash = Hash::new_unique();
        let token_amount = 500_000u64;
        let decimals = 6u8;

        // Use from.pubkey() as the owner so we only need one signer
        let instruction =
            create_transfer_checked_instruction(token_amount, decimals, &from.pubkey());
        let tx = Transaction::new_signed_with_payer(
            &[instruction],
            Some(&from.pubkey()),
            &[&from],
            recent_blockhash,
        );

        let tx_bytes = bincode::serialize(&tx).expect("failed to serialize");
        let result = parser.parse(&tx_bytes);
        assert!(
            result.is_ok(),
            "Failed to parse TransferChecked: {:?}",
            result
        );

        let parsed = result.unwrap();
        assert!(matches!(parsed.tx_type, TxType::TokenTransfer));
        assert_eq!(parsed.amount.unwrap(), U256::from(token_amount));
    }

    #[test]
    fn test_parse_system_transfer_helper() {
        // Test the parse_system_transfer helper function directly
        let lamports = 5_000_000_000u64;

        // Build instruction data: 4 bytes type (2 = transfer) + 8 bytes amount
        let mut data = vec![2u8, 0, 0, 0]; // instruction type 2 in little-endian
        data.extend_from_slice(&lamports.to_le_bytes());

        let source = Pubkey::new_unique();
        let destination = Pubkey::new_unique();
        let accounts = vec![source, destination];

        let result = SolanaParser::parse_system_transfer(&data, &accounts);
        assert!(result.is_some());

        let (dest, amount) = result.unwrap();
        assert_eq!(dest, destination.to_string());
        assert_eq!(amount, lamports);
    }

    #[test]
    fn test_parse_system_transfer_wrong_instruction_type() {
        // instruction type 1 (CreateAccount) should return None
        let mut data = vec![1u8, 0, 0, 0];
        data.extend_from_slice(&1000u64.to_le_bytes());

        let accounts = vec![Pubkey::new_unique(), Pubkey::new_unique()];

        let result = SolanaParser::parse_system_transfer(&data, &accounts);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_system_transfer_insufficient_data() {
        // Less than 12 bytes should return None
        let data = vec![2u8, 0, 0, 0, 0, 0, 0, 0]; // Only 8 bytes

        let accounts = vec![Pubkey::new_unique(), Pubkey::new_unique()];

        let result = SolanaParser::parse_system_transfer(&data, &accounts);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_token_transfer_helper() {
        let amount = 1_000_000u64;

        // Transfer instruction: type 3 + amount
        let mut data = vec![3u8];
        data.extend_from_slice(&amount.to_le_bytes());

        let accounts = vec![
            Pubkey::new_unique(), // source
            Pubkey::new_unique(), // destination
            Pubkey::new_unique(), // owner
        ];

        let result = SolanaParser::parse_token_transfer(&data, &accounts);
        assert!(result.is_some());

        let (dest, parsed_amount, is_checked) = result.unwrap();
        assert_eq!(dest, accounts[1].to_string());
        assert_eq!(parsed_amount, amount);
        assert!(!is_checked);
    }

    #[test]
    fn test_parse_token_transfer_checked_helper() {
        let amount = 2_000_000u64;

        // TransferChecked instruction: type 12 + amount + decimals
        let mut data = vec![12u8];
        data.extend_from_slice(&amount.to_le_bytes());
        data.push(9u8); // decimals

        let accounts = vec![
            Pubkey::new_unique(), // source
            Pubkey::new_unique(), // mint
            Pubkey::new_unique(), // destination
            Pubkey::new_unique(), // owner
        ];

        let result = SolanaParser::parse_token_transfer(&data, &accounts);
        assert!(result.is_some());

        let (dest, parsed_amount, is_checked) = result.unwrap();
        assert_eq!(dest, accounts[2].to_string()); // destination is at index 2
        assert_eq!(parsed_amount, amount);
        assert!(is_checked);
    }

    #[test]
    fn test_parse_token_transfer_unknown_instruction() {
        // Unknown instruction type should return None
        let data = vec![99u8, 0, 0, 0, 0, 0, 0, 0, 0];
        let accounts = vec![Pubkey::new_unique(), Pubkey::new_unique()];

        let result = SolanaParser::parse_token_transfer(&data, &accounts);
        assert!(result.is_none());
    }

    #[test]
    fn test_is_token_instruction() {
        let token_program = Pubkey::from_str(TOKEN_PROGRAM_ID).unwrap();
        let token_2022_program = Pubkey::from_str(TOKEN_2022_PROGRAM_ID).unwrap();
        let system_program = Pubkey::from_str(SYSTEM_PROGRAM_ID).unwrap();
        let random_program = Pubkey::new_unique();

        assert!(SolanaParser::is_token_instruction(&token_program));
        assert!(SolanaParser::is_token_instruction(&token_2022_program));
        assert!(!SolanaParser::is_token_instruction(&system_program));
        assert!(!SolanaParser::is_token_instruction(&random_program));
    }
}
