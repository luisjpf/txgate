//! # Install Skill Command
//!
//! Implementation of the `txgate install-skill` command that prints
//! instructions for installing the `TxGate` Claude Code skill.
//!
//! This command is intentionally read-only and does not write to the
//! filesystem. For a transaction signing tool, automatic writes to
//! user directories (like `~/.claude/`) would be a security concern.
//!
//! ## Usage
//!
//! ```no_run
//! use txgate::cli::commands::install_skill::InstallSkillCommand;
//!
//! let cmd = InstallSkillCommand::new();
//! cmd.run().expect("install-skill command failed");
//! ```

// ============================================================================
// InstallSkillError
// ============================================================================

/// Errors that can occur during the install-skill command.
#[derive(Debug, thiserror::Error)]
pub enum InstallSkillError {
    /// I/O error writing to stdout.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

// ============================================================================
// InstallSkillCommand
// ============================================================================

/// The `txgate install-skill` command handler.
///
/// Prints instructions for installing the `TxGate` skill for Claude Code.
/// This command intentionally does NOT write to the filesystem.
///
/// # Example
///
/// ```no_run
/// use txgate::cli::commands::install_skill::InstallSkillCommand;
///
/// let cmd = InstallSkillCommand::new();
/// match cmd.run() {
///     Ok(()) => {}
///     Err(e) => eprintln!("Error: {}", e),
/// }
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct InstallSkillCommand;

impl InstallSkillCommand {
    /// Create a new `InstallSkillCommand`.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Run the install-skill command.
    ///
    /// Prints installation instructions to stdout.
    ///
    /// # Errors
    ///
    /// Returns [`InstallSkillError::Io`] if writing to stdout fails.
    pub fn run(&self) -> Result<(), InstallSkillError> {
        use std::io::Write;
        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        write!(handle, "{INSTRUCTIONS}")?;
        Ok(())
    }
}

/// Installation instructions text.
const INSTRUCTIONS: &str = r"TxGate Claude Code Skill
========================

TxGate includes a Claude Code skill that teaches Claude how to use the
TxGate CLI. To install it, copy the skill files to your Claude Code
skills directory.

Option 1: From a git clone
---------------------------

  git clone https://github.com/luisjpf/txgate.git
  mkdir -p ~/.claude/skills/txgate
  cp -r txgate/contrib/claude-skill/* ~/.claude/skills/txgate/

Option 2: Download from GitHub
-------------------------------

  mkdir -p ~/.claude/skills/txgate/references
  curl -sL https://raw.githubusercontent.com/luisjpf/txgate/main/contrib/claude-skill/SKILL.md \
    -o ~/.claude/skills/txgate/SKILL.md
  curl -sL https://raw.githubusercontent.com/luisjpf/txgate/main/contrib/claude-skill/references/cli-reference.md \
    -o ~/.claude/skills/txgate/references/cli-reference.md
  curl -sL https://raw.githubusercontent.com/luisjpf/txgate/main/contrib/claude-skill/references/config-reference.md \
    -o ~/.claude/skills/txgate/references/config-reference.md

Verify installation
-------------------

  ls ~/.claude/skills/txgate/SKILL.md

After installation, Claude Code will automatically use the TxGate skill
when you ask about transaction signing, key management, or policy
configuration.

Note: This command intentionally does not write to your filesystem.
TxGate is a transaction signing tool and avoids unexpected file writes
as a security practice.
";

// ============================================================================
// Tests
// ============================================================================

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
        clippy::uninlined_format_args,
        clippy::doc_markdown,
        clippy::redundant_closure_for_method_calls,
        clippy::needless_pass_by_value
    )]

    use super::*;

    #[test]
    fn test_install_skill_command_new() {
        let cmd = InstallSkillCommand::new();
        let _ = format!("{cmd:?}");
    }

    #[test]
    fn test_install_skill_command_run_succeeds() {
        let cmd = InstallSkillCommand::new();
        let result = cmd.run();
        assert!(result.is_ok());
    }

    #[test]
    fn test_install_skill_command_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<InstallSkillCommand>();
    }

    #[test]
    fn test_install_skill_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<InstallSkillError>();
    }

    #[test]
    fn test_install_skill_command_default() {
        #[allow(clippy::default_constructed_unit_structs)]
        let cmd = InstallSkillCommand::default();
        let debug = format!("{cmd:?}");
        assert!(debug.contains("InstallSkillCommand"));
    }

    #[test]
    fn test_install_skill_command_copy() {
        let cmd = InstallSkillCommand::new();
        let copied = cmd;
        // Both should work since InstallSkillCommand is Copy
        let _ = format!("{cmd:?}");
        let _ = format!("{copied:?}");
    }

    #[test]
    fn test_instructions_contain_key_strings() {
        assert!(INSTRUCTIONS.contains("mkdir -p ~/.claude/skills/txgate"));
        assert!(INSTRUCTIONS.contains("SKILL.md"));
        assert!(INSTRUCTIONS.contains("curl"));
        assert!(INSTRUCTIONS.contains("does not write to your filesystem"));
    }

    #[test]
    fn test_install_skill_error_display() {
        let io_err = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pipe broken");
        let err = InstallSkillError::Io(io_err);
        assert!(err.to_string().contains("IO error"));
    }
}
