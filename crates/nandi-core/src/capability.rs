//! Tool capabilities and risk scores.
//!
//! A [`Capability`] says what kind of effect a tool can have: read data,
//! fetch from the network, write files, run commands, move money and so on.
//! The engine infers capabilities from tool definitions (names, input
//! schemas, MCP annotations) and from bare tool names; policies match on
//! them and dashboards rank servers by them.
//!
//! The risk score of a tool is derived from the [`Capability::weight`] of its
//! capabilities: the heaviest one counts fully, every other one a quarter,
//! plus fixed penalties for a high-severity description finding and for a
//! definition that drifted since it was pinned. Scores run from 0 to 100 and
//! map to a [`RiskLevel`].

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// What a tool can do. Use [`Capability::weight`] for scoring; the
/// derived order only keeps sets deterministic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// Reads data without side effects.
    ReadOnly,
    /// Fetches from or searches the network (URLs, web search, downloads).
    NetworkFetch,
    /// Creates or changes files.
    FileWrite,
    /// Deletes files or directories.
    FileDelete,
    /// Creates or changes records (issues, rows, documents, settings).
    DataModification,
    /// Deletes records, tables, repositories or other data.
    DataDeletion,
    /// Runs commands, scripts or code.
    CommandExecution,
    /// Sends something to people or systems outside: email, chat, posts,
    /// webhooks.
    ExternalSend,
    /// Moves money: payments, transfers, refunds, invoices, payouts.
    Payment,
    /// Reads or manages secrets, tokens, keys or passwords.
    CredentialAccess,
    /// Manages users, roles, permissions or invitations.
    IdentityAdmin,
}

impl Capability {
    /// Every capability, in declaration order.
    pub const ALL: [Capability; 11] = [
        Capability::ReadOnly,
        Capability::NetworkFetch,
        Capability::FileWrite,
        Capability::FileDelete,
        Capability::DataModification,
        Capability::DataDeletion,
        Capability::CommandExecution,
        Capability::ExternalSend,
        Capability::Payment,
        Capability::CredentialAccess,
        Capability::IdentityAdmin,
    ];

    /// Snake-case name as used in rules, Cedar and the admin API.
    pub fn as_str(&self) -> &'static str {
        match self {
            Capability::ReadOnly => "read_only",
            Capability::NetworkFetch => "network_fetch",
            Capability::FileWrite => "file_write",
            Capability::FileDelete => "file_delete",
            Capability::DataModification => "data_modification",
            Capability::DataDeletion => "data_deletion",
            Capability::CommandExecution => "command_execution",
            Capability::ExternalSend => "external_send",
            Capability::Payment => "payment",
            Capability::CredentialAccess => "credential_access",
            Capability::IdentityAdmin => "identity_admin",
        }
    }

    /// Contribution to a tool's risk score (0 - 40).
    pub fn weight(&self) -> u32 {
        match self {
            Capability::CommandExecution | Capability::Payment => 40,
            Capability::CredentialAccess => 35,
            Capability::DataDeletion | Capability::IdentityAdmin => 30,
            Capability::ExternalSend => 25,
            Capability::FileDelete => 20,
            Capability::DataModification | Capability::FileWrite => 15,
            Capability::NetworkFetch => 10,
            Capability::ReadOnly => 0,
        }
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Capability {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Capability::ALL
            .into_iter()
            .find(|c| c.as_str().eq_ignore_ascii_case(s.trim()))
            .ok_or_else(|| format!("unknown capability `{s}`"))
    }
}

/// Coarse risk bucket of a 0 - 100 score.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    #[default]
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    /// `low` below 25, `medium` below 50, `high` below 75, else `critical`.
    pub fn from_score(score: u8) -> Self {
        match score {
            0..25 => RiskLevel::Low,
            25..50 => RiskLevel::Medium,
            50..75 => RiskLevel::High,
            _ => RiskLevel::Critical,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            RiskLevel::Low => "low",
            RiskLevel::Medium => "medium",
            RiskLevel::High => "high",
            RiskLevel::Critical => "critical",
        }
    }
}

/// Points added to a tool's score when its description scan raised a
/// high-severity finding.
pub const DESCRIPTION_FINDING_PENALTY: u32 = 20;
/// Points added to a tool's score when its definition drifted from the pin.
pub const DRIFT_PENALTY: u32 = 20;
/// Points per distinct non-read-only capability beyond the first that a
/// server's score gains for breadth.
pub const BREADTH_BONUS: u32 = 2;
/// Upper bound of the breadth bonus.
pub const MAX_BREADTH_BONUS: u32 = 10;

/// Capability part of a tool's score: the heaviest weight plus a quarter of
/// the others, capped at 100.
pub fn capability_score(caps: &[Capability]) -> u8 {
    let mut distinct = caps.to_vec();
    distinct.sort_unstable();
    distinct.dedup();
    let mut weights: Vec<u32> = distinct.iter().map(Capability::weight).collect();
    weights.sort_unstable();
    let Some(max) = weights.pop() else { return 0 };
    let rest: u32 = weights.iter().sum();
    // `max + rest / 4`, rounded to the nearest point.
    let score = max + (rest + 2) / 4;
    score.min(100) as u8
}

/// Score of one tool: [`capability_score`] plus penalties for a high
/// severity description finding and for drift, capped at 100.
pub fn tool_score(caps: &[Capability], description_finding: bool, drifted: bool) -> u8 {
    let mut score = u32::from(capability_score(caps));
    if description_finding {
        score += DESCRIPTION_FINDING_PENALTY;
    }
    if drifted {
        score += DRIFT_PENALTY;
    }
    score.min(100) as u8
}

/// Score of a server: its highest tool score plus [`BREADTH_BONUS`] for
/// every distinct non-read-only capability beyond the first (at most
/// [`MAX_BREADTH_BONUS`]), capped at 100.
pub fn server_score(tool_scores: &[u8], capabilities: &[Capability]) -> u8 {
    let max = tool_scores.iter().copied().max().unwrap_or(0);
    let mut distinct: Vec<Capability> = capabilities.iter().copied().filter(|c| *c != Capability::ReadOnly).collect();
    distinct.sort_unstable();
    distinct.dedup();
    let bonus = (distinct.len().saturating_sub(1) as u32 * BREADTH_BONUS).min(MAX_BREADTH_BONUS);
    (u32::from(max) + bonus).min(100) as u8
}

#[cfg(test)]
mod tests {
    use super::*;
    use Capability::*;

    #[test]
    fn names_round_trip() {
        for c in Capability::ALL {
            assert_eq!(c.as_str().parse::<Capability>().unwrap(), c);
            assert_eq!(serde_json::to_value(c).unwrap(), serde_json::json!(c.as_str()));
            assert_eq!(c.to_string(), c.as_str());
        }
        assert_eq!(" Payment ".parse::<Capability>().unwrap(), Payment);
        assert!("money".parse::<Capability>().is_err());
    }

    #[test]
    fn weights_follow_the_table() {
        assert_eq!(CommandExecution.weight(), 40);
        assert_eq!(Payment.weight(), 40);
        assert_eq!(CredentialAccess.weight(), 35);
        assert_eq!(DataDeletion.weight(), 30);
        assert_eq!(IdentityAdmin.weight(), 30);
        assert_eq!(ExternalSend.weight(), 25);
        assert_eq!(FileDelete.weight(), 20);
        assert_eq!(DataModification.weight(), 15);
        assert_eq!(FileWrite.weight(), 15);
        assert_eq!(NetworkFetch.weight(), 10);
        assert_eq!(ReadOnly.weight(), 0);
    }

    #[test]
    fn scores_combine_max_and_a_quarter_of_the_rest() {
        assert_eq!(capability_score(&[]), 0);
        assert_eq!(capability_score(&[ReadOnly]), 0);
        assert_eq!(capability_score(&[NetworkFetch]), 10);
        // 40 + (25 + 10) / 4 = 48.75, rounded to 49.
        assert_eq!(capability_score(&[ExternalSend, CommandExecution, NetworkFetch]), 49);
        // Duplicates count once; 15 + 15 / 4 = 18.75, rounded to 19.
        assert_eq!(capability_score(&[DataModification, FileWrite, FileWrite]), 19);
        assert_eq!(tool_score(&[CommandExecution], true, false), 60);
        assert_eq!(tool_score(&[CommandExecution, Payment, CredentialAccess, IdentityAdmin], true, true), 100);
        assert_eq!(tool_score(&[ReadOnly], false, true), 20);
    }

    #[test]
    fn server_scores_add_breadth() {
        assert_eq!(server_score(&[], &[]), 0);
        assert_eq!(server_score(&[10, 40], &[NetworkFetch, CommandExecution]), 42);
        assert_eq!(server_score(&[0], &[ReadOnly]), 0);
        let all = Capability::ALL;
        assert_eq!(server_score(&[95], &all), 100);
        assert_eq!(server_score(&[40], &all), 50);
    }

    #[test]
    fn levels() {
        assert_eq!(RiskLevel::from_score(0), RiskLevel::Low);
        assert_eq!(RiskLevel::from_score(24), RiskLevel::Low);
        assert_eq!(RiskLevel::from_score(25), RiskLevel::Medium);
        assert_eq!(RiskLevel::from_score(49), RiskLevel::Medium);
        assert_eq!(RiskLevel::from_score(50), RiskLevel::High);
        assert_eq!(RiskLevel::from_score(74), RiskLevel::High);
        assert_eq!(RiskLevel::from_score(75), RiskLevel::Critical);
        assert_eq!(RiskLevel::from_score(100), RiskLevel::Critical);
        assert!(RiskLevel::Critical > RiskLevel::High);
        assert_eq!(RiskLevel::High.as_str(), "high");
    }
}
