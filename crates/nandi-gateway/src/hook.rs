//! Coding-agent hook adapters.

use std::sync::Arc;

use serde_json::Value;

use crate::App;

/// Hook payload dialects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookFormat {
    ClaudeCode,
    Cursor,
    Generic,
}

impl std::str::FromStr for HookFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "claude-code" | "claude" => Ok(Self::ClaudeCode),
            "cursor" => Ok(Self::Cursor),
            "generic" => Ok(Self::Generic),
            other => Err(format!("unknown hook format {other}")),
        }
    }
}

/// What the hook process must print and exit with.
#[derive(Debug, Clone, PartialEq)]
pub struct HookResponse {
    /// JSON written to stdout (may be `Value::Null` for no output).
    pub stdout: Value,
    /// Text written to stderr (shown to the agent / user by some hosts).
    pub stderr: String,
    pub exit_code: i32,
}

/// Evaluate one hook payload inside a running nandi (admin endpoint).
pub async fn handle(app: &Arc<App>, format: HookFormat, input: Value) -> HookResponse {
    let _ = (app, format, input);
    HookResponse { stdout: Value::Null, stderr: String::new(), exit_code: 0 }
}

/// Entry point of `nandi hook <format>`: read the payload from stdin, send it
/// to the admin API at `admin_url`, print the response. Falls back to
/// `fail_open` behaviour when nandi is unreachable. Returns the exit code.
pub async fn client_main(format: HookFormat, admin_url: &str, token: Option<&str>, fail_open: bool) -> i32 {
    let _ = (format, admin_url, token, fail_open);
    0
}
