//! Capture points and runtime services for nandi.
//!
//! - [`proxy`]: HTTP gateway in front of LLM APIs, MCP servers and A2A agents.
//! - [`stdio`]: `nandi wrap`, an interposer for stdio MCP servers.
//! - [`hook`]: coding-agent hook adapters (Claude Code, Cursor, generic).
//! - [`admin`]: admin API, dashboard, metrics endpoint.
//! - [`app`]: shared state; [`App::decide`] is the single evaluate, approve
//!   and record path used by all of them.

pub mod admin;
pub mod app;
pub mod approvals;
pub mod client;
pub mod graph;
pub mod hook;
pub mod metrics;
pub mod osv;
pub mod otlp;
pub mod policies;
pub mod proxy;
pub mod recorder;
pub mod stdio;
pub mod users;

pub use app::{App, Verdicted};
