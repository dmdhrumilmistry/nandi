//! Core types shared by every nandi crate: the normalized [`Event`] model,
//! [`Decision`]s and [`Finding`]s, the `nandi.yaml` [`Config`], tool
//! [`Capability`]s, MCP [`ServerSpec`]s, and helpers.

pub mod capability;
pub mod config;
pub mod decision;
pub mod error;
pub mod event;
pub mod server;
pub mod state;
pub mod util;

pub use capability::{Capability, RiskLevel};
pub use config::Config;
pub use decision::{Category, Decision, Finding, Severity, Verdict};
pub use error::{Error, Result};
pub use event::*;
pub use server::{Advisory, AdvisoryCheck, Ecosystem, PackageRef, ServerSpec};
pub use state::{MemoryStore, StateStore};
