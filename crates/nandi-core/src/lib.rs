//! Core types shared by every nandi crate: the normalized [`Event`] model,
//! [`Decision`]s and [`Finding`]s, the `nandi.yaml` [`Config`], and helpers.

pub mod config;
pub mod decision;
pub mod error;
pub mod event;
pub mod state;
pub mod util;

pub use config::Config;
pub use decision::{Category, Decision, Finding, Severity, Verdict};
pub use error::{Error, Result};
pub use event::*;
pub use state::{MemoryStore, StateStore};
