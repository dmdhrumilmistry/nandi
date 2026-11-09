//! The nandi inspection engine.
//!
//! [`Engine`] turns normalized [`nandi_core::Event`]s into
//! [`nandi_core::Decision`]s. It combines policy ([`nandi_policy`]), content
//! detection ([`nandi_detect`]), tool and card pinning, session taint and
//! value-flow tracking, plans, budgets, behaviour models and host-sensor
//! correlation.

pub mod behavior;
pub mod budget;
mod engine;
pub mod flow;
pub mod pins;
pub mod session;

pub use engine::{Classifier, Engine, LOCAL_SERVER, spotlight, spotlight_instructions};

#[cfg(test)]
mod tests;
