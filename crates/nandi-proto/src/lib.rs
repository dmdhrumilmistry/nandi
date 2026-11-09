//! Protocol parsing and rewriting for nandi.
//!
//! Everything here is pure: no I/O, no async, no crypto. The gateway feeds
//! raw bodies and stream chunks in and gets normalized
//! [`nandi_core::Event`] payloads (or rewritten bodies) out.
//!
//! - [`sse`]: incremental Server-Sent Events parser and encoder.
//! - [`llm`]: OpenAI (Chat Completions and Responses), Anthropic Messages
//!   and Gemini request / response / stream parsing.
//! - [`mcp`]: JSON-RPC 2.0 and Model Context Protocol helpers.
//! - [`a2a`]: Agent2Agent protocol requests, responses and Agent Cards.

pub mod a2a;
pub mod llm;
pub mod mcp;
pub mod sse;
mod util;

pub use sse::{SseEvent, SseParser};
