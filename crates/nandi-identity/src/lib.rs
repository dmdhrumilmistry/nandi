//! Agent identity for nandi.
//!
//! - [`Authenticator`]: turns request credentials (mTLS identity, Biscuit
//!   capability token, JWT bearer token, API key) into a [`Principal`].
//! - [`biscuit`]: minting, attenuating and authorizing Biscuit delegation
//!   tokens scoped to `server/tool` patterns.
//! - [`card`]: A2A Agent Card signature verification (detached JWS).
//! - [`hash_key`] / [`generate_api_key`]: API key helpers for the CLI.

mod auth;
pub mod biscuit;
pub mod card;
mod error;
mod jwk;
mod keys;

pub use auth::{AuthMethod, Authenticator, Principal};
pub use biscuit::BiscuitGrant;
pub use card::{CardVerification, TrustedKeys, verify_card};
pub use error::AuthError;
pub use keys::{generate_api_key, hash_key};
