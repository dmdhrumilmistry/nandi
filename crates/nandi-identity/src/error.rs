//! Authentication and authorization errors.

use thiserror::Error;

/// Why a request could not be authenticated or authorized.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AuthError {
    /// No credential was presented and anonymous access is disabled.
    #[error("no credentials presented")]
    Missing,
    /// A credential was presented but is not valid.
    #[error("invalid {method} credential: {reason}")]
    Invalid { method: &'static str, reason: String },
    /// The credential is valid but does not grant the requested action.
    #[error("forbidden: {0}")]
    Forbidden(String),
}

impl AuthError {
    pub(crate) fn invalid(method: &'static str, reason: impl Into<String>) -> Self {
        AuthError::Invalid { method, reason: reason.into() }
    }
}
