//! Optional model-based prompt-injection classifier for nandi.
//!
//! [`PromptInjectionClassifier`] runs a sequence-classification model
//! exported to ONNX (for example `protectai/deberta-v3-base-prompt-injection-v2`
//! or Llama Prompt Guard 2) on untrusted text and implements
//! [`nandi_engine::Classifier`]. The engine calls it on tool results, inbound
//! A2A messages and tool messages in LLM requests when `ml.enabled` is set.
//!
//! The real implementation sits behind the `onnx` cargo feature. It loads
//! the ONNX Runtime shared library at runtime (from `ml.onnxruntime` or
//! `ORT_DYLIB_PATH`), so nothing is downloaded at build time and builds
//! without the feature carry no ML dependencies at all; there
//! [`PromptInjectionClassifier::load`] returns an error.
//!
//! Long inputs are split into overlapping token windows (at most
//! [`prep::MAX_WINDOWS`] per call, scored in one batch) and the score is the
//! highest malicious-class probability over the windows.

pub mod prep;

#[cfg(feature = "onnx")]
mod onnx;
#[cfg(feature = "onnx")]
pub use onnx::PromptInjectionClassifier;

#[cfg(not(feature = "onnx"))]
mod stub;
#[cfg(not(feature = "onnx"))]
pub use stub::PromptInjectionClassifier;

/// Whether this build includes the ONNX classifier (cargo feature `onnx`).
pub const AVAILABLE: bool = cfg!(feature = "onnx");
