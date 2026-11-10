//! Placeholder used when the crate is built without the `onnx` feature.

use std::path::Path;

/// Prompt-injection classifier. This build has no model runtime: [`load`]
/// always fails.
///
/// [`load`]: PromptInjectionClassifier::load
#[derive(Debug)]
pub struct PromptInjectionClassifier {
    _private: (),
}

impl PromptInjectionClassifier {
    /// Always fails: the crate was built without the `onnx` feature.
    pub fn load(
        _model: &Path,
        _tokenizer: &Path,
        _onnxruntime: Option<&Path>,
        _max_tokens: usize,
    ) -> anyhow::Result<Self> {
        anyhow::bail!("nandi was built without the onnx feature (rebuild with `--features ml`)")
    }
}

impl nandi_engine::Classifier for PromptInjectionClassifier {
    fn score(&self, _text: &str) -> Option<f32> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_reports_missing_feature() {
        let err = PromptInjectionClassifier::load(Path::new("m.onnx"), Path::new("t.json"), None, 512).unwrap_err();
        assert!(err.to_string().contains("built without the onnx feature"), "{err}");
    }
}
