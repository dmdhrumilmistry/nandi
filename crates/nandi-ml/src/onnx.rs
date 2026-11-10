//! The ONNX Runtime backed classifier (cargo feature `onnx`).

use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, anyhow, bail, ensure};
use ort::session::builder::GraphOptimizationLevel;
use ort::session::{Session, SessionInputValue};
use ort::value::{Tensor, TensorElementType};
use parking_lot::Mutex;
use tokenizers::Tokenizer;

use crate::prep::{self, MAX_TEXT_BYTES, MAX_WINDOWS};

/// Shortest content window accepted (`max_tokens` minus special tokens).
const MIN_WINDOW: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InputKind {
    Ids,
    Mask,
    TypeIds,
}

#[derive(Debug, Clone)]
struct ModelInput {
    name: String,
    kind: InputKind,
    int32: bool,
}

/// Prompt-injection classifier backed by an ONNX sequence-classification
/// model and its HuggingFace tokenizer.
pub struct PromptInjectionClassifier {
    /// `Session::run` needs `&mut`; calls are serialized.
    session: Mutex<Session>,
    tokenizer: Tokenizer,
    inputs: Vec<ModelInput>,
    output: String,
    prefix: Vec<u32>,
    suffix: Vec<u32>,
    pad_id: u32,
    window: usize,
    overlap: usize,
    classes: Option<Vec<usize>>,
    failed: AtomicBool,
}

impl std::fmt::Debug for PromptInjectionClassifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PromptInjectionClassifier")
            .field("inputs", &self.inputs)
            .field("output", &self.output)
            .field("window", &self.window)
            .field("overlap", &self.overlap)
            .field("classes", &self.classes)
            .finish_non_exhaustive()
    }
}

fn ort_err<R>(e: ort::Error<R>) -> anyhow::Error {
    anyhow!("{e}")
}

fn tok_err(e: tokenizers::Error) -> anyhow::Error {
    anyhow!("{e}")
}

/// Load the ONNX Runtime shared library once per process. Later calls reuse
/// the library loaded first.
fn init_runtime(path: Option<&Path>) -> anyhow::Result<()> {
    let path: PathBuf = match path {
        Some(p) => p.to_path_buf(),
        None => match std::env::var_os("ORT_DYLIB_PATH") {
            Some(p) if !p.is_empty() => p.into(),
            _ => default_library().into(),
        },
    };
    let env = ort::init_from(&path).map_err(|e| anyhow!("loading ONNX Runtime from {}: {e}", path.display()))?;
    env.with_name("nandi").with_telemetry(false).commit();
    Ok(())
}

fn default_library() -> &'static str {
    if cfg!(target_os = "windows") {
        "onnxruntime.dll"
    } else if cfg!(target_os = "macos") {
        "libonnxruntime.dylib"
    } else {
        "libonnxruntime.so"
    }
}

fn pad_id(tokenizer: &Tokenizer) -> u32 {
    if let Some(p) = tokenizer.get_padding() {
        return p.pad_id;
    }
    ["[PAD]", "<pad>", "<PAD>"].iter().find_map(|t| tokenizer.token_to_id(t)).unwrap_or(0)
}

impl PromptInjectionClassifier {
    /// Load the model and tokenizer.
    ///
    /// - `model`: ONNX sequence-classification model. A HuggingFace
    ///   `config.json` next to it, when present, names the malicious class
    ///   (`id2label`); otherwise the last class is used.
    /// - `tokenizer`: HuggingFace `tokenizer.json` for the model.
    /// - `onnxruntime`: `libonnxruntime` to load; defaults to
    ///   `ORT_DYLIB_PATH`, then the platform library name on the loader's
    ///   search path. Only the first load in a process takes effect.
    /// - `max_tokens`: model input length per window, special tokens
    ///   included (512 for DeBERTa-based models).
    pub fn load(model: &Path, tokenizer: &Path, onnxruntime: Option<&Path>, max_tokens: usize) -> anyhow::Result<Self> {
        let mut tok =
            Tokenizer::from_file(tokenizer).map_err(|e| anyhow!("loading tokenizer {}: {e}", tokenizer.display()))?;
        let pad_id = pad_id(&tok);
        tok.with_truncation(None).map_err(tok_err)?;
        tok.with_padding(None);
        let probe = tok.encode("probe", true).map_err(tok_err)?;
        let (prefix, suffix) = prep::special_layout(probe.get_ids(), probe.get_special_tokens_mask());
        let specials = prefix.len() + suffix.len();
        ensure!(
            max_tokens >= specials + MIN_WINDOW,
            "ml.max_tokens is {max_tokens}; it must be at least {} for this tokenizer",
            specials + MIN_WINDOW
        );
        let window = max_tokens - specials;
        let overlap = window / 8;

        let classes = match std::fs::read_to_string(model.with_file_name("config.json")) {
            Ok(s) => prep::malicious_classes(&s),
            Err(_) => None,
        };

        init_runtime(onnxruntime)?;
        let mut builder = Session::builder()
            .map_err(ort_err)?
            .with_intra_threads(1)
            .map_err(ort_err)?
            .with_inter_threads(1)
            .map_err(ort_err)?
            .with_optimization_level(GraphOptimizationLevel::Level3)
            // Minimal runtime builds reject optimization settings.
            .unwrap_or_else(|e| e.recover());
        let session = builder.commit_from_file(model).map_err(|e| anyhow!("loading model {}: {e}", model.display()))?;

        let mut inputs = Vec::new();
        for input in session.inputs() {
            let kind = match input.name() {
                "input_ids" => InputKind::Ids,
                "attention_mask" => InputKind::Mask,
                "token_type_ids" => InputKind::TypeIds,
                other => {
                    bail!("unsupported model input `{other}` (expected input_ids, attention_mask, token_type_ids)")
                }
            };
            let int32 = match input.dtype().tensor_type() {
                Some(TensorElementType::Int64) => false,
                Some(TensorElementType::Int32) => true,
                other => bail!("model input `{}` has unsupported type {other:?}", input.name()),
            };
            inputs.push(ModelInput { name: input.name().to_string(), kind, int32 });
        }
        ensure!(inputs.iter().any(|i| i.kind == InputKind::Ids), "model has no `input_ids` input");
        let output = session
            .outputs()
            .iter()
            .find(|o| o.name() == "logits")
            .or_else(|| session.outputs().first())
            .map(|o| o.name().to_string())
            .context("model has no outputs")?;

        let c = Self {
            session: Mutex::new(session),
            tokenizer: tok,
            inputs,
            output,
            prefix,
            suffix,
            pad_id,
            window,
            overlap,
            classes,
            failed: AtomicBool::new(false),
        };
        tracing::info!(model = %model.display(), classifier = ?c, "prompt-injection classifier loaded");
        Ok(c)
    }

    /// Malicious-class probability of `text`: the maximum over its token
    /// windows.
    pub fn try_score(&self, text: &str) -> anyhow::Result<f32> {
        Ok(self.window_scores(text)?.into_iter().fold(0.0, f32::max))
    }

    /// Malicious-class probability of each scored token window of `text`,
    /// in document order.
    pub fn window_scores(&self, text: &str) -> anyhow::Result<Vec<f32>> {
        let text = prep::truncate(text, MAX_TEXT_BYTES);
        let enc = self.tokenizer.encode(text, false).map_err(tok_err)?;
        let ids = enc.get_ids();
        let windows = prep::windows(ids.len(), self.window, self.overlap, MAX_WINDOWS);
        let prep::Batch { rows, cols, input_ids, attention_mask } =
            prep::build_batch(ids, &windows, &self.prefix, &self.suffix, self.pad_id);
        let shape = [rows as i64, cols as i64];
        let mut values: Vec<(Cow<'_, str>, SessionInputValue<'_>)> = Vec::with_capacity(self.inputs.len());
        for input in &self.inputs {
            let data = match input.kind {
                InputKind::Ids => input_ids.clone(),
                InputKind::Mask => attention_mask.clone(),
                InputKind::TypeIds => vec![0; rows * cols],
            };
            let value: SessionInputValue<'_> = if input.int32 {
                let data: Vec<i32> = data.into_iter().map(|v| v as i32).collect();
                Tensor::from_array((shape, data)).map_err(ort_err)?.into()
            } else {
                Tensor::from_array((shape, data)).map_err(ort_err)?.into()
            };
            values.push((Cow::Borrowed(input.name.as_str()), value));
        }
        let mut session = self.session.lock();
        let outputs = session.run(values).map_err(ort_err)?;
        let (shape, logits) = outputs[self.output.as_str()].try_extract_tensor::<f32>().map_err(ort_err)?;
        let labels = shape.last().copied().unwrap_or(0).max(0) as usize;
        prep::row_malicious(logits, labels, self.classes.as_deref())
            .with_context(|| format!("unexpected logits shape {:?}", &**shape))
    }
}

impl nandi_engine::Classifier for PromptInjectionClassifier {
    fn score(&self, text: &str) -> Option<f32> {
        match self.try_score(text) {
            Ok(p) => Some(p),
            Err(e) => {
                if !self.failed.swap(true, Ordering::Relaxed) {
                    tracing::error!(error = %e, "prompt-injection classifier failed; further errors are logged at debug");
                } else {
                    tracing::debug!(error = %e, "prompt-injection classifier failed");
                }
                None
            }
        }
    }
}
