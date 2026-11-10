//! Model-independent pre- and post-processing: windowing long token
//! sequences, building padded batches, softmax and finding the malicious
//! class in a HuggingFace `config.json`.
//!
//! Nothing here needs ONNX Runtime or a tokenizer, so it is always compiled
//! and unit tested without a model.

use std::ops::Range;

/// Upper bound on windows scored per call. Each window is a full model pass,
/// so this bounds the latency of one `score` call.
pub const MAX_WINDOWS: usize = 4;

/// Text longer than this (in bytes, cut on a char boundary) is truncated
/// before tokenization.
pub const MAX_TEXT_BYTES: usize = 16 * 1024;

/// Labels that mark a class as malicious (matched case-insensitively as
/// substrings of the `id2label` value).
const MALICIOUS_LABELS: &[&str] = &["INJECTION", "JAILBREAK", "MALICIOUS", "UNSAFE"];

/// Cut `text` to at most `max` bytes without splitting a character.
pub fn truncate(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// Token windows over a sequence of `len` content tokens.
///
/// Windows hold at most `size` tokens and consecutive windows share
/// `overlap` tokens, so an injection that straddles a boundary is still
/// seen whole by one window (when it is shorter than the overlap). The last
/// window is aligned to the end of the sequence. When more than
/// `max_windows` would be needed, an evenly spaced subset is kept that
/// always includes the first and the last window: injected instructions
/// tend to sit at the start or the end of a document.
///
/// An empty sequence yields one empty window.
pub fn windows(len: usize, size: usize, overlap: usize, max_windows: usize) -> Vec<Range<usize>> {
    let size = size.max(1);
    if len <= size {
        return std::iter::once(0..len).collect();
    }
    let step = size.saturating_sub(overlap).max(1);
    let count = (len - size).div_ceil(step) + 1;
    let start = |i: usize| if i + 1 == count { len - size } else { i * step };
    let max_windows = max_windows.max(1);
    let picked: Vec<usize> = if count <= max_windows {
        (0..count).collect()
    } else if max_windows == 1 {
        vec![0]
    } else {
        let mut v: Vec<usize> =
            (0..max_windows).map(|k| (k * (count - 1) + (max_windows - 1) / 2) / (max_windows - 1)).collect();
        v.dedup();
        v
    };
    picked.into_iter().map(|i| start(i)..start(i) + size).collect()
}

/// Split the special tokens a tokenizer's post-processor adds around a
/// single sequence into a prefix and a suffix (`[CLS]` ... `[SEP]`,
/// `<s>` ... `</s>`). `ids` and `special_mask` come from encoding a short
/// probe text with special tokens; `special_mask` is 1 for added tokens.
pub fn special_layout(ids: &[u32], special_mask: &[u32]) -> (Vec<u32>, Vec<u32>) {
    let n = ids.len().min(special_mask.len());
    let lead = special_mask[..n].iter().take_while(|m| **m != 0).count();
    if lead == n {
        // Nothing but special tokens: treat them all as a prefix.
        return (ids[..n].to_vec(), Vec::new());
    }
    let trail = special_mask[..n].iter().rev().take_while(|m| **m != 0).count();
    (ids[..lead].to_vec(), ids[n - trail..n].to_vec())
}

/// A padded batch of token ids, row-major `[rows, cols]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Batch {
    pub rows: usize,
    pub cols: usize,
    pub input_ids: Vec<i64>,
    pub attention_mask: Vec<i64>,
}

/// Wrap each window of `content` in `prefix` and `suffix` and right-pad the
/// rows to the longest one with `pad_id` (attention mask 0).
pub fn build_batch(content: &[u32], windows: &[Range<usize>], prefix: &[u32], suffix: &[u32], pad_id: u32) -> Batch {
    let extra = prefix.len() + suffix.len();
    let rows = windows.len();
    let cols = windows.iter().map(|w| w.len() + extra).max().unwrap_or(extra);
    let mut input_ids = Vec::with_capacity(rows * cols);
    let mut attention_mask = Vec::with_capacity(rows * cols);
    for w in windows {
        let row = prefix.iter().chain(&content[w.clone()]).chain(suffix);
        let used = w.len() + extra;
        input_ids.extend(row.map(|t| i64::from(*t)));
        input_ids.extend(std::iter::repeat_n(i64::from(pad_id), cols - used));
        attention_mask.extend(std::iter::repeat_n(1, used));
        attention_mask.extend(std::iter::repeat_n(0, cols - used));
    }
    Batch { rows, cols, input_ids, attention_mask }
}

/// Numerically stable softmax.
pub fn softmax(logits: &[f32]) -> Vec<f32> {
    let max = logits.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    if !max.is_finite() {
        return vec![0.0; logits.len()];
    }
    let exps: Vec<f32> = logits.iter().map(|l| (l - max).exp()).collect();
    let sum: f32 = exps.iter().sum();
    exps.into_iter().map(|e| e / sum).collect()
}

/// Probability mass of the malicious classes in one row of logits. With no
/// known classes, the last class is taken as malicious.
pub fn malicious_probability(logits: &[f32], classes: Option<&[usize]>) -> f32 {
    let probs = softmax(logits);
    let p = match classes {
        Some(c) if c.iter().any(|i| *i < probs.len()) => c.iter().filter_map(|i| probs.get(*i)).sum(),
        _ => probs.last().copied().unwrap_or(0.0),
    };
    p.clamp(0.0, 1.0)
}

/// The highest malicious probability over the rows of a `[rows, labels]`
/// logits tensor.
pub fn max_malicious(logits: &[f32], labels: usize, classes: Option<&[usize]>) -> Option<f32> {
    if labels == 0 || logits.is_empty() || !logits.len().is_multiple_of(labels) {
        return None;
    }
    logits.chunks_exact(labels).map(|row| malicious_probability(row, classes)).reduce(f32::max)
}

/// Indices of the malicious classes from a HuggingFace `config.json`
/// (`id2label`). A label matches when it contains INJECTION, JAILBREAK,
/// MALICIOUS or UNSAFE; generic two-class labels (`LABEL_0`, `LABEL_1`)
/// map to class 1. Returns `None` when nothing matches, in which case the
/// caller falls back to the last class.
pub fn malicious_classes(config_json: &str) -> Option<Vec<usize>> {
    let v: serde_json::Value = serde_json::from_str(config_json).ok()?;
    let labels = v.get("id2label")?.as_object()?;
    let mut parsed: Vec<(usize, String)> = labels
        .iter()
        .filter_map(|(k, v)| Some((k.trim().parse::<usize>().ok()?, v.as_str()?.to_ascii_uppercase())))
        .collect();
    parsed.sort();
    let mut out: Vec<usize> =
        parsed.iter().filter(|(_, l)| MALICIOUS_LABELS.iter().any(|m| l.contains(m))).map(|(i, _)| *i).collect();
    if out.is_empty() {
        out = parsed.iter().filter(|(_, l)| l == "LABEL_1").map(|(i, _)| *i).collect();
    }
    (!out.is_empty()).then_some(out)
}

#[cfg(test)]
#[allow(clippy::single_range_in_vec_init)]
mod tests {
    use super::*;

    #[test]
    fn truncate_respects_char_boundaries() {
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("hello", 3), "hel");
        // "é" is two bytes; cutting inside it backs off.
        assert_eq!(truncate("aé", 2), "a");
        assert_eq!(truncate("", 0), "");
    }

    #[test]
    fn short_sequences_use_one_window() {
        assert_eq!(windows(0, 10, 2, 4), vec![0..0]);
        assert_eq!(windows(7, 10, 2, 4), vec![0..7]);
        assert_eq!(windows(10, 10, 2, 4), vec![0..10]);
    }

    #[test]
    fn windows_overlap_and_end_aligned() {
        // size 10, step 8: starts 0, 8, then the last window ends at 20.
        let w = windows(20, 10, 2, 8);
        assert_eq!(w, vec![0..10, 8..18, 10..20]);
        for pair in w.windows(2) {
            assert!(pair[1].start < pair[0].end, "consecutive windows overlap");
        }
        assert!(w.iter().all(|r| r.len() == 10));
        assert_eq!(w.last().unwrap().end, 20);
    }

    #[test]
    fn windows_cover_every_token() {
        for len in [17, 37, 100, 513, 1000] {
            let w = windows(len, 16, 4, usize::MAX);
            let mut covered = vec![false; len];
            for r in &w {
                assert!(r.end <= len && r.len() == 16);
                covered[r.clone()].iter_mut().for_each(|c| *c = true);
            }
            assert!(covered.iter().all(|c| *c), "len {len} not fully covered");
        }
    }

    #[test]
    fn capped_windows_keep_first_and_last() {
        let all = windows(1000, 100, 20, usize::MAX);
        assert!(all.len() > 4);
        let capped = windows(1000, 100, 20, 4);
        assert_eq!(capped.len(), 4);
        assert_eq!(capped[0], 0..100);
        assert_eq!(capped[3], 900..1000);
        assert!(capped.windows(2).all(|p| p[0].start < p[1].start));
        assert!(capped.iter().all(|r| all.contains(r)));
        assert_eq!(windows(1000, 100, 20, 1), vec![0..100]);
    }

    #[test]
    fn overlap_larger_than_window_still_advances() {
        let w = windows(5, 2, 10, 10);
        assert_eq!(w.first(), Some(&(0..2)));
        assert_eq!(w.last(), Some(&(3..5)));
    }

    #[test]
    fn special_layout_splits_prefix_and_suffix() {
        // [CLS] a b [SEP]
        assert_eq!(special_layout(&[1, 50, 51, 2], &[1, 0, 0, 1]), (vec![1], vec![2]));
        // <s> x </s> </s> (pair-style suffix)
        assert_eq!(special_layout(&[0, 9, 2, 2], &[1, 0, 1, 1]), (vec![0], vec![2, 2]));
        // No special tokens.
        assert_eq!(special_layout(&[5, 6], &[0, 0]), (vec![], vec![]));
        // Only special tokens.
        assert_eq!(special_layout(&[1, 2], &[1, 1]), (vec![1, 2], vec![]));
    }

    #[test]
    fn batch_is_wrapped_and_padded() {
        let content = [10, 11, 12, 13, 14];
        let b = build_batch(&content, &[0..3, 3..5], &[1], &[2], 0);
        assert_eq!((b.rows, b.cols), (2, 5));
        assert_eq!(b.input_ids, vec![1, 10, 11, 12, 2, 1, 13, 14, 2, 0]);
        assert_eq!(b.attention_mask, vec![1, 1, 1, 1, 1, 1, 1, 1, 1, 0]);
        let empty = build_batch(&[], &[0..0], &[1], &[2], 0);
        assert_eq!(empty.input_ids, vec![1, 2]);
    }

    #[test]
    fn softmax_is_stable_and_normalized() {
        let p = softmax(&[1000.0, 1000.0]);
        assert!((p[0] - 0.5).abs() < 1e-6 && (p[1] - 0.5).abs() < 1e-6);
        let p = softmax(&[0.0, 2.0, -1.0]);
        assert!((p.iter().sum::<f32>() - 1.0).abs() < 1e-6);
        assert!(p[1] > p[0] && p[0] > p[2]);
        assert_eq!(softmax(&[]), Vec::<f32>::new());
    }

    #[test]
    fn malicious_probability_uses_classes_or_last() {
        let logits = [0.0, 0.0, 0.0, 0.0];
        assert!((malicious_probability(&logits, None) - 0.25).abs() < 1e-6);
        assert!((malicious_probability(&logits, Some(&[1, 2])) - 0.5).abs() < 1e-6);
        // Out-of-range indices fall back to the last class.
        assert!((malicious_probability(&logits, Some(&[9])) - 0.25).abs() < 1e-6);
        let p = malicious_probability(&[-4.0, 4.0], Some(&[1]));
        assert!(p > 0.99);
    }

    #[test]
    fn max_over_rows() {
        let logits = [4.0, -4.0, -4.0, 4.0, 0.0, 0.0];
        let p = max_malicious(&logits, 2, Some(&[1])).unwrap();
        assert!(p > 0.99);
        assert_eq!(max_malicious(&logits, 4, None), None);
        assert_eq!(max_malicious(&[], 2, None), None);
    }

    #[test]
    fn label_detection() {
        let protectai = r#"{"id2label": {"0": "SAFE", "1": "INJECTION"}}"#;
        assert_eq!(malicious_classes(protectai), Some(vec![1]));
        let prompt_guard_2 = r#"{"id2label": {"0": "BENIGN", "1": "MALICIOUS"}}"#;
        assert_eq!(malicious_classes(prompt_guard_2), Some(vec![1]));
        let prompt_guard_1 = r#"{"id2label": {"0": "BENIGN", "1": "INJECTION", "2": "JAILBREAK"}}"#;
        assert_eq!(malicious_classes(prompt_guard_1), Some(vec![1, 2]));
        let generic = r#"{"id2label": {"0": "LABEL_0", "1": "LABEL_1"}}"#;
        assert_eq!(malicious_classes(generic), Some(vec![1]));
        let reversed = r#"{"id2label": {"0": "jailbreak", "1": "benign"}}"#;
        assert_eq!(malicious_classes(reversed), Some(vec![0]));
        assert_eq!(malicious_classes(r#"{"id2label": {"0": "NEG", "1": "POS"}}"#), None);
        assert_eq!(malicious_classes(r#"{"model_type": "bert"}"#), None);
        assert_eq!(malicious_classes("not json"), None);
    }
}
