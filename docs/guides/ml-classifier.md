# ML classifier

The pattern detector (`detect.injection`) catches known injection phrasing.
An optional ONNX classifier adds a model-based check for paraphrased and
novel injections. It is off by default and not part of the release binaries
or the Docker image.

It runs in-path on untrusted content only: MCP tool results, inbound A2A
messages and tool-role messages in LLM requests (up to 8192 characters per
item). A score at or above `ml.threshold` adds an `ml.injection` finding with
the `ml.on_detect` verdict. If the model fails at runtime, `fail_mode: closed`
adds an `ml.unavailable` alert; `open` lets the content through silently.

## Building

```sh
cargo build --release -p nandi --features ml   # binary in target/release/nandi
```

The feature adds `ort` and `tokenizers` (pure Rust, no C or C++ build). ONNX
Runtime itself is not linked or downloaded at build time: it is loaded when
nandi starts. The static musl builds cannot load shared libraries, so build
the `ml` binary for a glibc target (the default `x86_64-unknown-linux-gnu`,
or macOS).

## ONNX Runtime

Download a CPU build (1.17 or later; CI uses 1.31.1) from the
[ONNX Runtime releases](https://github.com/microsoft/onnxruntime/releases),
for example:

```sh
curl -fsSL https://github.com/microsoft/onnxruntime/releases/download/v1.31.1/onnxruntime-linux-x64-1.31.1.tgz \
  | tar -xz -C /opt
```

Point `ml.onnxruntime` at `lib/libonnxruntime.so` (`.dylib` on macOS), or set
`ORT_DYLIB_PATH`. With neither, the system loader's search path is used.

## Models

Any ONNX sequence-classification model with `input_ids` and `attention_mask`
(and optionally `token_type_ids`) inputs and a HuggingFace `tokenizer.json`
works. The malicious class is read from `id2label` in a `config.json` next to
the model (labels containing INJECTION, JAILBREAK, MALICIOUS or UNSAFE, or
`LABEL_1`); without one the last class is used.

- [protectai/deberta-v3-base-prompt-injection-v2](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2)
  (Apache-2.0). Ships an `onnx/` folder, so no export is needed:

  ```sh
  mkdir -p models/prompt-injection && cd models/prompt-injection
  for f in model.onnx tokenizer.json config.json; do
    curl -fsSLO "https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2/resolve/main/onnx/$f"
  done
  ```

  This is the model CI tests against.
- [Llama Prompt Guard 2](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-22M)
  (22M and 86M; BENIGN / MALICIOUS). Released under the Llama 4 Community
  License: the repository is gated, so accept the license on Hugging Face
  first, and the license and acceptable use policy apply to your deployment.
  Meta publishes safetensors only; export to ONNX with
  [Optimum](https://huggingface.co/docs/optimum):

  ```sh
  optimum-cli export onnx --model meta-llama/Llama-Prompt-Guard-2-22M \
    --task text-classification models/prompt-guard-2-22m
  ```

  The export writes `model.onnx`, `tokenizer.json` and `config.json` side by
  side. The 22M model is a fraction of the size of DeBERTa-base and the one to
  try first where memory or latency matters (it is not covered by CI because
  the repository is gated).

Check a model before deploying it (the test prints scores, latency and
memory):

```sh
export ORT_DYLIB_PATH=/opt/onnxruntime-linux-x64-1.31.1/lib/libonnxruntime.so
export NANDI_ML_MODEL=models/prompt-injection/model.onnx
cargo test -p nandi-ml --features onnx -- --ignored --nocapture
```

## Configuration

```yaml
ml:
  enabled: true
  model: models/prompt-injection/model.onnx
  # Default: tokenizer.json next to the model.
  tokenizer: models/prompt-injection/tokenizer.json
  onnxruntime: /opt/onnxruntime-linux-x64-1.31.1/lib/libonnxruntime.so
  threshold: 0.9
  on_detect: alert      # alert | ask | deny
  max_tokens: 512       # model input length, special tokens included
```

Relative paths are resolved against the directory of `nandi.yaml`. If the
model cannot be loaded, `nandi run` and `nandi wrap` refuse to start under
`fail_mode: closed` and start without the classifier (with a warning) under
`fail_mode: open`. A binary built without `--features ml` ignores the section
with a warning.

## Cost

Text is tokenized and split into windows of `max_tokens` tokens that overlap
by an eighth. At most four windows are scored per item (the first, the last
and evenly spaced ones between), in one batch, on one ONNX Runtime thread;
the score is the highest over the windows. Calls are serialized, so the
classifier uses at most one core.

Measured in CI (GitHub-hosted `ubuntu-latest`, ONNX Runtime 1.31.1,
protectai DeBERTa-v3-base in fp32, one thread):

| | |
|---|---|
| model load at startup | about 2 s |
| short tool result (one window) | 40 to 70 ms |
| 6 KB document (four 512-token windows) | 4 to 6 s |
| gateway RSS, idle, model loaded | about 1.3 GB |

The model file alone is 740 MB; without the classifier the gateway idles at
a few tens of MB. A smaller model such as Prompt Guard 2 22M cuts both
memory and latency; a lower `max_tokens` cuts latency but scores less of a
long document. Evaluation is marked as blocking while the classifier runs, so
other connections keep being served, but the agent waiting on the scored
content sees the full delay.

Start with `on_detect: alert`, watch the findings with
`nandi tail --min-verdict alert`, and tighten once the false-positive rate on
your traffic is known.
