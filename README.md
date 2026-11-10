# nandi

> Nandi guards the gate of Kailash and decides who may enter. nandi does the
> same for your AI agents.

nandi is a lightweight zero-trust gateway and runtime monitor for AI agents,
written in Rust. It sits between agents and everything they talk to (LLM
APIs, MCP servers, other agents over A2A, the host itself) and gives you:

- **Visibility**: every LLM request, tool list, tool call, tool result and
  A2A message as a structured event, exported as OpenTelemetry GenAI spans
  and Prometheus metrics, and kept in a signed, hash-chained audit log.
- **Zero-trust policy**: agent identity (API keys, JWT/OIDC, mTLS/SPIFFE,
  Biscuit delegation tokens), Cedar and YAML policies over tools and their
  arguments, default-deny mode, identity-filtered tool lists.
- **Tool integrity**: MCP tool definitions are hash-pinned; silent changes
  (rug pulls) and poisoned descriptions are caught.
- **Data-flow security**: sessions that read untrusted content are tainted;
  consequential tools (send, write, exec, pay) are escalated, and calls that
  reuse values copied from untrusted output are held for approval.
- **Detection**: secrets, PII, prompt injection, SSRF, honeytokens, with
  base64 / hex / URL decoding, and redaction; an optional ONNX classifier
  scores untrusted content for injections.
- **Behaviour analytics**: per-agent tool-sequence models, loop and rate
  detection, temporal rules, plan-locked execution.
- **Controls**: human approval queue, kill switch, token and call budgets.
- **Host sensing** (Linux, eBPF): process, file and network effects of agent
  processes, correlated with the tool calls they declared; shadow AI
  detection.

It ships as a single static binary with a low memory and CPU footprint. All
in-path checks are deterministic; nothing calls an LLM to make a decision.

## Status

Pre-release, under active development.

- [x] Core event model, configuration, CI
- [x] Signed hash-chained audit log
- [x] Policy: Cedar, YAML argument rules, sequence rules, plans, default deny
- [x] Detectors: secrets, PII, honeytokens, injection, SSRF, tool poisoning
- [x] Protocol parsers (OpenAI, Anthropic, Gemini, MCP 2025-06-18 to 2026-07-28, A2A 1.0) and identity (API keys, JWT, mTLS, Biscuit)
- [x] Engine: taint and value flow, tool pinning, plans, budgets, behaviour models
- [x] Evaluation harness (41/41 attack checks, 0 false positives on the bundled corpus)
- [x] Host sensor (procfs backend)
- [x] Gateway (LLM, MCP, A2A), stdio wrapper, coding-agent hooks, admin API, dashboard, CLI
- [ ] eBPF sensor backend
- [x] Optional ONNX injection classifier (`--features ml`, off by default)

## Quick start

```sh
nandi init                 # writes nandi.yaml and example policies
nandi run                  # proxy on :8787, admin API and dashboard on :8788
```

Point an SDK at the proxy (`OPENAI_BASE_URL=http://127.0.0.1:8787/openai/v1`),
wrap stdio MCP servers with `nandi wrap --server NAME -- <command>`, or add
`nandi hook claude-code` / `nandi hook cursor` to your coding agent's hooks.
See [docs/usage.md](docs/usage.md) for the full guide.

## Design

See [docs/architecture.md](docs/architecture.md) for how the pieces fit and
[docs/research.md](docs/research.md) for the products and papers each
feature comes from.

## License

Apache-2.0
