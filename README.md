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
  base64 / hex / URL decoding, and redaction.
- **Behaviour analytics**: per-agent tool-sequence models, loop and rate
  detection, temporal rules, plan-locked execution.
- **Controls**: human approval queue, kill switch, token and call budgets.
- **Host sensing** (Linux, eBPF): process, file and network effects of agent
  processes, correlated with the tool calls they declared; shadow AI
  detection.

It ships as a single static binary with a low memory and CPU footprint. All
in-path checks are deterministic; nothing calls an LLM to make a decision.

## Status

Under active development. Milestones:

- [x] M0 Scaffold, core event model, configuration, CI
- [ ] M1 Signed audit store
- [ ] M2 Stdio MCP wrapper, tool pinning, Cedar and YAML policy
- [ ] M3 HTTP gateway for LLM APIs and MCP, budgets
- [ ] M4 Detectors and redaction
- [ ] M5 Taint, value flow, temporal rules, plan-locked mode
- [ ] M6 Behaviour models
- [ ] M7 Approvals, kill switch, dashboard, OTLP, metrics
- [ ] M8 A2A security and Biscuit delegation
- [ ] M9 Coding-agent hooks
- [ ] M10 eBPF sensor
- [ ] M11 Optional ONNX injection classifier
- [ ] M12 Evaluation harness

## Usage

See [docs/usage.md](docs/usage.md) for the quick start, SDK, MCP and
coding-agent setup, and the operator workflow.

## Design

See [docs/architecture.md](docs/architecture.md) for how the pieces fit and
[docs/research.md](docs/research.md) for the products and papers each
feature comes from.

## License

Apache-2.0
