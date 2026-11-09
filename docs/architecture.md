# Architecture

```
 agents (Claude Code, Cursor, LangGraph, CrewAI, custom)
        | LLM API        | MCP (stdio / HTTP)    | A2A          | syscalls
        v                v                       v              v
 +----------------- capture -----------------------------+  +-------------+
 | nandi proxy (LLM, MCP, A2A over HTTP)                  |  | nandi sense |
 | nandi wrap  (stdio MCP)   nandi hook (coding agents)   |  | (eBPF)      |
 +---------------------------+----------------------------+  +------+------+
                             | normalized Event                     |
                             v                                      v
     identity -> kill switch -> tool integrity -> policy (Cedar + rules)
       -> plan -> taint / value flow -> detectors -> behaviour -> budgets
                             |
                             v
     Decision: allow | alert | redact | ask | deny   (monitor or enforce)
                             |
                             v
     signed hash-chained audit (redb), OTLP, Prometheus, webhooks, UI, CLI
```

## Crates

| Crate | Role |
|---|---|
| `nandi-core` | Event model, decisions, configuration, helpers. No I/O. |
| `nandi-detect` | Secret, PII, injection, SSRF and honeytoken scanners; redaction. |
| `nandi-policy` | Cedar authorization, YAML rules, sequence rules, plans. |
| `nandi-audit` | redb event store, hash chain, Ed25519 receipts, replay source. |
| `nandi-identity` | API keys, JWT, mTLS identities, Biscuit delegation. |
| `nandi-proto` | Parsers for OpenAI / Anthropic / Gemini, MCP JSON-RPC, A2A. |
| `nandi-engine` | Session state and the inspection pipeline that yields decisions. |
| `nandi-gateway` | HTTP proxy, stdio wrapper, hook endpoint, admin API, dashboard, telemetry. |
| `nandi-sense` | eBPF host sensor (Linux). |
| `nandi-ml` | Optional ONNX prompt-injection classifier. |
| `nandi` | The CLI binary. |

## Principles

1. **Deterministic in the hot path.** Policies, pins, taint and models are
   evaluated with plain data structures. Model-based checks are optional and
   bounded.
2. **Monitor first.** `mode: monitor` records every verdict without applying
   it, so a policy can be tuned on real traffic before `mode: enforce`.
3. **Explicit failure behaviour.** `fail_mode: closed` (default) blocks when
   an approval or model component is unavailable; `open` lets traffic pass.
4. **Agents never hold upstream credentials.** Routes inject them.
5. **Evidence is masked.** Findings never contain raw secrets.
6. **Small footprint.** Streaming bodies are inspected without full
   buffering where possible; release builds are static, LTO, stripped.
