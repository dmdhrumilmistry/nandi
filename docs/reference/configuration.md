# Configuration

nandi reads one YAML file, `nandi.yaml` by default. Every key has a safe
default, so an empty file is a valid configuration: monitor mode, listeners
on localhost, all detectors on. Unknown keys are errors, which catches typos.

Values that hold credentials can be written as `env:NAME` (read from the
environment) or `file:/path` (read from a file) instead of literally.
Relative paths are resolved against the directory of the configuration file.

## Sections

| Section | Controls | Details |
|---|---|---|
| `mode`, `fail_mode` | monitor or enforce; behaviour when a dependency fails | [How it works](../how-it-works.md) |
| `listen`, `admin` | proxy and admin listeners, TLS, admin token, dashboard | [Proxy](../guides/proxy.md), [Admin API](admin-api.md) |
| `routes` | upstreams on the proxy, credential injection | [Proxy](../guides/proxy.md) |
| `identity` | anonymous access, API keys, JWT, Biscuit | [Identity](../operations/identity.md) |
| `policy` | default action, rule and Cedar files | [Rules](../policy/rules.md), [Cedar](../policy/cedar.md) |
| `tools` | pinning, drift and unlisted verdicts, description scanning, list filtering | [MCP servers](../guides/mcp.md) |
| `taint`, `plan` | untrusted content, consequential tools, value flow, spotlighting, plans | [Data flow](../policy/data-flow.md) |
| `detect` | secrets, PII, injection, SSRF, honeytokens | [Detection](../policy/detection.md) |
| `behavior`, `budgets` | loops, rate limits, anomaly scoring, daily budgets | below |
| `approvals` | timeout, timeout verdict, webhook | [Approvals](../operations/approvals.md) |
| `audit` | database, signing key, retention | [Audit log](../operations/audit.md) |
| `telemetry` | OTLP, Prometheus, webhooks, log format | [Observability](../operations/observability.md) |
| `a2a` | Agent Card signatures and pinning, context binding | [Proxy](../guides/proxy.md#a2a-agents) |
| `sensor` | host sensor backend, agent names, sensitive paths | [Host sensor](../guides/host-sensor.md) |
| `ml` | ONNX classifier | [ML classifier](../guides/ml-classifier.md) |

## Behaviour and budgets

```yaml
behavior:
  enabled: true
  mode: detect              # learn | detect | frozen
  min_observations: 200     # calls per agent before anomaly alerts start
  surprise_bits: 8.0        # how unusual a tool transition must be
  on_anomaly: alert
  loop_threshold: 8         # identical calls within loop_window_secs
  loop_window_secs: 60
  max_calls_per_minute: 0   # 0 = unlimited
  unsafe_reach_threshold: 0.5

budgets:
  - agent: "support-*"
    tokens_per_day: 2000000
    tool_calls_per_day: 5000
    verdict: deny
```

Each agent gets a model of which tool usually follows which. A call to a tool
the agent has never used, or an unusual transition, raises a behaviour
finding once the model has seen enough traffic. The model also estimates how
likely the session is to reach a call that was flagged before, and escalates
when that probability passes `unsafe_reach_threshold`.

## The annotated example

This is the file `nandi init` writes
([examples/nandi.yaml](https://github.com/dmdhrumilmistry/nandi/blob/main/examples/nandi.yaml)).

<!-- include: examples/nandi.yaml yaml -->
