# Observability

## Dashboard

The admin listener serves a dashboard at `/`: the live event stream, calls
waiting for approval, tool integrity, the kill switch, sessions with their
taint and risk, and today's usage. Click an event to see its findings and
the raw event. It is a single page with no external assets, and it follows
the system's light or dark setting.

![The dashboard in dark mode](../assets/screenshots/dashboard-dark.png)

When `admin.token` is set the page asks for it (Token, top right) and keeps
it in the browser's local storage.

### Map

The **Map** tab (or `/#map`) answers one question: which agents reached
what, and what nandi did about it. Pick the last 15 minutes to 24 hours, or
any range on the timeline.

- **The Kailash map.** Agents, the MCP servers, models and peers they
  reached, and their tools, with every path through the gate. Line width is
  volume; a coloured line on top is the share that was flagged, coloured by
  its worst decision, so a path with one denial in 400 calls stays mostly
  grey. Marks on top of a server show its
  [risk](../policy/capabilities.md#risk-scores): one for medium, two for
  high, three for critical.
- **Rings or layers.** The same graph as rings around the gate, or as
  columns (agents, the gate, what they reached, tools), which reads better
  with many nodes.
- **Pan and zoom** with drag, the mouse wheel, the + and − buttons, or the
  keyboard (`+`, `-`, `0` to fit, arrows to move). Tool labels appear as you
  zoom in.
- **Find** highlights an agent, server or tool and its paths. **Only
  flagged** keeps paths with at least one alert, redaction, hold or denial.
- **Details.** Click anything (or focus it and press Enter) to open it in
  the side panel: its decisions as a bar, where an agent went or which
  agents reached a server, a server's risk, capabilities and tools, its
  most recent decisions, and **Disable agent** for operators. Click a name
  in the panel to move to it; Escape closes it.
- **Time.** Drag across the bars of *Decisions over time* (or press Enter
  on one) and the map, the flow and the summary show that range; **Clear**
  goes back to the last 15 minutes to 24 hours.
- **Live.** New decisions travel along their path as small dots in the
  colour of the decision (not with reduced motion).
- *Through the gate* shows the same traffic as a flow from agents to
  destinations, split by decision, and **Show as table** gives everything as
  tables.

The busiest 40 destinations and 80 tools are drawn; the rest fold into
"other". The map needs the audit log (`audit.enabled`); the data comes from
[`GET /v1/graph`](../reference/admin-api.md) (`window_secs`, and `until_ms`
for a past range).

![The map in light mode](../assets/screenshots/map-light.png)

## Terminal

```sh
nandi tail                         # every event as it happens
nandi tail --min-verdict alert     # only what matters
nandi tail --agent billing-agent --json
```

```text
12:50:19.619  research-agent   tool_call    web/fetch_page                     deny         ssrf.metadata
12:50:19.685  billing-agent    tool_call    crm/issue_refund                   deny         sequence.refund-needs-verification
12:50:19.725  claude-code      tool_call    notion/create_page                 redact       secret.database-url
12:50:19.742  claude-code      tool_call    local/Bash                         ask          policy.no-pipe-to-shell
12:50:19.763  support-bot      tool_call    crm/export_customers               deny         killswitch
```

When the verdict and what was applied differ (monitor mode, or an operator's
decision), the column shows both, for example `deny>allow`.

## Metrics, tracing and webhooks

- Prometheus: `GET http://127.0.0.1:8788/metrics` (`telemetry.prometheus`,
  on by default): events by kind, decisions by verdict, enforced verdicts,
  evaluation latency, approvals, recorder drops, export and OTLP delivery,
  plus gauges for sessions, pending approvals and killed agents.
- OpenTelemetry: set `telemetry.otlp_endpoint` (for example
  `http://127.0.0.1:4318`) or `OTEL_EXPORTER_OTLP_ENDPOINT`. nandi sends
  traces (continuing the agent's trace and passing it upstream), a log record
  per decision and admin action, and these metrics over OTLP/HTTP; see
  [OpenTelemetry](opentelemetry.md).
- SIEMs, webhooks and files: see [exports](exports.md). The older
  `telemetry.webhooks` receive findings at or above
  `telemetry.webhook_min_severity`.
- Health: `GET /healthz` (no auth) returns status, version, mode and uptime.


Logs go to stderr; `telemetry.log_format: json` switches `nandi run` to JSON
lines.
