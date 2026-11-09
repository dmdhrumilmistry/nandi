# Using nandi

This guide covers installing and running nandi, putting it in front of LLM
SDKs, MCP servers and coding agents, and the day-to-day operator workflow:
moving from monitor to enforce, approvals, the kill switch, audit
verification and delegation tokens.

## Quick start

```sh
nandi init                 # writes nandi.yaml and policies/ in the current directory
nandi policy validate      # loads the config and policies, prints warnings
nandi run                  # proxy on 127.0.0.1:8787, admin API and dashboard on 127.0.0.1:8788
```

Open <http://127.0.0.1:8788/> for the dashboard: live events, pending
approvals, sessions, the kill switch, tool pins and usage.

Every command takes `-c/--config <path>` (default `nandi.yaml`, or
`NANDI_CONFIG`) and `--log-level` (default `info`, or `NANDI_LOG`). Logs always
go to stderr. Set `telemetry.log_format: json` for JSON logs from `nandi run`.

The generated files are the same as [`examples/`](../examples): a commented
`nandi.yaml`, YAML rules in `policies/rules.yaml` and Cedar policies in
`policies/policy.cedar`.

### Docker

```sh
docker build -t nandi .
docker run --rm -p 8787:8787 -p 8788:8788 \
  -v "$PWD:/etc/nandi" -e NANDI_ADMIN_TOKEN=change-me nandi
```

Inside a container the listeners must bind `0.0.0.0` (set `listen.proxy` and
`admin.listen` accordingly) and `admin.token` must be set, because without a
token the admin API only answers loopback clients. Mount a writable volume
for `data_dir`.

## Pointing LLM SDKs at the proxy

Each entry in `routes` maps a path prefix to an upstream. With the generated
config:

```sh
export OPENAI_BASE_URL=http://127.0.0.1:8787/openai/v1
export ANTHROPIC_BASE_URL=http://127.0.0.1:8787/anthropic
```

The official OpenAI and Anthropic SDKs (Python, TypeScript, Go, ...) read these
variables, so most agents need no code change. To identify an agent, send its
API key in the `x-nandi-key` header (`identity.api_key_header`) and, optionally,
a session id in `x-nandi-session`:

```python
from openai import OpenAI
client = OpenAI(default_headers={"x-nandi-key": os.environ["NANDI_AGENT_KEY"]})
```

To keep provider credentials away from agents entirely, put them on the route
with `inject_headers` (values may be `env:NAME` or `file:/path`) and list the
agent's own header under `strip_headers`.

Remote MCP servers (Streamable HTTP) and A2A agents are routed the same way
with `kind: mcp` and `kind: a2a`; point the client at
`http://127.0.0.1:8787/<prefix>`.

## Wrapping stdio MCP servers

`nandi wrap` sits between an MCP client and a local stdio server. It sees
`tools/list` (pinning and poisoning checks), every `tools/call` and every
result. Replace the server's command with `nandi` and move the original
command after `--`.

Claude Desktop (`claude_desktop_config.json`), Cursor (`.cursor/mcp.json`) and
Claude Code (`.mcp.json`) all use the same shape:

```json
{
  "mcpServers": {
    "github": {
      "command": "nandi",
      "args": ["wrap", "-c", "/path/nandi.yaml", "--server", "github", "--",
               "npx", "-y", "@modelcontextprotocol/server-github"],
      "env": { "GITHUB_PERSONAL_ACCESS_TOKEN": "..." }
    }
  }
}
```

With Claude Code you can also add it from the command line:

```sh
claude mcp add github -- nandi wrap -c /path/nandi.yaml --server github -- \
  npx -y @modelcontextprotocol/server-github
```

Notes:

- `--server` is the name policies use (`github/create_issue`).
- `--agent` (or `NANDI_AGENT`) sets the agent identity, default `local`;
  `--session` pins a session id, otherwise each wrapper process is a session.
- The wrapper writes nothing to stdout except the MCP protocol; its logs go
  to stderr, which MCP clients show in their server logs.
- Each wrapped server gets its own database, `<data_dir>/wrap-<server>.redb`,
  because a database file can only be open in one process. Set `audit.path`
  only if you run a single wrapper.

## Coding-agent hooks

Hooks let nandi see and gate the built-in tools of coding agents (shell,
file edits, web fetches), not just MCP. `nandi hook <format>` reads the hook
payload on stdin, asks the running nandi (`POST /v1/hook/<format>` on the
admin API) and prints the answer in the host's format. If nandi is
unreachable the action is blocked, unless `--fail-open` is given.

The admin URL defaults to `admin.listen` from the config (or
`http://127.0.0.1:8788`); override it with `--admin`. The token comes from
`--token`, `NANDI_ADMIN_TOKEN` or `admin.token` in the config.

### Claude Code

In `~/.claude/settings.json` (all projects) or `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "*", "hooks": [{ "type": "command", "command": "nandi hook claude-code -c /path/nandi.yaml" }] }
    ],
    "PostToolUse": [
      { "matcher": "*", "hooks": [{ "type": "command", "command": "nandi hook claude-code -c /path/nandi.yaml" }] }
    ],
    "UserPromptSubmit": [
      { "hooks": [{ "type": "command", "command": "nandi hook claude-code -c /path/nandi.yaml" }] }
    ]
  }
}
```

`PreToolUse` gates tool calls, `PostToolUse` feeds tool output into taint
tracking and detection, and `UserPromptSubmit` scans prompts.

How verdicts map to Claude Code:

- **allow**: no output, so Claude Code's own permission rules still apply
  (nandi never silently approves something your settings would ask about).
- **deny**: `permissionDecision: "deny"` with nandi's reason, which the
  model sees and can adapt to.
- **ask**: `permissionDecision: "ask"`, handing the decision to Claude Code's
  own prompt instead of nandi's approval queue.
- **redact**: the call proceeds with `updatedInput` carrying the redacted
  arguments.
- Findings in tool output (for example an injection in a fetched page) are
  returned as `additionalContext` warning the model that the content is
  untrusted data; a deny verdict blocks with `decision: "block"`.
- Prompts are blocked when they would leak a secret, since prompts cannot be
  rewritten.

MCP tools appear in Claude Code as `mcp__<server>__<tool>` and are mapped to
`<server>/<tool>` for policies; built-in tools (Bash, Read, Edit, WebFetch,
...) use the server name `local`, e.g. `local/Bash`.

### Cursor

In `~/.cursor/hooks.json` or `<project>/.cursor/hooks.json`:

```json
{
  "version": 1,
  "hooks": {
    "beforeShellExecution": [{ "command": "nandi hook cursor -c /path/nandi.yaml" }],
    "beforeMCPExecution": [{ "command": "nandi hook cursor -c /path/nandi.yaml" }],
    "beforeReadFile": [{ "command": "nandi hook cursor -c /path/nandi.yaml" }],
    "beforeSubmitPrompt": [{ "command": "nandi hook cursor -c /path/nandi.yaml" }],
    "afterShellExecution": [{ "command": "nandi hook cursor -c /path/nandi.yaml" }],
    "afterMCPExecution": [{ "command": "nandi hook cursor -c /path/nandi.yaml" }],
    "afterFileEdit": [{ "command": "nandi hook cursor -c /path/nandi.yaml" }]
  }
}
```

Shell commands map to `local/shell` (`{"command": ...}`), MCP calls to
`<server>/<tool>` and file reads to `local/read_file`. Cursor receives
`{"permission": "allow" | "deny" | "ask", "user_message", "agent_message"}`;
`after*` events are recorded and feed taint tracking. Cursor treats missing
output on permission hooks as a block, so nandi always answers explicitly.

Any other agent that can run a command before a tool call can use
`nandi hook generic` with `{"agent", "session", "server", "tool", "args"}` (or
`{"event": <nandi event>}`) on stdin. It prints
`{"verdict", "reason", "decision"}` and exits 0 when allowed, 2 when denied.

## Writing and testing policy

Policy has two layers, both evaluated on every action:

- YAML rules (`policies/rules.yaml`): argument predicates with graded actions
  (`allow`, `alert`, `redact`, `ask`, `deny`) and sequences
  (`requires_prior`, `forbid_after`).
- Cedar policies (`policies/policy.cedar`): `permit` and `forbid` over agents,
  groups, tools, servers, models and peers.

`policy.default: deny` turns on zero trust for tool calls: anything not
explicitly permitted is denied.

Test changes without traffic. Write events as JSON lines (missing `id`,
`ts_ms`, `source`, `agent` and `session` are filled in) and evaluate them in
order with a fresh engine, so sequences behave as in a real session:

```sh
cat > events.jsonl <<'EOF'
{"kind":{"type":"tool_call","server":"shell","tool":"run","args":{"command":"rm -rf /srv"}}}
{"kind":{"type":"tool_call","server":"bank","tool":"make_payment","args":{"amount":5000}}}
{"event":{"agent":"intern-1","kind":{"type":"tool_call","server":"github","tool":"delete_repository","args":{}}},"groups":["interns"]}
EOF
nandi policy test --events events.jsonl
# 1    tool_call     shell/run                deny   policy.no-rm-rf
# 2    tool_call     bank/make_payment        ask    policy.large-payment
# 3    tool_call     github/delete_repository deny   cedar.interns-no-repo-delete
```

Add `--json` for machine-readable output. A running nandi picks up edited
policy files with `curl -X POST http://127.0.0.1:8788/v1/policy/reload`
(add `-H "Authorization: Bearer $NANDI_ADMIN_TOKEN"` when a token is set).

## From monitor to enforce

1. Run in `mode: monitor` (the default). Everything is evaluated and recorded
   with the verdict it would have received; nothing is blocked or rewritten.
   Watch the dashboard or `nandi tail --min-verdict alert`.
2. Tune the policy. Re-check the recorded traffic against the new policy and
   config:

   ```sh
   nandi replay                    # all recorded events
   nandi replay --since-seq 5000   # only newer ones
   ```

   Replay prints every event whose verdict would change (`old -> new` and the
   rules responsible) and a summary of how many became stricter or looser. The
   database can only be open in one process, so run it while nandi is stopped,
   or against a copy taken while it was stopped (`--db`, `--key`).
3. When the remaining denies are the ones you want, set `mode: enforce` and
   restart.

## Approvals and the kill switch

An `ask` verdict holds the call until an operator decides or
`approvals.timeout_secs` passes (then `approvals.on_timeout` applies, deny by
default). The agent just sees a slow call. Approve or deny from the dashboard,
or:

```sh
nandi approvals                 # list
nandi approvals approve <id>
nandi approvals deny <id>
```

Set `approvals.webhook` to get a Slack-compatible notification for every
pending approval.

The kill switch denies every action of an agent, in monitor mode too, until it
is revived. It survives restarts.

```sh
nandi kill support-bot
nandi revive support-bot
```

Other admin commands: `nandi status`, `nandi sessions`, `nandi tail`,
`nandi pins` (`list`, `approve <server/tool>`, `forget <server/tool>`; add
`--cards` for A2A Agent Card pins). All take `--admin <url>`, `--token`
(or `NANDI_ADMIN_TOKEN`) and `--json`.

When a tool definition changes after it was pinned (a possible rug pull), calls
to it get `tools.on_drift` until you review and accept the new definition with
`nandi pins approve github/create_issue` or from the dashboard.

## Audit log

Every evaluated event and its decision is appended to a hash-chained,
Ed25519-signed log in `<data_dir>/audit.redb` (key in
`<data_dir>/audit.key`, created on first start).

```sh
nandi audit head                       # newest seq, hash and the public key
nandi audit verify                     # recompute the chain, check every signature
nandi audit export --out audit.jsonl   # JSON lines for archival or an auditor
nandi audit verify --export audit.jsonl --pubkey <hex public key>
```

An auditor needs only the export and the public key. Publishing `audit head`
somewhere else (a ticket, a chat channel) lets them also detect truncation.
While nandi is running, `GET /v1/audit/verify` on the admin API verifies the
live log.

## API keys

```sh
nandi key generate     # prints a new key and its SHA-256
nandi key hash <key>   # SHA-256 of an existing key (`-` reads stdin)
```

Give the key to the agent and put only the hash in `identity.api_keys` with
the agent id and its groups.

## Delegation with Biscuit tokens

Biscuit tokens let an orchestrator hand a sub-agent a narrower capability
without contacting nandi or holding any private key.

```sh
# 1. Once: a root key pair. Keep the private key secret.
nandi token keygen
# private: <hex>
# public:  <hex>
```

```yaml
# 2. nandi.yaml
identity:
  biscuit:
    root_public_key: "<public hex>"
```

```sh
# 3. Mint a token for the planner: any GitHub tool, valid for one hour.
nandi token mint --private-key <private hex> --agent planner --tool 'github/*' --ttl 3600

# 4. The planner narrows it for a sub-agent that may only read issues, for 10 minutes.
nandi token attenuate --token <token> --public-key <public hex> --tool github/get_issue --ttl 600

# 5. Check what a token says.
nandi token inspect --token <token>
```

The sub-agent sends the token in the `x-nandi-biscuit` header. nandi verifies
the signature chain and allows a tool only if every block permits it, so an
attenuated token can never do more than its parent.

## Metrics and tracing

- Prometheus: `GET http://127.0.0.1:8788/metrics` (`telemetry.prometheus`,
  on by default): events by kind, decisions by verdict, enforced verdicts,
  evaluation latency, approvals, recorder drops, plus gauges for sessions,
  pending approvals and killed agents.
- OpenTelemetry: set `telemetry.otlp_endpoint` (for example
  `http://127.0.0.1:4318`) and optional `otlp_headers`; events are exported as
  OTLP/HTTP spans following the GenAI semantic conventions.
- Webhooks: `telemetry.webhooks` receive findings at or above
  `telemetry.webhook_min_severity`.
- Health: `GET /healthz` (no auth) returns status, version, mode and uptime.

## Admin API reference

All endpoints are JSON and live on `admin.listen`. With `admin.token` set they
require `Authorization: Bearer <token>` (except `/healthz` and the dashboard
page); without a token they only answer loopback clients.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/` | dashboard |
| GET | `/healthz` | liveness |
| GET | `/metrics` | Prometheus text |
| GET | `/v1/status` | mode, routes, counts, audit head |
| GET | `/v1/events?agent=&session=&min_verdict=&kind=&since_seq=&limit=` | audit query (default 100, max 1000) |
| GET | `/v1/events/stream?agent=&min_verdict=` | live events (server-sent events) |
| GET | `/v1/sessions` | active sessions |
| GET | `/v1/approvals` | pending approvals |
| POST | `/v1/approvals/{id}/approve`, `/deny` | resolve, optional body `{"by": "name"}` |
| GET | `/v1/agents/killed` | killed agents |
| POST | `/v1/agents/{agent}/kill`, `/revive` | kill switch |
| GET | `/v1/pins/tools`, `/v1/pins/cards` | pins |
| POST | `/v1/pins/tools/approve`, `/forget` (same for cards) | body `{"id": "server/tool"}` |
| GET, DELETE | `/v1/behavior/{agent}` | behaviour model, reset |
| GET | `/v1/usage` | token and tool-call usage today |
| POST | `/v1/policy/reload` | reload policy files |
| GET | `/v1/audit/verify` | verify the audit chain |
| POST | `/v1/hook/{format}` | evaluate a hook payload |
