# Coding agents

Hooks let nandi see and gate the built-in tools of coding agents (shell,
file edits, web fetches), not just MCP. `nandi hook <format>` reads the hook
payload on stdin, asks the running nandi (`POST /v1/hook/<format>` on the
admin API) and prints the answer in the host's format. If nandi is
unreachable the action is blocked, unless `--fail-open` is given.

The admin URL defaults to `admin.listen` from the config (or
`http://127.0.0.1:8788`); override it with `--admin`. The token comes from
`--token`, `NANDI_ADMIN_TOKEN` or `admin.token` in the config.

## Claude Code

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

## Cursor

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

## Behaviour when nandi is down

A hook that cannot reach nandi blocks the action (Claude Code gets a deny
with the reason "nandi is unavailable"). Add `--fail-open` to the hook
command to let actions through instead, for example on a laptop where nandi
is not always running.
