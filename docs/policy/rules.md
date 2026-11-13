# Writing rules

YAML rules are the quickest way to say what an agent may do with a tool.
They live in the files listed under `policy.rules` and are evaluated on every
action, next to [Cedar policies](cedar.md).

```yaml
rules:
  - id: large-payment
    description: Payments above 1000 need a human
    match:
      tool: "*pay*"
      args:
        amount: { gt: 1000 }
    action: ask
    severity: high
```

This holds any call to a tool whose name contains `pay` when its `amount`
argument is above 1000. The finding is reported as `policy.large-payment`.

## Matching

`match` narrows when a rule applies. Every field is optional; an empty
`match` applies to every tool call.

| Field | Matches | Example |
|---|---|---|
| `kind` | `tool_call` (default), `list_tools`, `llm`, `a2a` | `kind: llm` |
| `agent` | agent id (glob) | `agent: "billing-*"` |
| `capability` | what the tool can do, a name, glob or list ([capabilities](capabilities.md)) | `capability: [payment, external_send]` |
| `group` | one of the agent's groups (glob) | `group: interns` |
| `server` | MCP server or route name (glob) | `server: github` |
| `tool` | tool name, or `server/tool` (glob) | `tool: "github/delete_*"` |
| `provider`, `model` | LLM requests | `model: "gpt-4*"` |
| `peer`, `skill`, `method` | A2A messages | `peer: travel` |
| `args` | argument values (see below) | `args: { path: { prefix: /etc } }` |
| `session` | session state | `session: { tainted: true }` |

Globs use `*` and `?` and are case-insensitive. Tools built into coding
agents use the server name `local` (`local/Bash`).

### Arguments

Keys under `args` are paths into the call's arguments. Dots descend into
objects, numbers index arrays (`files.0.path`), and a key that literally
contains a dot wins over the path.

A bare value is an equality check, a string with `*` or `?` is a glob, and a
list means "one of". Anything else is an operator map:

| Operator | True when the value | Example |
|---|---|---|
| `eq`, `ne` | equals / does not equal | `{ ne: main }` |
| `in`, `not_in` | is / is not one of a list | `{ in: [users, payments] }` |
| `glob`, `regex` | matches a glob / a regular expression | `{ regex: '^/etc/' }` |
| `prefix`, `not_prefix`, `suffix` | starts or ends with | `{ prefix: /tmp/ }` |
| `contains`, `not_contains` | contains a substring, element or key | `{ contains: "--force" }` |
| `lt`, `lte`, `gt`, `gte` | compares as a number | `{ gt: 1000 }` |
| `max_len` | is a string, list or object no longer than | `{ max_len: 200 }` |
| `exists` | is present (`true`) or absent (`false`) | `{ exists: false }` |
| `any`, `all` | is a list where any / every element matches | `{ any: { suffix: ".pem" } }` |

Several operators in one map must all hold. A missing argument only matches
`exists: false`, `ne` and the `not_*` operators. Regular expressions use
Rust's `regex` syntax (no look-around), are compiled when the file loads, and
an invalid one is a load error.

### Session conditions

| Field | True when |
|---|---|
| `tainted: true` | the session has read untrusted content |
| `risk_gte`, `risk_lt` | the session's risk score (0.0 to 1.0) is above / below |
| `calls_gte`, `calls_lt` | the session has made at least / fewer than this many calls |

## Actions

`action` is one of `allow`, `alert`, `redact`, `ask` or `deny` (the default).
`allow` is an explicit permit: under `policy.default: deny` a call runs only
if some rule or Cedar policy allows it. `severity` (`info` to `critical`,
default `medium`) and `message` describe the finding.

## Sequences

Some rules are about order, not a single call. Sequence rules look back over
the session's earlier calls.

```yaml
sequences:
  # A refund must follow a successful identity check of the same user.
  - id: refund-needs-verification
    tool: "*refund*"
    requires_prior:
      tool: "*verify_identity*"
      success: true
      same_args: [user_id]
      within_calls: 50
    action: deny

  # Nothing goes out over HTTP after a secret file was read.
  - id: no-upload-after-secret-read
    tool: "http_*"
    forbid_after:
      tool: read_file
      args: { path: { regex: '(\.env|id_rsa|credentials)' } }
    action: ask
```

`requires_prior` fails unless an earlier call matches; `forbid_after` fails
if one does. `success: true` only counts calls that did not return an error,
`same_args` requires the listed arguments to be equal in both calls (a
missing value fails closed), and `within_calls` limits how far back to look.

## Loading and reloading

Unknown fields, duplicate ids and invalid regular expressions are errors, so
a typo cannot silently switch a rule off. Check files with
`nandi policy validate`, test them with `nandi policy test` (see
[Testing policy](testing.md)) and load edits into a running nandi with
`POST /v1/policy/reload`.
