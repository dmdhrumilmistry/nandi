# Capabilities and server risk

Tool names say little about what a tool does. `pay_invoice`,
`create_transfer` and `stripe_refund` all move money; `get_payment` does
not. nandi classifies every tool it sees into **capabilities**, scores each
tool and server by them, and lets policies match on the capability instead
of on name patterns.

## Capabilities

| Capability | Meaning | Weight |
|---|---|---|
| `command_execution` | runs commands, scripts or code | 40 |
| `payment` | moves money: payments, transfers, refunds, invoices, payouts | 40 |
| `credential_access` | reads or manages secrets, tokens, keys or passwords | 35 |
| `data_deletion` | deletes records, tables, repositories or other data | 30 |
| `identity_admin` | manages users, roles, permissions or invitations | 30 |
| `external_send` | sends to people or systems outside: email, chat, posts, webhooks | 25 |
| `file_delete` | deletes files or directories | 20 |
| `data_modification` | creates or changes records, documents or settings | 15 |
| `file_write` | creates or changes files | 15 |
| `network_fetch` | fetches from or searches the network | 10 |
| `read_only` | reads data without side effects | 0 |

A tool can have several. A tool nothing is known about has none.

## How a tool is classified

Classification is deterministic: no model is involved, and the same
definition always gives the same result.

1. The tool name is split into words (`listUsers` becomes `list`, `user`).
   The first verb decides the direction: `list_payments` reads payments,
   `create_payment` makes one.
2. Nouns refine the verb. A delete on a file is `file_delete`, on anything
   else `data_deletion`; writes on payment nouns are `payment`, on identity
   nouns `identity_admin`, on message nouns `external_send`. Secret nouns
   (`secret`, `token`, `password`, `api key`) mean `credential_access`
   whatever the verb.
3. Input schema properties add evidence: `command` or `script` means
   command execution, `amount` with `iban` or `account` means a payment, a
   recipient with a body means sending, a URL means fetching.
4. When the name and schema say nothing, a few unambiguous phrases in the
   description are used.
5. MCP annotations come last. `readOnlyHint: true` reduces the result to
   `read_only`, unless the name implies something heavier (deleting,
   sending, paying, running commands, secrets, identity). A server cannot
   talk its way out of a `delete_repository` with an annotation.
   `destructiveHint` and `openWorldHint` add `data_deletion` and
   `network_fetch` when nothing else was found.

The built-in tools of coding agents are mapped explicitly: `Bash` runs
commands, `Write` and `Edit` write files, `WebFetch` fetches, `Read` and
`Grep` read.

## Matching capabilities in policy

In [rules](rules.md), `match.capability` takes a name, a glob or a list,
and matches when any of the tool's capabilities does:

```yaml
rules:
  - id: payments-need-approval
    match:
      capability: payment
    action: ask
    severity: high

  - id: no-shell-for-interns
    match:
      agent: "intern-*"
      capability: [command_execution, credential_access]
    action: deny
```

Names are checked when the policy loads, so a typo such as `paymnet` is an
error instead of a rule that never matches.

In [Cedar](cedar.md), tools carry a `capabilities` set:

```cedar
forbid (principal in Group::"interns", action == Action::"call_tool", resource)
  when { resource.capabilities.containsAny(["command_execution", "credential_access"]) };
```

## Risk scores

Each tool gets a score from 0 to 100. Its heaviest capability counts
fully and every other one a quarter. A high-severity finding on the tool's
description adds 20, and so does a definition that changed since it was
pinned. A server's score is that of its riskiest tool, plus 2 for every
other kind of side effect its tools have (at most 10), so a server that can
both delete data and send email ranks above one that can only delete.

| Score | Level |
|---|---|
| below 25 | low |
| 25 to 49 | medium |
| 50 to 74 | high |
| 75 and above | critical |

For example, a tool that sends email (25) and fetches URLs (10) scores
25 + 10 / 4 = 28, medium. A shell tool whose description tries to give
the model instructions scores 40 + 20 = 60, high.

## Server supply chain

nandi records how each MCP server is reached: the command line of a server
run with `nandi wrap`, or the upstream URL of a proxy route. From the
command line it works out which package the server runs:

| Launcher | Example | Package |
|---|---|---|
| `npx`, `bunx`, `pnpm dlx`, `yarn dlx`, `npm exec` | `npx -y @scope/server@1.2.3` | npm |
| `uvx`, `uv tool run`, `pipx run`, `python -m` | `uvx --from mcp-x==1.2.3 mcp-x` | pypi |
| `docker run`, `podman run` | `docker run -i --rm ghcr.io/org/server:1.4` | oci |
| `node`, `python`, `deno run`, `bun run` with a path, or a binary | `node ./build/index.js` | local |

A package is **pinned** when its version is exact: npm `1.2.3`, pypi
`==1.2.3`, an OCI digest or a tag other than `latest`. `npx pkg` runs
whatever was published last, so it is unpinned. A local file is pinned by
its SHA-256, and nandi notices when the file changes.

The `servers` section of the configuration decides what happens:

```yaml
servers:
  on_unpinned: alert        # registry package without an exact version
  on_binary_change: alert   # local server file differs from the first one seen
  on_unknown: deny          # server not in `approved` (only once the list has entries)
  approved:
    - { name: github, package: "npm:@modelcontextprotocol/server-github@2025.4.8" }
    - { name: copilot, url: "https://api.githubcopilot.com/mcp" }
    - { name: tools, sha256: "<hex sha-256 of the script>" }
```

| Finding | When |
|---|---|
| `server.unpinned` | a registry package runs without an exact version |
| `server.unapproved` | `approved` has entries and the server is not one of them |
| `server.spec-mismatch` | the server is approved by name, but runs a different package, URL or file |
| `server.binary-changed` | a local server binary or script changed since it was first seen |

An approved entry matches by `name` (globs allowed). When it also gives a
`package`, `url` or `sha256`, that must match too, so an approved
`github` server that is quietly switched to another package is caught.
With `on_unknown: deny` an unapproved server is quarantined: its tools are
hidden from `tools/list` and every call to it is denied.

The defaults alert and never block, and `on_unknown` does nothing until you
list approved servers, so turning nandi on does not break existing setups.

### Known malicious and vulnerable packages

With `servers.osv.enabled`, `nandi wrap` looks a server's npm or PyPI
package up in the [OSV](https://osv.dev) database before it starts the
server:

```yaml
servers:
  osv:
    enabled: true
    on_malicious: deny      # MAL-* report: in enforce mode the server is not started
    on_vulnerable: alert    # known vulnerabilities in the pinned version
```

```text
$ nandi wrap --server notes -- npx -y flatmap-stream@0.1.1
nandi: not starting MCP server notes: npm:flatmap-stream@0.1.1 is reported as malicious (MAL-2025-20690); see https://osv.dev/vulnerability/MAL-2025-20690
```

| Finding | When |
|---|---|
| `server.malicious-package` | OSV has a malicious-package report (`MAL-*`) for the package |
| `server.vulnerable-package` | the pinned version has known vulnerabilities |

A pinned version is checked for every advisory. An unpinned package can
resolve to any version, so only malicious-package reports, which cover the
whole package, count for it. Results are cached for a day
(`cache_hours`). The lookup sends the package name and version to
`api.osv.dev` (or the mirror in `servers.osv.url`), which is why it is off
by default. If OSV cannot be reached within `timeout_ms` (3 seconds) the
server starts as usual and a warning is logged. Container images and local
files are not looked up; pin them by digest and `sha256` instead.

In monitor mode, or with a verdict other than `deny`, the server starts
and the findings are recorded on its tool lists and calls like the others.

## Seeing it

`nandi servers` lists every server with its risk level and score,
approval, pinning, package and capabilities (`--json` for the full record):

```text
$ nandi servers
NAME                 RISK          APPROVAL   PINNED   SPEC                                             CAPABILITIES
local                medium    44  approved   -        (seen through hooks)                             command_execution,file_write,network_fetch
bank                 medium    40  approved   pinned   npm:@acme/bank-mcp@1.4.2                         payment
github               medium    32  approved   pinned   npm:@modelcontextprotocol/server-github@2025.4.8 data_deletion,data_modification
notes                medium    25  UNAPPROVED UNPINNED npm:notes-mcp                                    external_send QUARANTINED
```

Here `notes` was started with `npx -y notes-mcp`: it is not on the approved
list and runs whatever version was published last, so with
`on_unknown: deny` its tools are hidden and its calls denied. `local` is
the coding agent's built-in tools, seen through [hooks](../guides/coding-agents.md).

After a deliberate upgrade of a local server, accept the new file with
`POST /v1/servers/accept-binary` (see the [admin API](../reference/admin-api.md)).
The dashboard's Tool integrity card lists servers by risk.
