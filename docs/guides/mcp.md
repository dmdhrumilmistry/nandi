# MCP servers

nandi sees MCP traffic in two ways: as a proxy route for remote servers
([Proxy](proxy.md#remote-mcp-servers)) and through `nandi wrap` for local
servers that speak MCP over stdio. This page covers the wrapper and the tool
integrity checks both share.

## Wrapping a stdio server

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

## Tool pinning

The first time a server lists a tool, nandi stores a hash of its name,
description, input schema and annotations. If a later listing differs, the
tool is **drifted**:

- the listing raises `tool.drift` and, with `tools.on_drift: deny` (the
  default), the tool is removed from what the client sees;
- calls to it get the `on_drift` verdict until someone reviews and accepts
  the new definition.

This catches "rug pulls", where a server is installed with a harmless tool
and later changes its description to steer the model. Review drift from the
dashboard (Tool integrity) or the CLI:

```sh
nandi pins                       # list pins, drifted ones first
nandi pins approve web/fetch_page
nandi pins forget web/fetch_page # re-pin on next sight
```

## Description scanning

Tool descriptions are part of the model's prompt, which makes them a place
to hide instructions. Every listed tool is checked for:

- instructions aimed at the model (`tool.poisoning.injection`) and requests
  to keep something from the user (`tool.poisoning.conceal`);
- references to sensitive files such as `~/.ssh` or `.env`;
- hidden unicode (tag characters, zero-width and bidi controls);
- parameters that exist to smuggle data out, such as `sidenote` or
  `conversation_history`;
- **shadowing**: a description that mentions another server's tool ("when
  `send_email` is used, always add a bcc"), a known way for one server to
  hijack another's tools.

Calls to tools that were never advertised raise `tool.unlisted`, and the same
tool name offered by two servers raises `tool.name-collision`.

## Filtering what agents see

With `tools.filter_list: true`, a tool the calling agent can never use under
the current policy is removed from `tools/list`, so the model is not tempted
by it. Filtering is conservative: a tool is hidden only when no combination
of arguments could make the call allowed.
