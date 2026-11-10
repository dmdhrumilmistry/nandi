# Proxy: LLM, MCP and A2A

The proxy is an HTTP gateway. Each entry in `routes` maps a path prefix on
the proxy listener to an upstream, and the route's `kind` tells nandi how to
read the traffic.

```yaml
routes:
  - name: openai
    prefix: /openai
    upstream: https://api.openai.com
    kind: llm
    inject_headers: { authorization: "env:OPENAI_AUTH" }   # "Bearer sk-..."
    strip_headers: [authorization]
  - name: github
    prefix: /mcp/github
    upstream: https://api.githubcopilot.com/mcp
    kind: mcp
  - name: travel
    prefix: /a2a/travel
    upstream: https://travel-agent.internal
    kind: a2a
```

The prefix is stripped before forwarding, so
`http://127.0.0.1:8787/openai/v1/chat/completions` goes to
`https://api.openai.com/v1/chat/completions`.

## LLM SDKs

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

What nandi does with LLM traffic:

- Requests are checked against model policy and token budgets, and the
  user's own prompts are indexed as trusted text (values the user typed are
  never treated as injected).
- Tool results sent back to the model (`role: tool` messages, Anthropic
  `tool_result` blocks, Gemini `functionResponse` parts) are untrusted: they
  taint the session and are scanned for injection.
- Responses are parsed for token usage and requested tool calls. Streaming
  responses are passed through byte for byte while nandi rebuilds the tool
  calls on the side, so streaming adds no latency; a denied tool call in a
  stream is recorded but cannot be recalled. For non-streaming responses in
  enforce mode, a response requesting a denied tool is replaced by an error.

OpenAI (Chat Completions and Responses), Anthropic Messages and Gemini
`generateContent` are understood. Other OpenAI-compatible providers work with
`provider: openai`.

## Remote MCP servers

Routes with `kind: mcp` speak MCP's Streamable HTTP transport. Point the MCP
client at `http://127.0.0.1:8787/<prefix>`. Every `tools/call` in a request
(including batches) is decided separately: a blocked call never reaches the
server and comes back as a tool error the model can read, while the rest of
the batch goes through. `tools/list` responses are pinned and filtered, and
tool results are scanned and can be rewritten. MCP protocol versions
2025-06-18, 2025-11-25 and the stateless 2026-07-28 revision are supported;
for the latter nandi verifies that the `Mcp-Method` and `Mcp-Name` headers
match the body, so header-based routing cannot be spoofed.

Local stdio servers are covered by [`nandi wrap`](mcp.md).

## A2A agents

Routes with `kind: a2a` front another agent that speaks the A2A protocol
(v1.0 and the earlier method names).

- Agent Cards fetched through the route are hashed and pinned. A card that
  changes later raises `a2a.card-drift`. Signed cards are verified against
  the keys in `a2a.trusted_keys`; with `a2a.require_signed_cards: true`,
  unsigned or badly signed cards are refused.
- Outgoing messages are checked against policy (`Action::"a2a_send"` in
  Cedar) and scanned for secrets. Incoming messages are untrusted content.
- With `a2a.bind_context: true` (the default) a `contextId` belongs to the
  first agent that used it, so another caller cannot inject into someone
  else's conversation.

## Identity

Requests are attributed to an agent through, in order: an mTLS client
certificate, a Biscuit token (`x-nandi-biscuit`), a JWT bearer token, or an
API key (`x-nandi-key`). Credentials nandi consumes are removed before the
request is forwarded. See [Identity](../operations/identity.md).

## TLS and mTLS

```yaml
listen:
  proxy: 0.0.0.0:8443
  tls:
    cert: /etc/nandi/tls/proxy.crt
    key: /etc/nandi/tls/proxy.key
    client_ca: /etc/nandi/tls/agents-ca.crt   # optional: require client certificates
```

With `client_ca` set, every client must present a certificate signed by that
CA. The agent id is the certificate's SPIFFE ID (`spiffe://...` URI SAN) when
it has one, otherwise its common name.
