# Introduction

nandi is a gateway and runtime monitor for AI agents. It sits between your
agents and the things they talk to (LLM APIs, MCP servers, other agents, the
host they run on), records what they do, and applies your policy before
anything runs.

It answers three questions that are hard to answer once agents are in
production:

- **What did the agent actually do?** Every model request, tool listing, tool
  call, tool result and agent-to-agent message becomes a structured event,
  kept in a signed, hash-chained audit log and exported as OpenTelemetry
  traces, logs and metrics.
- **Should it be allowed to?** Policies over agents, tools and arguments
  (YAML rules and Cedar), a default-deny mode, budgets, and a human approval
  queue for the calls you don't want to automate.
- **Was it manipulated?** Prompt injection rarely announces itself, so nandi
  tracks where data came from: a payment to an IBAN that only ever appeared in
  a fetched web page is held, whatever the page said. Tool definitions are
  pinned, so a server that quietly rewrites a tool description is caught.

nandi is a single static binary. A release build idles at about 20 MB of
memory and evaluates a typical event in tens of microseconds. Nothing in the
request path calls a model to make a decision.

## Three ways in

| You run | Put nandi in front with | You get |
|---|---|---|
| Agents that use an LLM SDK | the HTTP proxy (`OPENAI_BASE_URL=http://127.0.0.1:8787/openai/v1`) | model, prompt and tool-call visibility, token budgets, credential injection |
| MCP servers | `nandi wrap -- <server command>` for stdio, or a proxy route for remote servers | tool pinning, argument policy, taint tracking, result scanning |
| Claude Code, Cursor and similar | a hook command (`nandi hook claude-code`) | the same checks on built-in tools: shell, file edits, web fetches |

They can be combined, and they share state: a document read through a
wrapped MCP server taints the session that later asks the model to send an
email.

## Where to go next

- [Getting started](getting-started.md) installs nandi and walks through a
  first session in monitor mode.
- [How it works](how-it-works.md) explains events, verdicts and the order in
  which checks run.
- [Writing rules](policy/rules.md) and [Cedar policies](policy/cedar.md)
  cover policy.
- [Research](background/research.md) lists the products and papers each
  feature comes from.
