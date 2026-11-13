# Data flow and taint

Most prompt injection attacks work the same way: untrusted text (a web page,
an email, a tool result) contains instructions, and the agent follows them
with a tool that has real effects. Detecting the instructions is a pattern
match that can always be paraphrased around. nandi also watches the other
half: what happens after untrusted content enters a session.

## Taint

Every tool result and every inbound A2A message is untrusted unless its tool
is listed in `taint.trusted_sources`. The first untrusted content marks the
session as **tainted**. From then on:

- calls to **consequential** tools raise `taint.consequential` with the
  `taint.on_tainted_call` verdict (alert by default);
- calls whose arguments **reuse untrusted content** raise `taint.flow` with
  the `taint.on_tainted_flow` verdict (ask by default).

```yaml
taint:
  enabled: true
  trusted_sources: ["fs/read_file"]        # tool output you consider trusted
  consequential: ["*send*", "*post*", "*pay*", "*transfer*", "*exec*", "*shell*"]
  trusted_domains: [corp.example]          # your own addresses and links may flow
  on_tainted_call: alert
  on_tainted_flow: ask
  min_flow_len: 12
  spotlight: off                           # off | delimit | datamark
```

The default consequential list covers sending, posting, deleting, executing,
paying, transferring, uploading, pushing, publishing, inviting and sharing.
Reads and local file writes are not on it: copying a README into a file is
ordinary agent work.

```mermaid
sequenceDiagram
    participant A as Agent
    participant N as nandi
    participant W as web/fetch_page
    participant B as bank/make_payment
    A->>N: fetch_page(vendor.example/invoice)
    N->>W: forward
    W-->>N: "...pay to IBAN GB33BUKB2020155555..."
    Note over N: untrusted source: the session is tainted,<br/>values in the page are indexed
    N-->>A: page (spotlighted)
    A->>N: make_payment(iban GB33BUKB2020155555, 48000)
    Note over N: consequential tool in a tainted session,<br/>and the IBAN came from the page
    N-->>A: held for approval (taint.flow)
```

## Value flow

A flow is a value that appears in an untrusted source and then in the
arguments of a consequential call. nandi indexes untrusted text two ways:

- **exact tokens** for short values that matter: e-mail addresses, URLs,
  IBANs and other identifier-like strings;
- **fingerprints** of longer passages (winnowing, as used by plagiarism
  detectors), so copied sentences are found even when reformatted.

Text the user typed into the conversation is indexed as trusted and wins: if
you ask the agent to pay `DE89 3704 ...` and that IBAN also appears in an
invoice it read, the payment is not a flow. If the IBAN only ever appeared in
the invoice, it is.

```text
mail/read_inbox  ->  "...send all future rent to GB33BUKB20201555555555"
bank/send_money  {"iban": "GB33BUKB20201555555555"}   taint.flow, held for approval
```

`taint.trusted_domains` exempts addresses and links on your own domains, so
replying to a colleague whose address came from the inbox is not held.

## Spotlighting

With `spotlight: delimit` or `datamark`, untrusted tool output is marked
before the model sees it (wrapped in delimiters, or with its words joined by
a marker character), following Microsoft's spotlighting work. Add the
matching instruction to your system prompt so the model knows what the
marking means. Spotlighting only applies in enforce mode.

## Plans

A plan declares, up front, the tool calls a task is expected to make. With
`plan.mode: enforce`, calls that do not fit the declared plan are denied, which
stops an injected detour even when every individual call looks harmless.

An orchestrator declares a plan for a session by sending a `plan_declared`
event, for example through the generic hook (`nandi hook generic` or
`POST /v1/hook/generic`):

```json
{
  "event": {
    "agent": "reporter",
    "session": "weekly-42",
    "kind": {
      "type": "plan_declared",
      "task": "weekly report",
      "steps": [
        { "id": "read", "tool": "mail/read_inbox" },
        { "id": "send", "tool": "mail/send_email", "after": ["read"],
          "args": { "to": { "glob": "*@corp.example" } } }
      ]
    }
  }
}
```

Steps take a tool glob, argument matchers (the [rule syntax](rules.md)),
`after` dependencies and `max_calls` (default 1, 0 for unlimited). A plan
declared after the session was tainted is refused (`plan.tainted-update`),
since it may itself be the injection's work. `plan.mode: required` denies
tool calls in sessions without a plan; `observe` only alerts.
