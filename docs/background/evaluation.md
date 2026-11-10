# Evaluation

`eval/scenarios` holds scripted agent sessions. Attack scenarios are modelled
on public benchmarks and papers; benign scenarios measure false positives.
Each scenario runs against a fresh in-memory engine in enforce mode, so the
results are deterministic and run in CI on every change (`eval` job).

```
cargo test --release -p nandi-eval -- --nocapture bundled_corpus
```

## Expectations

| Expectation | Meaning |
|---|---|
| `block` | Applied verdict is `ask` (held for approval) or `deny` |
| `flag` | At least one finding (alerts count) |
| `allow` | Not blocked; findings allowed |
| `clean` | No findings at all |

A benign step that does not meet its expectation counts as a false positive.

## Coverage

| Category | Modelled on | What is checked |
|---|---|---|
| injection-flow | AgentDojo (banking, workspace, slack), InjecAgent | Values injected through tool output (IBANs, e-mail addresses, URLs) reaching consequential calls are held |
| injection-content | ASCII smuggling, markdown exfiltration, Prompt Infection | Hidden unicode, exfil links and injected instructions in tool output and inbound A2A messages are flagged |
| tool-integrity | Invariant tool poisoning and shadowing, ETDI, MCPSecBench | Poisoned descriptions, cross-tool shadowing, rug pulls, unlisted tools, name collisions |
| exfiltration | Whispers in the Machine, Caught in the Act(ivation) | Credentials, base64-wrapped honeytokens, card numbers in tool arguments |
| ssrf | Cloud metadata theft, IP encoding bypasses | Metadata endpoints and encoded loopback targets |
| policy | Progent, AgentSpec, Agent-C, MiniScope, Cedar | Argument rules, approval thresholds, sequence rules, default deny, Cedar forbids |
| a2a | A2ABreak, agent card spoofing | contextId hijack, unsigned, tampered and drifting Agent Cards |
| plan | ACE, IPIGuard, DRIFT, Conseca | Plan deviations, plans rewritten after injection, required plans |
| behavior | Loop and budget controls | Identical-call loops, call rate limits, token budgets |
| sensor | AgentSight | Undeclared credential reads, shadow AI, undeclared process execution |
| benign | Everyday agent work | Refactoring code, local dev servers, replying to colleagues, paying user-supplied payees, research, multilingual and emoji content, A2A bookings, planned workflows |

## Results at the time of writing

```
scenarios 50  attack checks 41/41 caught (100.0%)  benign checks 36 with 0 false positives (0.0%)
```

These numbers describe this corpus, not general-purpose detection rates: the
scenarios are written to exercise each defence and its known false-positive
traps. The deterministic defences (taint and value flow, pinning, policy,
plans) do not depend on recognising attack wording; the pattern detectors
(injection phrases, secrets) do, and will miss novel phrasings. The optional
ML classifier is meant to narrow that gap.

## Known trade-offs

- Value flow is lexical. Copying an untrusted value that the user also typed
  is not a flow; copying one the user never supplied is, even when benign
  (for example replying to a sender found in the inbox). Use
  `taint.trusted_domains` or `taint.trusted_sources` for such cases.
- Local file writes and reads are not "consequential" by default, so content
  copied from a README into a file is not escalated; shell execution is.
- SSRF blocks only when an argument is itself the network target; addresses
  mentioned inside code or prose raise an alert.
