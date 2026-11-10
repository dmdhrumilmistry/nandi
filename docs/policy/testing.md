# Testing policy

Three tools let you check policy without waiting for traffic.

## Single events: `nandi policy test`

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

## Recorded traffic: `nandi replay`

`replay` re-evaluates the events in the audit log with the current
configuration and policy, and prints every event whose verdict would change:

```sh
nandi replay                    # all recorded events
nandi replay --since-seq 5000   # only newer ones
```

It is the main tool for [moving from monitor to
enforce](../operations/enforce.md). The audit database can be open in only one
process, so run it while nandi is stopped, or against a copy (`--db`,
`--key`).

## The attack corpus: `nandi eval`

The repository ships a corpus of 50 scenarios modelled on public benchmarks
(AgentDojo, InjecAgent, MCPTox and others), half attacks and half everyday
benign sessions. `nandi eval` runs them against a fresh engine and reports
how many attacks were caught and how many benign steps were blocked:

```text
$ nandi eval --dir eval/scenarios
...
scenarios 50  attack checks 41/41 caught (100.0%)  benign checks 36 with 0 false positives (0.0%)
```

Use `--min-detection` and `--max-false-positives` to fail a CI job on
regressions, and add your own scenarios for the workflows you care about.
See [Evaluation](../background/evaluation.md) for the format.
