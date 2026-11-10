# Detection

The detectors scan content in both directions. Arguments, prompts and
outgoing A2A messages are checked for data that should not leave; tool
results and incoming messages for content that should not be trusted. All of
them are pattern and validator based and run in the request path.

| Detector | Looks for | Rule ids | Default verdict |
|---|---|---|---|
| Secrets | 47 credential formats (cloud, VCS, chat, payment, LLM provider and registry keys, private keys, JWTs, credentialed database URLs, high-entropy assignments) | `secret.*` | `redact` |
| PII | e-mail, phone, card numbers (Luhn), US SSN, IBAN (mod-97), Aadhaar (Verhoeff), PAN | `pii.*` | `alert` |
| Honeytokens | your planted canary strings, in both directions | `honeytoken` | `deny` |
| Injection | instruction overrides, role changes, fake delimiters, concealment, tool forcing, credential and exfiltration requests | `injection.*` | `alert` |
| Hidden text | unicode tag characters (decoded into the evidence), zero-width and bidi controls | `injection.hidden-unicode` | `alert` |
| Exfiltration links | markdown and HTML images or links that carry data in the URL | `exfil.*` | `alert` |
| SSRF | cloud metadata endpoints, private and link-local ranges, encoded loopback addresses, internal names | `ssrf.*` | `deny` |

Before scanning, base64, hex and URL-encoded runs are decoded (two levels by
default, `detect.decode_depth`) so a key or canary wrapped in an encoding is
still found. Evidence in findings is always masked: the first few characters
and the length, never the secret.

```yaml
detect:
  secrets: true
  pii: true
  injection: true
  ssrf: true
  honeytokens: ["NANDI-CANARY-7f3a9c2e81"]
  on_secret: redact
  on_pii: alert
  on_injection: alert
  on_ssrf: deny
  on_honeytoken: deny
  allow_hosts: [localhost:3000]     # internal targets an agent may reach
```

## Notes

- **SSRF blocks only real targets.** A finding blocks when an argument is the
  network target (a `url` field, or a short command such as
  `curl http://10.0.0.5/admin`). An address mentioned inside code or prose is
  an alert. The agent's own local tools may reach local development servers;
  cloud metadata stays blocked everywhere.
- **Injection scoring.** Phrases carry weights and a text is flagged only past
  a threshold, so a single weak phrase such as "act as" does not trigger it.
  Pattern matching will miss novel phrasings; the
  [ML classifier](../guides/ml-classifier.md) and the
  [data flow](data-flow.md) checks exist for that reason.
- **Honeytokens** are the cheapest high-confidence signal: plant a fake
  credential in a file or a document the agent can read, list it under
  `detect.honeytokens`, and any attempt to send it anywhere is denied.
