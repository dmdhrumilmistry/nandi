# Policy packs

Packs are ready-made rule files for common situations. They ship inside the
binary and are plain YAML, so you can read them, copy them and edit them.

```sh
nandi policy packs                                  # list them
nandi policy pack payments > policies/payments.yaml # save one
```

Then add the file to `policy.rules`:

```yaml
policy:
  rules:
    - policies/rules.yaml
    - policies/payments.yaml
```

| Pack | What it does |
|---|---|
| `coding-agent` | Baseline for Claude Code, Cursor and similar: no recursive deletes of the root, home or parent directories, no piping downloads into a shell, force pushes to main need approval, no reading SSH keys or cloud credentials through the shell, an alert when TLS verification is turned off |
| `payments` | Any tool that moves money is held for approval, whatever it is called; payments from a session that read untrusted content are refused |
| `protect-production` | `kubectl`/`helm` against production contexts, cloud CLIs with production profiles, `terraform apply`/`destroy` and database shells on production hosts need approval; destructive SQL is refused |
| `sensitive-saas` | Fetches and shell requests to HR, payroll, finance and identity SaaS (Workday, Rippling, NetSuite, Okta, 1Password and others) are refused |
| `tainted-outbound` | After a session reads untrusted content, outbound messages need approval and user or permission changes are refused |

`payments` and `tainted-outbound` match on [capabilities](capabilities.md)
(`payment`, `external_send`, `identity_admin`), which nandi infers from tool
names, descriptions and schemas, so they cover tools you have never named in a
rule. The others match on arguments such as `command`, `query` and `url`.

The patterns use common naming conventions (`prod`, `production`, `live`).
Read a pack before enforcing it and adjust the patterns to your environment;
`nandi policy test` and `nandi replay` show what it would change on your
traffic.
