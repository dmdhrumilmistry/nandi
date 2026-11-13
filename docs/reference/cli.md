# CLI reference

Every command accepts `-c/--config <path>` (default `nandi.yaml`, or `NANDI_CONFIG`) and
`--log-level` (default `info`, or `NANDI_LOG`). Logs go to stderr. Commands that talk to a
running nandi take `--admin <url>`, `--token` (or `NANDI_ADMIN_TOKEN`) and `--json`; the
URL and token default to the values in the configuration file.

This page is generated from `nandi <command> --help`.

## Running

### nandi run

```text
Run the gateway and the admin API

Usage: nandi run [OPTIONS]

Options:
  -c, --config <CONFIG>        Configuration file [env: NANDI_CONFIG=] [default: nandi.yaml]
      --log-level <LOG_LEVEL>  Log filter (error, warn, info, debug, trace or a tracing directive) [env: NANDI_LOG=] [default: info]
  -h, --help                   Print help
```

### nandi wrap

```text
Interpose on a stdio MCP server: `nandi wrap --server NAME -- CMD ARGS...`

Usage: nandi wrap [OPTIONS] --server <SERVER> -- <CMD>...

Arguments:
  <CMD>...  The MCP server command and its arguments

Options:
  -c, --config <CONFIG>        Configuration file [env: NANDI_CONFIG=] [default: nandi.yaml]
      --server <SERVER>        Logical server name used in policies (`server/tool`)
      --agent <AGENT>          Agent identity to attribute the traffic to [env: NANDI_AGENT=] [default: local]
      --log-level <LOG_LEVEL>  Log filter (error, warn, info, debug, trace or a tracing directive) [env: NANDI_LOG=] [default: info]
      --session <SESSION>      Session id (default: one per wrapper process)
  -h, --help                   Print help
```

### nandi hook

```text
Coding-agent hook: read the payload on stdin, ask nandi, print the answer

Usage: nandi hook [OPTIONS] <FORMAT>

Arguments:
  <FORMAT>  claude-code | cursor | generic

Options:
      --admin <URL>            
  -c, --config <CONFIG>        Configuration file [env: NANDI_CONFIG=] [default: nandi.yaml]
      --log-level <LOG_LEVEL>  Log filter (error, warn, info, debug, trace or a tracing directive) [env: NANDI_LOG=] [default: info]
      --token <TOKEN>          [env: NANDI_ADMIN_TOKEN]
      --fail-open              Allow the action when nandi is unreachable (default: block)
  -h, --help                   Print help
```

### nandi sense

```text
Watch agent processes on this host and print the sensor events (the same sensor `run` starts when `sensor.enabled` is set)

Usage: nandi sense [OPTIONS]

Options:
  -c, --config <CONFIG>        Configuration file [env: NANDI_CONFIG=] [default: nandi.yaml]
      --log-level <LOG_LEVEL>  Log filter (error, warn, info, debug, trace or a tracing directive) [env: NANDI_LOG=] [default: info]
  -h, --help                   Print help
```

### nandi discover

```text
Inventory the AI agents, MCP servers, hooks, skills and plugins on this machine and show which of them bypass nandi

Usage: nandi discover [OPTIONS]

Options:
  -c, --config <CONFIG>        Configuration file [env: NANDI_CONFIG=] [default: nandi.yaml]
      --home <DIR>             Home directory to scan (default: $HOME)
      --log-level <LOG_LEVEL>  Log filter (error, warn, info, debug, trace or a tracing directive) [env: NANDI_LOG=] [default: info]
      --project <DIR>          Project directory to scan; repeatable (default: the current directory)
      --json                   Print the inventory as JSON
      --suggest                Print the configuration changes that bring everything under nandi
      --nandi-config <PATH>    nandi config path used in suggested commands (default: --config, made absolute)
      --proxy-url <URL>        nandi proxy base URL; repeatable (default: http://127.0.0.1:8787 and http://localhost:8787, plus `listen.proxy` from the config)
      --report                 Send the inventory to the admin API (`POST /v1/inventory`) for the dashboard
      --admin <URL>            Admin API base URL (default: `admin.listen` from the config, else http://127.0.0.1:8788)
      --token <TOKEN>          Admin bearer token (default: `admin.token` from the config) [env: NANDI_ADMIN_TOKEN]
  -h, --help                   Print help
```

## Policy and evaluation

### nandi policy validate

```text
Load the configured policies and print warnings

Usage: nandi policy validate [OPTIONS]

Options:
  -c, --config <CONFIG>        Configuration file [env: NANDI_CONFIG=] [default: nandi.yaml]
      --log-level <LOG_LEVEL>  Log filter (error, warn, info, debug, trace or a tracing directive) [env: NANDI_LOG=] [default: info]
  -h, --help                   Print help
```

### nandi policy test

```text
Evaluate events from a JSON lines file, in order, and print verdicts

Usage: nandi policy test [OPTIONS] --events <EVENTS>

Options:
  -c, --config <CONFIG>        Configuration file [env: NANDI_CONFIG=] [default: nandi.yaml]
      --events <EVENTS>        One event per line, or `{"event": ..., "groups": [...]}`
      --json                   JSON lines output
      --log-level <LOG_LEVEL>  Log filter (error, warn, info, debug, trace or a tracing directive) [env: NANDI_LOG=] [default: info]
  -h, --help                   Print help
```

### nandi replay

```text
Re-evaluate recorded events with the current config and policy and show the verdicts that would change

Usage: nandi replay [OPTIONS]

Options:
  -c, --config <CONFIG>        Configuration file [env: NANDI_CONFIG=] [default: nandi.yaml]
      --db <DB>                Audit database (default: from the config)
      --key <KEY>              Audit signing key (default: from the config)
      --log-level <LOG_LEVEL>  Log filter (error, warn, info, debug, trace or a tracing directive) [env: NANDI_LOG=] [default: info]
      --since-seq <SINCE_SEQ>  Start after this sequence number [default: 0]
      --limit <LIMIT>          Maximum number of events to replay (0 = all) [default: 0]
      --json                   JSON lines output
  -h, --help                   Print help
```

### nandi eval

```text
Run the attack / false-positive evaluation corpus against the current engine (`eval/scenarios` in the repository)

Usage: nandi eval [OPTIONS]

Options:
  -c, --config <CONFIG>
          Configuration file [env: NANDI_CONFIG=] [default: nandi.yaml]
      --dir <DIR>
          Directory of scenario YAML files [default: eval/scenarios]
      --json
          Print the full report as JSON
      --log-level <LOG_LEVEL>
          Log filter (error, warn, info, debug, trace or a tracing directive) [env: NANDI_LOG=] [default: info]
      --min-detection <MIN_DETECTION>
          Fail when the attack detection rate is below this (0.0 - 1.0) [default: 0]
      --max-false-positives <MAX_FALSE_POSITIVES>
          Fail when the false-positive rate is above this (0.0 - 1.0) [default: 1]
  -h, --help
          Print help
```

## Audit log

### nandi audit verify

```text
Check the hash chain and signatures

Usage: nandi audit verify [OPTIONS]

Options:
  -c, --config <CONFIG>        Configuration file [env: NANDI_CONFIG=] [default: nandi.yaml]
      --db <DB>                
      --key <KEY>              
      --log-level <LOG_LEVEL>  Log filter (error, warn, info, debug, trace or a tracing directive) [env: NANDI_LOG=] [default: info]
      --export <EXPORT>        Verify an exported JSON lines file instead (needs --pubkey)
      --pubkey <PUBKEY>        Hex Ed25519 public key of the log
  -h, --help                   Print help
```

### nandi audit export

```text
Export every record as JSON lines

Usage: nandi audit export [OPTIONS] --out <OUT>

Options:
  -c, --config <CONFIG>        Configuration file [env: NANDI_CONFIG=] [default: nandi.yaml]
      --out <OUT>              Output file, `-` for stdout
      --db <DB>                
      --log-level <LOG_LEVEL>  Log filter (error, warn, info, debug, trace or a tracing directive) [env: NANDI_LOG=] [default: info]
      --key <KEY>              
  -h, --help                   Print help
```

### nandi audit head

```text
Print the newest record's sequence number and hash

Usage: nandi audit head [OPTIONS]

Options:
  -c, --config <CONFIG>        Configuration file [env: NANDI_CONFIG=] [default: nandi.yaml]
      --db <DB>                
      --key <KEY>              
      --log-level <LOG_LEVEL>  Log filter (error, warn, info, debug, trace or a tracing directive) [env: NANDI_LOG=] [default: info]
  -h, --help                   Print help
```

## Credentials

### nandi key generate

```text
Generate an agent API key and its SHA-256 for `identity.api_keys`

Usage: nandi key generate [OPTIONS]

Options:
  -c, --config <CONFIG>        Configuration file [env: NANDI_CONFIG=] [default: nandi.yaml]
      --log-level <LOG_LEVEL>  Log filter (error, warn, info, debug, trace or a tracing directive) [env: NANDI_LOG=] [default: info]
  -h, --help                   Print help
```

### nandi key hash

```text
SHA-256 of an existing key (`-` reads it from stdin)

Usage: nandi key hash [OPTIONS] <KEY>

Arguments:
  <KEY>  

Options:
  -c, --config <CONFIG>        Configuration file [env: NANDI_CONFIG=] [default: nandi.yaml]
      --log-level <LOG_LEVEL>  Log filter (error, warn, info, debug, trace or a tracing directive) [env: NANDI_LOG=] [default: info]
  -h, --help                   Print help
```

### nandi token keygen

```text
Generate a root key pair

Usage: nandi token keygen [OPTIONS]

Options:
  -c, --config <CONFIG>        Configuration file [env: NANDI_CONFIG=] [default: nandi.yaml]
      --log-level <LOG_LEVEL>  Log filter (error, warn, info, debug, trace or a tracing directive) [env: NANDI_LOG=] [default: info]
  -h, --help                   Print help
```

### nandi token mint

```text
Mint a token for an agent, scoped to tool patterns

Usage: nandi token mint [OPTIONS] --private-key <PRIVATE_KEY> --agent <AGENT> --tool <TOOLS>

Options:
  -c, --config <CONFIG>            Configuration file [env: NANDI_CONFIG=] [default: nandi.yaml]
      --private-key <PRIVATE_KEY>  [env: NANDI_BISCUIT_PRIVATE_KEY]
      --agent <AGENT>              
      --log-level <LOG_LEVEL>      Log filter (error, warn, info, debug, trace or a tracing directive) [env: NANDI_LOG=] [default: info]
      --tool <TOOLS>               `server/tool`, `server/*` or `*`; repeatable
      --ttl <TTL>                  Lifetime in seconds [default: 3600]
  -h, --help                       Print help
```

### nandi token attenuate

```text
Narrow a token for delegation (no private key needed)

Usage: nandi token attenuate [OPTIONS] --token <TOKEN> --public-key <PUBLIC_KEY> --tool <TOOLS>

Options:
  -c, --config <CONFIG>          Configuration file [env: NANDI_CONFIG=] [default: nandi.yaml]
      --token <TOKEN>            
      --log-level <LOG_LEVEL>    Log filter (error, warn, info, debug, trace or a tracing directive) [env: NANDI_LOG=] [default: info]
      --public-key <PUBLIC_KEY>  
      --tool <TOOLS>             
      --ttl <TTL>                
  -h, --help                     Print help
```

### nandi token inspect

```text
Print a token's blocks (signatures are not checked)

Usage: nandi token inspect [OPTIONS] --token <TOKEN>

Options:
  -c, --config <CONFIG>        Configuration file [env: NANDI_CONFIG=] [default: nandi.yaml]
      --token <TOKEN>          
      --log-level <LOG_LEVEL>  Log filter (error, warn, info, debug, trace or a tracing directive) [env: NANDI_LOG=] [default: info]
  -h, --help                   Print help
```

## Operating a running nandi

### nandi status

```text
Gateway status (admin API)

Usage: nandi status [OPTIONS]

Options:
      --admin <URL>            Admin API base URL (default: `admin.listen` from the config, else http://127.0.0.1:8788)
  -c, --config <CONFIG>        Configuration file [env: NANDI_CONFIG=] [default: nandi.yaml]
      --log-level <LOG_LEVEL>  Log filter (error, warn, info, debug, trace or a tracing directive) [env: NANDI_LOG=] [default: info]
      --token <TOKEN>          Admin bearer token (default: `admin.token` from the config) [env: NANDI_ADMIN_TOKEN]
      --json                   Print raw JSON instead of a summary
  -h, --help                   Print help
```

### nandi sessions

```text
Active sessions (admin API)

Usage: nandi sessions [OPTIONS]

Options:
      --admin <URL>            Admin API base URL (default: `admin.listen` from the config, else http://127.0.0.1:8788)
  -c, --config <CONFIG>        Configuration file [env: NANDI_CONFIG=] [default: nandi.yaml]
      --log-level <LOG_LEVEL>  Log filter (error, warn, info, debug, trace or a tracing directive) [env: NANDI_LOG=] [default: info]
      --token <TOKEN>          Admin bearer token (default: `admin.token` from the config) [env: NANDI_ADMIN_TOKEN]
      --json                   Print raw JSON instead of a summary
  -h, --help                   Print help
```

### nandi approvals

```text
Pending approvals (admin API)

Usage: nandi approvals [OPTIONS] [COMMAND]

Commands:
  list     List calls waiting for a decision
  approve  Let a held call through
  deny     Block a held call
  help     Print this message or the help of the given subcommand(s)

Options:
  -c, --config <CONFIG>        Configuration file [env: NANDI_CONFIG=] [default: nandi.yaml]
      --log-level <LOG_LEVEL>  Log filter (error, warn, info, debug, trace or a tracing directive) [env: NANDI_LOG=] [default: info]
      --admin <URL>            Admin API base URL (default: `admin.listen` from the config, else http://127.0.0.1:8788)
      --token <TOKEN>          Admin bearer token (default: `admin.token` from the config) [env: NANDI_ADMIN_TOKEN]
      --json                   Print raw JSON instead of a summary
  -h, --help                   Print help
```

### nandi kill

```text
Deny every action of an agent until revived (admin API)

Usage: nandi kill [OPTIONS] <AGENT>

Arguments:
  <AGENT>  

Options:
      --admin <URL>            Admin API base URL (default: `admin.listen` from the config, else http://127.0.0.1:8788)
  -c, --config <CONFIG>        Configuration file [env: NANDI_CONFIG=] [default: nandi.yaml]
      --log-level <LOG_LEVEL>  Log filter (error, warn, info, debug, trace or a tracing directive) [env: NANDI_LOG=] [default: info]
      --token <TOKEN>          Admin bearer token (default: `admin.token` from the config) [env: NANDI_ADMIN_TOKEN]
      --json                   Print raw JSON instead of a summary
  -h, --help                   Print help
```

### nandi revive

```text
Lift the kill switch for an agent (admin API)

Usage: nandi revive [OPTIONS] <AGENT>

Arguments:
  <AGENT>  

Options:
      --admin <URL>            Admin API base URL (default: `admin.listen` from the config, else http://127.0.0.1:8788)
  -c, --config <CONFIG>        Configuration file [env: NANDI_CONFIG=] [default: nandi.yaml]
      --log-level <LOG_LEVEL>  Log filter (error, warn, info, debug, trace or a tracing directive) [env: NANDI_LOG=] [default: info]
      --token <TOKEN>          Admin bearer token (default: `admin.token` from the config) [env: NANDI_ADMIN_TOKEN]
      --json                   Print raw JSON instead of a summary
  -h, --help                   Print help
```

### nandi pins

```text
Tool definition pins (admin API)

Usage: nandi pins [OPTIONS] [COMMAND]

Commands:
  list     List pinned tool (or card) definitions and pending changes
  approve  Accept the changed definition of `server/tool`
  forget   Drop a pin; the next sighting is pinned afresh
  help     Print this message or the help of the given subcommand(s)

Options:
  -c, --config <CONFIG>        Configuration file [env: NANDI_CONFIG=] [default: nandi.yaml]
      --log-level <LOG_LEVEL>  Log filter (error, warn, info, debug, trace or a tracing directive) [env: NANDI_LOG=] [default: info]
      --cards                  A2A Agent Card pins instead of tool pins
      --admin <URL>            Admin API base URL (default: `admin.listen` from the config, else http://127.0.0.1:8788)
      --token <TOKEN>          Admin bearer token (default: `admin.token` from the config) [env: NANDI_ADMIN_TOKEN]
      --json                   Print raw JSON instead of a summary
  -h, --help                   Print help
```

### nandi servers

```text
MCP servers with their package, approval, pinning and risk (admin API)

Usage: nandi servers [OPTIONS]

Options:
  -c, --config <CONFIG>        Configuration file [env: NANDI_CONFIG=] [default: nandi.yaml]
      --log-level <LOG_LEVEL>  Log filter (error, warn, info, debug, trace or a tracing directive) [env: NANDI_LOG=] [default: info]
      --admin <URL>            Admin API base URL (default: `admin.listen` from the config, else http://127.0.0.1:8788)
      --token <TOKEN>          Admin bearer token (default: `admin.token` from the config) [env: NANDI_ADMIN_TOKEN]
      --json                   Print raw JSON instead of a summary
  -h, --help                   Print help
```

### nandi tail

```text
Stream live events (admin API)

Usage: nandi tail [OPTIONS]

Options:
      --agent <AGENT>              
  -c, --config <CONFIG>            Configuration file [env: NANDI_CONFIG=] [default: nandi.yaml]
      --log-level <LOG_LEVEL>      Log filter (error, warn, info, debug, trace or a tracing directive) [env: NANDI_LOG=] [default: info]
      --min-verdict <MIN_VERDICT>  allow | alert | redact | ask | deny
      --admin <URL>                Admin API base URL (default: `admin.listen` from the config, else http://127.0.0.1:8788)
      --token <TOKEN>              Admin bearer token (default: `admin.token` from the config) [env: NANDI_ADMIN_TOKEN]
      --json                       Print raw JSON instead of a summary
  -h, --help                       Print help
```

## Setup

### nandi init

```text
Write a starter nandi.yaml and policies

Usage: nandi init [OPTIONS]

Options:
  -c, --config <CONFIG>        Configuration file [env: NANDI_CONFIG=] [default: nandi.yaml]
      --dir <DIR>              [default: .]
      --force                  Overwrite existing files
      --log-level <LOG_LEVEL>  Log filter (error, warn, info, debug, trace or a tracing directive) [env: NANDI_LOG=] [default: info]
  -h, --help                   Print help
```

### nandi version

```text
Print the version

Usage: nandi version [OPTIONS]

Options:
  -c, --config <CONFIG>        Configuration file [env: NANDI_CONFIG=] [default: nandi.yaml]
      --log-level <LOG_LEVEL>  Log filter (error, warn, info, debug, trace or a tracing directive) [env: NANDI_LOG=] [default: info]
  -h, --help                   Print help
```
