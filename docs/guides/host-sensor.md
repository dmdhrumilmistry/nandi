# Host sensor

Proxies and hooks see what an agent *asks* for. The host sensor (Linux only)
watches what its process tree *does*: the processes it starts, the sensitive
files it opens and the hosts it connects to. These effects become `process`,
`file` and `network` events that the engine correlates with the tool calls it
saw, so an undeclared credential read or a direct call to an LLM provider
that bypasses the gateway (shadow AI) raises a finding.

Enable it in `nandi.yaml`; `nandi run` then starts it alongside the proxy,
and `nandi sense` prints its events as JSON lines without the gateway:

```yaml
sensor:
  enabled: true
  backend: auto          # auto | procfs | ebpf
  agent_comms: [claude, codex, cursor, gemini, aider, goose, opencode]
  sensitive_paths: ["*/.ssh/*", "*/.aws/credentials", "*/.env", "/etc/shadow"]
  llm_hosts: [api.openai.com, api.anthropic.com]
```

A process belongs to an agent when it, or one of its ancestors, matches
`agent_comms` by process name, executable name or one of the first two argv
entries (so `node /usr/local/bin/claude` counts as `claude`). Everything the
agent spawns is attributed to it, and events carry the agent root's pid as
the session (`pid:<n>`).

## Backends

| Backend | How it works | Needs | Misses |
|---------|--------------|-------|--------|
| `procfs` | Polls `/proc` every 500 ms: new processes, their open file descriptors and TCP connections | Nothing beyond read access to the agents' `/proc` entries (same user, or root) | Processes, files and connections that come and go between two polls |
| `ebpf` | Kernel tracepoints on fork, exec, openat/openat2/open, connect and exit, delivered through a BPF ring buffer | The Linux x86_64 or aarch64 release binary (or a build with `--features ebpf`), Linux 5.8+, root or `CAP_BPF` + `CAP_PERFMON` (on kernels before 5.8 there is no ring buffer) | Nothing it hooks, however short-lived |
| `auto` (default) | `ebpf` when the binary includes it and the program loads, otherwise `procfs` with an info log | | |

An explicit `backend: ebpf` fails to start instead of falling back, which is
what you want when the sensor is a requirement. The log line `host sensor
started (ebpf backend)` (or `procfs backend`) shows which one runs.

The x86_64 and aarch64 Linux release binaries and container images include
the eBPF backend; `nandi version` prints `(ebpf)` when it is built in. There
is nothing else to install: the BPF program is compiled into the binary.

```sh
sudo nandi sense
```

Building from source, add `--features ebpf` (needs `clang` and the libbpf
headers at build time; on Debian/Ubuntu `apt install clang llvm libbpf-dev`;
set `CLANG` to use a specific compiler):

```sh
cargo build --release -p nandi --features ebpf
```

Instead of running as root, the binary can be given capabilities:

```sh
sudo setcap cap_bpf,cap_perfmon,cap_dac_read_search,cap_sys_ptrace+ep "$(command -v nandi)"
```

`CAP_BPF` and `CAP_PERFMON` load and attach the programs,
`CAP_DAC_READ_SEARCH` reads the tracepoint ids under tracefs, and
`CAP_SYS_PTRACE` reads other users' `/proc/<pid>/exe` and `cwd` (used to
fill in executables and resolve relative paths). Note that these capabilities
let the binary observe every process on the host; treat it like any other
privileged agent.

## What is reported

- **process**: every exec by a process in an agent tree (not the agent
  itself) with pid, parent pid, uid, name, executable and argv. The eBPF
  backend reports only successful execs, names the executable by the path
  that was executed (procfs reports the resolved `/proc/<pid>/exe`) and
  captures up to 8 argv entries of 127 bytes in the kernel, completed from
  `/proc` when the process still runs.
- **file**: opens of paths matching `sensitive_paths`, once per process and
  path, with a write flag (`O_WRONLY` or `O_RDWR`). The eBPF backend reports
  open attempts (including ones that fail, e.g. a probe for `~/.ssh/id_rsa`)
  and resolves relative paths against the process's working directory or
  directory file descriptor.
- **network**: outbound connections to non-loopback addresses, once per
  process, address and port. Addresses of `llm_hosts` (resolved every five
  minutes) are reported by name. The eBPF backend sees `connect()` on any
  IPv4/IPv6 socket, including UDP; procfs sees established TCP connections.

The eBPF backend keeps its overhead low by filtering in the kernel: exec and
exit records are sent for every process (attribution needs them), opens and
connects only for processes in agent trees. Children forked by a watched
process are watched from their first instruction. The sensor ignores its own
process.

## Limitations

- No TLS plaintext capture (`ssl_uprobes` is reserved): the sensor sees
  where an agent connects, not what it sends. Route traffic through the
  gateway to inspect content.
- File paths are captured up to 255 bytes and are reported as the agent
  passed them, normalised lexically; symlinks are not resolved.
- Agents that started before the sensor are picked up from `/proc` at
  startup, but anything they did before that is not reported.
- Under extreme load the ring buffer (512 KiB) can overflow and drop
  records (logged as a warning); the sensor recovers process state from
  `/proc` periodically.
- Syscalls are hooked through the raw `sys_enter` tracepoint, so a small
  BPF program runs on every syscall and returns at once for the ones it does
  not watch. Arguments are read without faulting pages in: a path in memory
  that was never touched (rare) is dropped. 32-bit (compat) syscalls on
  x86_64 are not decoded.
- Containers: run the sensor on the host (or with `--pid=host`) and in the
  host's pid namespace; pids are reported as seen from the sensor.
