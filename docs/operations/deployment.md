# Deployment

## Footprint

Measured in CI on the static release builds, idle with the example
configuration:

| | x86_64 | aarch64 |
|---|---|---|
| binary (static, stripped) | 20 MB | 16 MB |
| memory at idle (RSS) | 21 MB | 19 MB |
| evaluation per event, median | about 25 µs | about 30 µs |

The tokio runtime uses at most four worker threads by default
(`NANDI_WORKER_THREADS` overrides it). The optional ML classifier changes
these numbers substantially; see its [cost section](../guides/ml-classifier.md#cost).

## Docker

```sh
docker build -t nandi .
docker run --rm -p 8787:8787 -p 8788:8788 \
  -v "$PWD:/etc/nandi" -e NANDI_ADMIN_TOKEN=change-me nandi
```

Inside a container the listeners must bind `0.0.0.0` (set `listen.proxy` and
`admin.listen` accordingly) and `admin.token` must be set, because without a
token the admin API only answers loopback clients. Mount a writable volume
for `data_dir`.

## systemd

```ini
[Unit]
Description=nandi agent gateway
After=network-online.target

[Service]
ExecStart=/usr/local/bin/nandi run -c /etc/nandi/nandi.yaml
WorkingDirectory=/var/lib/nandi
User=nandi
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/nandi
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

Point `data_dir` at `/var/lib/nandi` and use `admin.token: file:/etc/nandi/admin-token`.
The eBPF sensor needs extra privileges; see [Host sensor](../guides/host-sensor.md).

## Next to agents or in front of them

- **One per developer machine**, with hooks and wrapped MCP servers: the
  default localhost configuration.
- **A shared gateway** in front of production agents: bind the proxy to an
  internal address, require credentials (`identity.allow_anonymous: false`),
  terminate TLS or use mTLS, and set an admin token.
- **A sidecar** per agent pod in Kubernetes: the same binary, one per pod,
  with its own data volume. Each nandi keeps its own sessions and audit log.
