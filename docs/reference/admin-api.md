# Admin API

All endpoints are JSON and live on `admin.listen`. With `admin.token` set they
require `Authorization: Bearer <token>` (except `/healthz` and the dashboard
page); without a token they only answer loopback clients.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/` | dashboard |
| GET | `/healthz` | liveness |
| GET | `/metrics` | Prometheus text |
| GET | `/v1/status` | mode, routes, counts, audit head |
| GET | `/v1/me` | who the token belongs to: name, roles, permissions |
| GET, POST | `/v1/users` | list users; create one with `{"name", "roles"}`, which returns its token once |
| PATCH, DELETE | `/v1/users/{name}` | change `roles` or `disabled`; delete |
| POST | `/v1/users/{name}/rotate` | replace the token; returns the new one once |
| GET | `/v1/audit/admin?actor=&action=&limit=` | administrative actions from the audit log, newest first |
| GET | `/v1/exports` | each export with events sent, failed and dropped, the last delivery and error |
| POST | `/v1/exports/{name}/test` | deliver a test event to one export now (admin) |
| GET | `/v1/events?agent=&session=&min_verdict=&kind=&since_seq=&limit=` | audit query (default 100, max 1000) |
| GET | `/v1/events/stream?agent=&min_verdict=` | live events (server-sent events) |
| GET | `/v1/graph?window_secs=&buckets=&until_ms=` | agents, destinations, tools and decisions over a window ending at `until_ms` (default now), for the dashboard map (default 3600 s and 30 buckets) |
| GET | `/v1/sessions` | active sessions |
| GET | `/v1/approvals` | pending approvals |
| POST | `/v1/approvals/{id}/approve`, `/deny` | resolve, optional body `{"by": "name"}` |
| GET | `/v1/agents/killed` | killed agents |
| POST | `/v1/agents/{agent}/kill`, `/revive` | kill switch |
| GET | `/v1/pins/tools`, `/v1/pins/cards` | pins |
| POST | `/v1/pins/tools/approve`, `/forget` (same for cards) | body `{"id": "server/tool"}` |
| GET | `/v1/servers` | MCP servers with risk score and level, capabilities, package spec, approval, pinning, binary-change flags and OSV advisories |
| POST | `/v1/servers/accept-binary` | accept a changed server binary, body `{"name": "server"}` |
| GET, DELETE | `/v1/behavior/{agent}` | behaviour model, reset |
| GET | `/v1/usage` | token and tool-call usage today |
| POST | `/v1/policy/reload` | reload policy files |
| GET | `/v1/policies` | policy files (read-only), documents written in the dashboard, packs, whether changes are allowed |
| GET | `/v1/policies/packs/{name}`, `/v1/policies/docs/{name}/versions` | a pack's text; a document's versions, newest first |
| POST | `/v1/policies/validate`, `/v1/policies/preview` | check `{"ops": [...]}`; check and replay recent events to show which decisions would change |
| GET, POST | `/v1/policies/changes` | change requests; propose one with `{"title", "description", "ops"}` |
| GET | `/v1/policies/changes/{id}` | one change request |
| POST | `/v1/policies/changes/{id}/approve`, `/reject`, `/withdraw` | review with `{"comment"}`; approving applies it |
| GET | `/v1/audit/verify` | verify the audit chain |
| POST | `/v1/hook/{format}` | evaluate a hook payload |
| POST | `/v1/inventory` | store a host's AI footprint (`nandi discover --report`), JSON body up to 2 MiB; also accepts `admin.report_token` |
| GET | `/v1/inventory` | latest inventory of every reporting host, newest scan first |
| GET | `/v1/tokens/revoked` | revoked Biscuit block ids |
| POST | `/v1/tokens/revoke` | revoke a Biscuit block, body `{"id": "<hex>"}` |

## Permissions

Each route needs a permission, granted by the caller's roles (see
[Users and audit trail](../operations/users.md)): reading needs `read`;
approvals, the kill switch, pins, server binaries, behaviour resets and
token revocation need `operate`; proposing, checking and previewing policy changes `policy_propose`; approving or rejecting them and reloading policy `policy_approve`; users
`manage_users`; `/v1/hook/*` needs `hook` and `POST /v1/inventory` needs
`report`. `/v1/me` works for everyone signed in. A route not listed here
needs `admin`.

## Examples

```sh
# Who is waiting for approval?
curl -s http://127.0.0.1:8788/v1/approvals | jq '.[] | {id, summary}'

# Approve one, recording who did it.
curl -s -X POST http://127.0.0.1:8788/v1/approvals/<id>/approve -d '{"by": "priya"}' \
  -H 'content-type: application/json'

# The last 20 denied events of one agent.
curl -s 'http://127.0.0.1:8788/v1/events?agent=billing-agent&min_verdict=deny&limit=20'

# Follow the live stream (server-sent events).
curl -N http://127.0.0.1:8788/v1/events/stream?min_verdict=alert

# Who talked to what in the last 15 minutes.
curl -s 'http://127.0.0.1:8788/v1/graph?window_secs=900' | jq '.edges[:5]'

# Which machines run MCP servers that bypass nandi?
curl -s http://127.0.0.1:8788/v1/inventory \
  | jq '.[] | {host, through_nandi: .coverage.servers_via_nandi, total: .coverage.servers_total}'
```

With `admin.token` set, add `-H "Authorization: Bearer $NANDI_ADMIN_TOKEN"`.

Inventories are stored in nandi's state database under `inventory/<host>`;
a new report from a host replaces its previous one. See
[AI footprint and coverage](../guides/discovery.md).

## Security

Without a token the admin API answers only loopback clients, rejects
requests whose `Host` header is not a loopback name (DNS rebinding), and
refuses state-changing requests from another origin. With a token,
comparison is constant-time and the dashboard page is the only route that
loads without it. Bind `admin.listen` to localhost or an internal network;
it is an operator interface, not something agents should reach.
