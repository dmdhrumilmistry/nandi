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
| GET | `/v1/events?agent=&session=&min_verdict=&kind=&since_seq=&limit=` | audit query (default 100, max 1000) |
| GET | `/v1/events/stream?agent=&min_verdict=` | live events (server-sent events) |
| GET | `/v1/sessions` | active sessions |
| GET | `/v1/approvals` | pending approvals |
| POST | `/v1/approvals/{id}/approve`, `/deny` | resolve, optional body `{"by": "name"}` |
| GET | `/v1/agents/killed` | killed agents |
| POST | `/v1/agents/{agent}/kill`, `/revive` | kill switch |
| GET | `/v1/pins/tools`, `/v1/pins/cards` | pins |
| POST | `/v1/pins/tools/approve`, `/forget` (same for cards) | body `{"id": "server/tool"}` |
| GET, DELETE | `/v1/behavior/{agent}` | behaviour model, reset |
| GET | `/v1/usage` | token and tool-call usage today |
| POST | `/v1/policy/reload` | reload policy files |
| GET | `/v1/audit/verify` | verify the audit chain |
| POST | `/v1/hook/{format}` | evaluate a hook payload |

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
```

With `admin.token` set, add `-H "Authorization: Bearer $NANDI_ADMIN_TOKEN"`.

## Security

Without a token the admin API answers only loopback clients, rejects
requests whose `Host` header is not a loopback name (DNS rebinding), and
refuses state-changing requests from another origin. With a token,
comparison is constant-time and the dashboard page is the only route that
loads without it. Bind `admin.listen` to localhost or an internal network;
it is an operator interface, not something agents should reach.
