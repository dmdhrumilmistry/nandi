# Users, roles and the audit trail

On a laptop, one person uses nandi through local access without a token.
As soon as a team shares a nandi, give each person and each tool its own
user, with only the roles it needs. Everything they change is then recorded
under their name, in the same signed audit log as agent activity.

## Who can get in

| Principal | How | Permissions |
|---|---|---|
| A user | their own token (`Authorization: Bearer nandi_...`) | what their roles allow |
| `admin` | the admin token, `admin.token` | everything (break-glass) |
| `local` | loopback, only when no admin token is configured | everything |
| `report-token` | `admin.report_token` | reporting inventories only |

Users can reach the admin API from anywhere; only local access is limited
to loopback. Tokens are random, shown once when they are created or
replaced, and stored only as SHA-256 hashes.

## Roles

Roles add up, so a person who approves held calls and also edits policy
gets both `operator` and `policy_editor`.

| Role | May |
|---|---|
| `viewer` | read everything: activity, approvals, sessions, servers, the map, policies, the audit trail; not users |
| `operator` | viewer, plus approving and denying held calls, the kill switch, accepting changed tools and server binaries, resetting behaviour models, revoking tokens |
| `policy_editor` | viewer, plus proposing policy changes |
| `policy_approver` | policy editor, plus approving, applying and rolling back policy changes, reloading policy files |
| `admin` | everything, including users |
| `hook` | only sending coding-agent hook events (`nandi hook`): for agent machines |
| `reporter` | only reporting inventories (`nandi discover --report`): for fleets |

The dashboard hides what a role cannot do, and the admin API refuses it
with `403`. Every refusal of a signed-in user is recorded too.

## Managing users

In the dashboard, the **Users** tab (admins only) lists users, adds them,
changes roles, disables, replaces tokens and deletes. From the command line:

```sh
nandi users add asha --role operator --role policy_editor   # prints the token once
nandi users list
nandi users set asha --role viewer
nandi users disable asha        # the token stops working; the user stays
nandi users rotate asha         # a new token, the old one stops working
nandi users remove asha
```

Users can also be defined in the configuration, which suits GitOps and
Helm. They are read-only in the dashboard:

```yaml
admin:
  token: env:NANDI_ADMIN_TOKEN          # break-glass
  users:
    - name: ci-policy-bot
      roles: [policy_editor]
      token: env:NANDI_CI_TOKEN
    - name: grafana
      roles: [viewer]
      token: file:/run/secrets/nandi-grafana
```

Keep the admin token for emergencies. With users in place, nobody needs it
day to day, and an action taken with it is recorded as `admin`.

## The audit trail

Every change made through the admin API is appended to the audit log as an
`admin` event, in the same hash chain and with the same Ed25519 signatures
as agent events, so `nandi audit verify` covers it. Each record says who
did what to which target, whether it worked, and the request body with
anything that looks like a secret replaced by `[redacted]`.

| Action | When |
|---|---|
| `approval.approve`, `approval.deny` | a held call was resolved |
| `agent.kill`, `agent.revive` | the kill switch |
| `pin.tool.approve`, `pin.tool.forget`, `pin.card.*` | tool and Agent Card pins |
| `server.accept_binary` | a changed MCP server binary was accepted |
| `behavior.reset` | a behaviour model was reset |
| `token.revoke` | a Biscuit token was revoked |
| `policy.*` | policy reloads and changes |
| `user.create`, `user.update`, `user.rotate`, `user.delete` | users |
| `access.denied` | a signed-in principal tried something its roles do not allow |

The dashboard's **Audit** tab shows the trail with filters by person and
kind of action, expands each record, and checks the whole log with
**Verify log**. From the command line, on the machine that holds the log:

```sh
nandi audit trail                         # newest first
nandi audit trail --actor asha --action approval.
nandi audit trail --json | jq .
```

The API is `GET /v1/audit/admin?actor=&action=&limit=`; see the
[admin API](../reference/admin-api.md).
