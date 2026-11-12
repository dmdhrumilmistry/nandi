# Identity

Every event is attributed to an agent. Policies, budgets, the kill switch
and the audit trail all key on that id, so it is worth setting up even in
monitor mode. Requests without credentials are attributed to `anonymous`
unless `identity.allow_anonymous` is `false`.

nandi checks, in order: an mTLS client certificate, a Biscuit token, a JWT,
and an API key. A credential that is present but invalid always fails the
request; it never falls back to anonymous.

## API keys

```sh
nandi key generate     # prints a new key and its SHA-256
nandi key hash <key>   # SHA-256 of an existing key (`-` reads stdin)
```

Give the key to the agent and put only the hash in `identity.api_keys` with
the agent id and its groups.


```yaml
identity:
  allow_anonymous: false
  api_key_header: x-nandi-key
  api_keys:
    - { agent: billing-agent, sha256: 3f0a..., groups: [finance] }
```

## JWT

For agents that already get tokens from an identity provider:

```yaml
identity:
  jwt:
    issuer: https://login.example.com
    audience: nandi
    jwks_file: /etc/nandi/jwks.json      # or hs256_secret: env:NANDI_JWT_SECRET
    agent_claim: sub
    groups_claim: groups
    delegator_claim: act.sub             # who the agent acts for, if delegated
```

Issuer, audience, expiry and not-before are checked; RSA, EC and Ed25519 keys
are supported.

## mTLS and SPIFFE

With `listen.tls.client_ca` set, the client certificate is the identity: its
SPIFFE ID (`spiffe://...`) when present, otherwise its common name. See
[Proxy](../guides/proxy.md#tls-and-mtls).

## Delegation with Biscuit tokens

Biscuit tokens let an orchestrator hand a sub-agent a narrower capability
without contacting nandi or holding any private key.

```sh
# 1. Once: a root key pair. Keep the private key secret.
nandi token keygen
# private: <hex>
# public:  <hex>
```

```yaml
# 2. nandi.yaml
identity:
  biscuit:
    root_public_key: "<public hex>"
```

```sh
# 3. Mint a token for the planner: any GitHub tool, valid for one hour.
nandi token mint --private-key <private hex> --agent planner --tool 'github/*' --ttl 3600

# 4. The planner narrows it for a sub-agent that may only read issues, for 10 minutes.
nandi token attenuate --token <token> --public-key <public hex> --tool github/get_issue --ttl 600

# 5. Check what a token says.
nandi token inspect --token <token>
```

The sub-agent sends the token in the `x-nandi-biscuit` header. nandi verifies
the signature chain and allows a tool only if every block permits it, so an
attenuated token can never do more than its parent.

### Revoking a token

Biscuit tokens are checked offline, so they stay valid until they expire
unless nandi is told otherwise. Every block of a token has a revocation id,
printed by `nandi token inspect`:

```text
// authority, revocation id 3b1f...c2
agent("planner");
right_prefix("github/");
...

// block 1, revocation id 9e07...41
check if operation("authenticate") or tool($t), $t == "github/get_issue";
```

Revoking a block rejects that token and every token attenuated from it, so
revoking a sub-agent's block leaves the planner's own token working, while
revoking the authority block cancels the whole family.

```sh
nandi token revoke 9e07...41     # takes effect immediately, survives restarts
nandi token revoked              # list revoked ids
```

Revocations can also be listed in the configuration under
`identity.biscuit.revoked`, which is the way to keep them when the data
directory is wiped.

