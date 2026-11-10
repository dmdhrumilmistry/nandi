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

