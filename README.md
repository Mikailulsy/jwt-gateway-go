# jwt-gateway-go

A small authenticating reverse proxy in Go (standard library only). It verifies RS256/ES256
access tokens against a JWKS endpoint, then forwards the request upstream with trusted
identity headers.

**Status: learning project, not production software.** I wrote it to learn Go by working on
the problems an auth gateway has: token verification, key rotation, header trust and abuse
limits. It has not been load-tested or security-audited.

## What it does

- Verifies `RS256` and `ES256` signatures. Everything else (`none`, `HS*`) is rejected, and the
  header `alg` must match the type of the key found by `kid` (blocks algorithm-confusion attacks).
- Validates `exp` (required), `nbf`, `iss`, `aud` (string or array form) and `sub`, with a small leeway.
- Optional `TOKEN_TYP=at+jwt` enforces RFC 9068 access tokens; `crit` headers and non-canonical base64 are rejected.
- Caches the JWKS (fetches never hold the read lock, so a slow IdP cannot stall cached lookups), refreshes on TTL, and refreshes on an unknown `kid` to support key rotation.
  Unknown-`kid` refreshes are rate-limited so random-kid floods cannot hammer the identity provider.
- Keeps serving already-known keys during an IdP outage for at most 24h past the TTL, and fails closed for unknown keys.
- Strips client-supplied identity headers (`X-User*`, `X-Auth*`, underscore variants, `Authorization`,
  `Forwarded`), replaces `X-Forwarded-*` with the real peer, and sets verified `X-User-Id` / `X-User-Role`.
  Uses `ReverseProxy.Rewrite`, so `Connection: X-User-Id` cannot make the proxy drop the trusted header.
- Per-client token-bucket rate limit (IPv6 grouped by /64; idle buckets evicted; a full table denies new keys
  instead of resetting everyone), graceful shutdown, structured JSON logs. Rejection reasons are
  logged, never returned to the caller. Signature and algorithm failures log at `WARN`.

## Run

```sh
JWKS_URL=https://idp.example/.well-known/jwks.json \
TOKEN_ISSUER=https://idp.example \
TOKEN_AUDIENCE=my-api \
UPSTREAM_URL=http://localhost:9000 \
go run .
```

## Test

```sh
go test -race ./...
```

## Review history

An independent review found real bugs in the first version, all fixed with regression tests: the proxy used
`Director`, so a client `Connection: X-User-Id` header deleted the trusted identity header; underscore and
other identity-looking headers passed through; `X-Forwarded-For` was appended to instead of replaced; the rate
limiter reset all state at 100k keys; the JWKS write lock was held during the HTTP call.

Tests generate RSA and EC keys, serve a fake JWKS, and cover valid tokens, expiry, nbf, wrong
issuer/audience, foreign signatures, `alg: none`, HS256 key confusion, key rotation, refresh
rate-limiting, IdP outage behaviour, header spoofing end to end, and the rate limiter.

## Known limits (deliberately out of scope)

- No token revocation or introspection (opaque tokens, refresh flow).
- No mTLS or workload identity between gateway and upstream.
- Rate limiting keys on the peer address (not `X-Forwarded-For`; behind a load balancer all clients share a bucket
  unless you add trusted-proxy parsing) and is in-memory per instance.
- ES256 signatures are not required to be low-S; matters only if you denylist tokens by their text.
- No metrics or tracing; no `typ` or `jti` replay checks.
- Only P-256 EC keys and RSA keys of 2048 bits or more are accepted.
