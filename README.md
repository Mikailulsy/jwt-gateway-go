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
- Caches the JWKS, refreshes on TTL, and refreshes on an unknown `kid` to support key rotation.
  Unknown-`kid` refreshes are rate-limited so random-kid floods cannot hammer the identity provider.
- Keeps serving already-known keys during an IdP outage, and fails closed for unknown keys.
- Strips client-supplied `X-User-Id` / `X-User-Role` / `Authorization` and sets verified values,
  so upstream services can trust those headers.
- Per-IP token-bucket rate limit, graceful shutdown, structured JSON logs. Rejection reasons are
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

Tests generate RSA and EC keys, serve a fake JWKS, and cover valid tokens, expiry, nbf, wrong
issuer/audience, foreign signatures, `alg: none`, HS256 key confusion, key rotation, refresh
rate-limiting, IdP outage behaviour, header spoofing end to end, and the rate limiter.

## Known limits (deliberately out of scope)

- No token revocation or introspection (opaque tokens, refresh flow).
- No mTLS or workload identity between gateway and upstream.
- Rate limiting keys on the peer address (not `X-Forwarded-For`) and is in-memory per instance.
- No metrics or tracing; no `typ` or `jti` replay checks.
- Only P-256 EC keys and RSA keys of 2048 bits or more are accepted.
