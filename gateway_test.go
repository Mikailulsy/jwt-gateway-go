package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

var b64 = base64.RawURLEncoding

type testIdP struct {
	srv     *httptest.Server
	hits    atomic.Int32
	keys    atomic.Pointer[[]jwk]
	rsaKey  *rsa.PrivateKey
	ecKey   *ecdsa.PrivateKey
	current time.Time
}

func newIdP(t *testing.T) *testIdP {
	t.Helper()
	idp := &testIdP{}
	var err error
	if idp.rsaKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		t.Fatal(err)
	}
	if idp.ecKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	idp.publish(rsaJWK("rsa-1", &idp.rsaKey.PublicKey), ecJWK("ec-1", &idp.ecKey.PublicKey))
	idp.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		idp.hits.Add(1)
		_ = json.NewEncoder(w).Encode(jwks{Keys: *idp.keys.Load()})
	}))
	t.Cleanup(idp.srv.Close)
	return idp
}

func (i *testIdP) publish(keys ...jwk) { i.keys.Store(&keys) }

func rsaJWK(kid string, p *rsa.PublicKey) jwk {
	return jwk{Kty: "RSA", Kid: kid, Use: "sig", N: b64.EncodeToString(p.N.Bytes()), E: b64.EncodeToString(big.NewInt(int64(p.E)).Bytes())}
}

func ecJWK(kid string, p *ecdsa.PublicKey) jwk {
	return jwk{Kty: "EC", Kid: kid, Use: "sig", Crv: "P-256", X: b64.EncodeToString(p.X.FillBytes(make([]byte, 32))), Y: b64.EncodeToString(p.Y.FillBytes(make([]byte, 32)))}
}

func seg(v any) string { b, _ := json.Marshal(v); return b64.EncodeToString(b) }

func signRS256(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	in := seg(map[string]any{"alg": "RS256", "kid": kid, "typ": "JWT"}) + "." + seg(claims)
	d := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, d[:])
	if err != nil {
		t.Fatal(err)
	}
	return in + "." + b64.EncodeToString(sig)
}

func signES256(t *testing.T, key *ecdsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	in := seg(map[string]any{"alg": "ES256", "kid": kid}) + "." + seg(claims)
	d := sha256.Sum256([]byte(in))
	r, s, err := ecdsa.Sign(rand.Reader, key, d[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return in + "." + b64.EncodeToString(sig)
}

func good(now time.Time) map[string]any {
	return map[string]any{"sub": "user-1", "iss": "https://idp.test", "aud": "api", "exp": now.Add(time.Hour).Unix(), "nbf": now.Add(-time.Minute).Unix(), "role": "admin"}
}

func newVerifier(idp *testIdP, now time.Time) *Verifier {
	ks := NewKeySet(idp.srv.URL, time.Hour, 0)
	return &Verifier{Keys: ks, Issuer: "https://idp.test", Audience: "api", Leeway: 5 * time.Second, Now: func() time.Time { return now }}
}

func TestVerify(t *testing.T) {
	idp := newIdP(t)
	now := time.Now()
	v := newVerifier(idp, now)

	mut := func(f func(m map[string]any)) map[string]any { m := good(now); f(m); return m }
	otherRSA, _ := rsa.GenerateKey(rand.Reader, 2048)

	// HS256 token signed with the RSA public key bytes as the HMAC secret
	// (algorithm confusion attack).
	hs := func() string {
		in := seg(map[string]any{"alg": "HS256", "kid": "rsa-1"}) + "." + seg(good(now))
		mac := hmac.New(sha256.New, idp.rsaKey.PublicKey.N.Bytes())
		mac.Write([]byte(in))
		return in + "." + b64.EncodeToString(mac.Sum(nil))
	}()
	none := seg(map[string]any{"alg": "none", "kid": "rsa-1"}) + "." + seg(good(now)) + "."

	tests := []struct {
		name    string
		token   string
		wantErr error
	}{
		{"valid RS256", signRS256(t, idp.rsaKey, "rsa-1", good(now)), nil},
		{"valid ES256", signES256(t, idp.ecKey, "ec-1", good(now)), nil},
		{"audience as array", signRS256(t, idp.rsaKey, "rsa-1", mut(func(m map[string]any) { m["aud"] = []string{"other", "api"} })), nil},
		{"expired", signRS256(t, idp.rsaKey, "rsa-1", mut(func(m map[string]any) { m["exp"] = now.Add(-time.Hour).Unix() })), ErrExpired},
		{"missing exp", signRS256(t, idp.rsaKey, "rsa-1", mut(func(m map[string]any) { delete(m, "exp") })), ErrExpired},
		{"not yet valid", signRS256(t, idp.rsaKey, "rsa-1", mut(func(m map[string]any) { m["nbf"] = now.Add(time.Hour).Unix() })), ErrNotYet},
		{"wrong issuer", signRS256(t, idp.rsaKey, "rsa-1", mut(func(m map[string]any) { m["iss"] = "https://evil.test" })), ErrIssuer},
		{"wrong audience", signRS256(t, idp.rsaKey, "rsa-1", mut(func(m map[string]any) { m["aud"] = "other" })), ErrAudience},
		{"missing subject", signRS256(t, idp.rsaKey, "rsa-1", mut(func(m map[string]any) { delete(m, "sub") })), ErrMalformed},
		{"signed by another key", signRS256(t, otherRSA, "rsa-1", good(now)), ErrSignature},
		{"alg none", none, ErrAlg},
		{"HS256 confusion", hs, ErrAlg},
		{"RS256 header on EC key", signES256(t, idp.ecKey, "ec-1", good(now))[:0] + swapAlg(signES256(t, idp.ecKey, "ec-1", good(now)), "RS256"), ErrAlg},
		{"garbage", "not.a.jwt", ErrMalformed},
		{"two segments", "a.b", ErrMalformed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := v.Verify(tc.token)
			if tc.wantErr == nil && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantErr != nil && !isErr(err, tc.wantErr) {
				t.Fatalf("got %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func isErr(got, want error) bool {
	for e := got; e != nil; {
		if e == want {
			return true
		}
		u, ok := e.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		e = u.Unwrap()
	}
	return false
}

func swapAlg(token, alg string) string {
	parts := splitDot(token)
	var h map[string]any
	raw, _ := b64.DecodeString(parts[0])
	_ = json.Unmarshal(raw, &h)
	h["alg"] = alg
	return seg(h) + "." + parts[1] + "." + parts[2]
}

func splitDot(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == '.' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	return append(out, cur)
}

func TestKeyRotationRefreshesOnUnknownKid(t *testing.T) {
	idp := newIdP(t)
	now := time.Now()
	v := newVerifier(idp, now)

	if _, err := v.Verify(signRS256(t, idp.rsaKey, "rsa-1", good(now))); err != nil {
		t.Fatal(err)
	}
	before := idp.hits.Load()

	rotated, _ := rsa.GenerateKey(rand.Reader, 2048)
	idp.publish(rsaJWK("rsa-2", &rotated.PublicKey))
	if _, err := v.Verify(signRS256(t, rotated, "rsa-2", good(now))); err != nil {
		t.Fatalf("rotated key should be picked up: %v", err)
	}
	if idp.hits.Load() != before+1 {
		t.Fatalf("expected exactly one refresh, got %d", idp.hits.Load()-before)
	}
}

func TestUnknownKidRefreshIsRateLimited(t *testing.T) {
	idp := newIdP(t)
	now := time.Now()
	clock := now
	ks := NewKeySet(idp.srv.URL, time.Hour, time.Minute)
	ks.now = func() time.Time { return clock }
	v := &Verifier{Keys: ks, Issuer: "https://idp.test", Audience: "api", Now: func() time.Time { return now }}

	for i := 0; i < 20; i++ {
		_, err := v.Verify(signRS256(t, idp.rsaKey, "attacker-kid", good(now)))
		if !isErr(err, ErrUnknownKey) {
			t.Fatalf("got %v, want ErrUnknownKey", err)
		}
	}
	if got := idp.hits.Load(); got != 1 {
		t.Fatalf("20 bad-kid tokens caused %d JWKS fetches, want 1", got)
	}
}

func TestKeepsServingKnownKeysWhenIdPIsDown(t *testing.T) {
	idp := newIdP(t)
	now := time.Now()
	clock := now
	ks := NewKeySet(idp.srv.URL, time.Minute, 0)
	ks.now = func() time.Time { return clock }
	v := &Verifier{Keys: ks, Issuer: "https://idp.test", Audience: "api", Now: func() time.Time { return now }}

	if _, err := v.Verify(signRS256(t, idp.rsaKey, "rsa-1", good(now))); err != nil {
		t.Fatal(err)
	}
	idp.srv.Close()
	clock = clock.Add(time.Hour) // cache is stale, refresh will fail
	if _, err := v.Verify(signRS256(t, idp.rsaKey, "rsa-1", good(now))); err != nil {
		t.Fatalf("known key should survive an IdP outage: %v", err)
	}
	if _, err := v.Verify(signRS256(t, idp.rsaKey, "never-seen", good(now))); err == nil {
		t.Fatal("unknown key must fail closed during an outage")
	}
}

func TestGatewayEndToEnd(t *testing.T) {
	idp := newIdP(t)
	now := time.Now()

	var gotID, gotRole, gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotID, gotRole, gotAuth = r.Header.Get("X-User-Id"), r.Header.Get("X-User-Role"), r.Header.Get("Authorization")
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)

	h := Authenticate(newVerifier(idp, now), slog.New(slog.NewTextHandler(io.Discard, nil)), NewProxy(u))
	gw := httptest.NewServer(h)
	defer gw.Close()

	do := func(authz string, extra map[string]string) *http.Response {
		req, _ := http.NewRequest("GET", gw.URL+"/orders", nil)
		if authz != "" {
			req.Header.Set("Authorization", authz)
		}
		for k, v := range extra {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	if r := do("", nil); r.StatusCode != 401 || r.Header.Get("WWW-Authenticate") == "" {
		t.Fatalf("missing token: got %d", r.StatusCode)
	}
	if r := do("Bearer garbage", nil); r.StatusCode != 401 {
		t.Fatalf("bad token: got %d", r.StatusCode)
	}
	if r := do("Basic abc", nil); r.StatusCode != 401 {
		t.Fatalf("wrong scheme: got %d", r.StatusCode)
	}

	token := signRS256(t, idp.rsaKey, "rsa-1", good(now))
	r := do("Bearer "+token, map[string]string{"X-User-Id": "spoofed", "X-User-Role": "superadmin"})
	if r.StatusCode != 200 {
		t.Fatalf("valid token: got %d", r.StatusCode)
	}
	if gotID != "user-1" || gotRole != "admin" {
		t.Fatalf("upstream saw spoofable identity: id=%q role=%q", gotID, gotRole)
	}
	if gotAuth != "" {
		t.Fatal("bearer token must not be forwarded upstream")
	}
}

func TestRateLimit(t *testing.T) {
	clock := time.Now()
	l := NewRateLimit(1, 3)
	l.now = func() time.Time { return clock }
	for i := 0; i < 3; i++ {
		if !l.Allow("a") {
			t.Fatalf("request %d should pass within burst", i)
		}
	}
	if l.Allow("a") {
		t.Fatal("burst exhausted, request must be limited")
	}
	if !l.Allow("b") {
		t.Fatal("other keys are independent")
	}
	clock = clock.Add(2 * time.Second)
	if !l.Allow("a") {
		t.Fatal("tokens should refill over time")
	}
}
