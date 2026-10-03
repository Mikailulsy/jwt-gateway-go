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

// ---- regression tests for review findings ----

func gatewayWithUpstream(t *testing.T, idp *testIdP, now time.Time) (gw *httptest.Server, seen *http.Header) {
	t.Helper()
	var last http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		last = r.Header.Clone()
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(upstream.Close)
	u, _ := url.Parse(upstream.URL)
	h := Authenticate(newVerifier(idp, now), slog.New(slog.NewTextHandler(io.Discard, nil)), NewProxy(u))
	gw = httptest.NewServer(h)
	t.Cleanup(gw.Close)
	return gw, &last
}

func TestProxyCannotBeTrickedIntoDroppingOrForgingIdentity(t *testing.T) {
	idp := newIdP(t)
	now := time.Now()
	gw, seen := gatewayWithUpstream(t, idp, now)

	claims := good(now)
	delete(claims, "role") // token without a role: client-supplied roles must not survive
	token := signRS256(t, idp.rsaKey, "rsa-1", claims)

	req, _ := http.NewRequest("GET", gw.URL+"/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Connection", "X-User-Id")          // hop-by-hop trick
	req.Header["X_user_role"] = []string{"superadmin"} // underscore variant
	req.Header.Set("X-User-Email", "ceo@corp")         // other identity-looking header
	req.Header.Set("X-Auth-Token", "forged")
	req.Header.Set("X-Forwarded-For", "10.0.0.1") // spoofed client IP
	req.Header.Set("Forwarded", "for=10.0.0.1")
	req.Header.Set("X-Forwarded-Host", "evil.test")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("request failed: %v %v", err, resp)
	}
	h := *seen
	if got := h.Get("X-User-Id"); got != "user-1" {
		t.Fatalf("verified X-User-Id lost: %q", got)
	}
	for _, name := range []string{"X_user_role", "X-User-Role", "X-User-Email", "X-Auth-Token", "Forwarded", "Authorization"} {
		if v := h[name]; len(v) != 0 {
			t.Fatalf("%s reached upstream: %v", name, v)
		}
	}
	if xff := h.Get("X-Forwarded-For"); xff == "10.0.0.1" || len(h.Values("X-Forwarded-For")) != 1 || xff == "" {
		t.Fatalf("X-Forwarded-For must be replaced by the peer address, got %q", xff)
	}
	if h.Get("X-Forwarded-Host") == "evil.test" {
		t.Fatal("client X-Forwarded-Host must not be trusted")
	}
}

func TestRateLimitEvictsIdleKeysInsteadOfResetting(t *testing.T) {
	clock := time.Now()
	l := NewRateLimit(1, 2)
	l.maxKeys = 3
	l.now = func() time.Time { return clock }

	l.Allow("victim")
	l.Allow("victim")
	if l.Allow("victim") {
		t.Fatal("victim should be limited")
	}
	l.Allow("a")
	// Table is full (victim, a, + one more). New key churn must not reset victim.
	l.Allow("b")
	if l.Allow("c") {
		t.Fatal("full table with no idle buckets must deny new keys (fail closed)")
	}
	if l.Allow("victim") {
		t.Fatal("churn must not wipe the victim's bucket")
	}
	clock = clock.Add(10 * time.Second) // everyone refills, idle buckets are evictable
	if !l.Allow("c") {
		t.Fatal("after idle eviction a new key should be admitted")
	}
}

func TestClientKeyGroupsIPv6By64(t *testing.T) {
	a := clientKey("[2001:db8:1:2::1]:5000")
	b := clientKey("[2001:db8:1:2:ffff::9]:6000")
	c := clientKey("[2001:db8:1:3::1]:5000")
	if a != b {
		t.Fatalf("same /64 must share a key: %s vs %s", a, b)
	}
	if a == c {
		t.Fatal("different /64 must not share a key")
	}
	if clientKey("203.0.113.9:1234") != "203.0.113.9" {
		t.Fatal("ipv4 key should be the bare address")
	}
}

func TestRateLimitMiddleware(t *testing.T) {
	l := NewRateLimit(0.001, 2)
	h := l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	codes := []int{}
	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "198.51.100.7:4444"
		h.ServeHTTP(rec, req)
		codes = append(codes, rec.Code)
	}
	if codes[0] != 200 || codes[1] != 200 || codes[2] != 429 {
		t.Fatalf("got %v, want [200 200 429]", codes)
	}
}

func TestSlowIdPDoesNotBlockCachedKeys(t *testing.T) {
	idp := newIdP(t)
	now := time.Now()
	v := newVerifier(idp, now)
	if _, err := v.Verify(signRS256(t, idp.rsaKey, "rsa-1", good(now))); err != nil {
		t.Fatal(err)
	}

	release := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		_ = json.NewEncoder(w).Encode(jwks{Keys: *idp.keys.Load()})
	}))
	defer slow.Close()
	defer close(release)
	v.Keys.url = slow.URL

	// An unknown kid starts a slow refresh in the background...
	go func() { _, _ = v.Verify(signRS256(t, idp.rsaKey, "new-kid", good(now))) }()
	time.Sleep(100 * time.Millisecond)

	// ...while a request with a cached, fresh key must still be served promptly.
	done := make(chan error, 1)
	go func() { _, err := v.Verify(signRS256(t, idp.rsaKey, "rsa-1", good(now))); done <- err }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cached-key verification was blocked behind a slow JWKS fetch")
	}
}

func TestStaleKeysExpireDuringLongOutage(t *testing.T) {
	idp := newIdP(t)
	now := time.Now()
	clock := now
	ks := NewKeySet(idp.srv.URL, time.Minute, 0)
	ks.maxStale = time.Hour
	ks.now = func() time.Time { return clock }
	v := &Verifier{Keys: ks, Issuer: "https://idp.test", Audience: "api", Now: func() time.Time { return now }}

	if _, err := v.Verify(signRS256(t, idp.rsaKey, "rsa-1", good(now))); err != nil {
		t.Fatal(err)
	}
	idp.srv.Close()
	clock = clock.Add(30 * time.Minute)
	if _, err := v.Verify(signRS256(t, idp.rsaKey, "rsa-1", good(now))); err != nil {
		t.Fatalf("within maxStale a known key is still served: %v", err)
	}
	clock = clock.Add(2 * time.Hour)
	if _, err := v.Verify(signRS256(t, idp.rsaKey, "rsa-1", good(now))); err == nil {
		t.Fatal("beyond maxStale verification must fail closed")
	}
}

func TestTypAndCritHeaders(t *testing.T) {
	idp := newIdP(t)
	now := time.Now()
	v := newVerifier(idp, now)
	v.RequiredTyp = "at+jwt"

	mk := func(hdr map[string]any) string {
		in := seg(hdr) + "." + seg(good(now))
		d := sha256.Sum256([]byte(in))
		sig, _ := rsa.SignPKCS1v15(rand.Reader, idp.rsaKey, crypto.SHA256, d[:])
		return in + "." + b64.EncodeToString(sig)
	}
	if _, err := v.Verify(mk(map[string]any{"alg": "RS256", "kid": "rsa-1", "typ": "at+jwt"})); err != nil {
		t.Fatalf("at+jwt should pass: %v", err)
	}
	if _, err := v.Verify(mk(map[string]any{"alg": "RS256", "kid": "rsa-1", "typ": "JWT"})); err == nil {
		t.Fatal("wrong typ must be rejected when RequiredTyp is set")
	}
	v.RequiredTyp = ""
	if _, err := v.Verify(mk(map[string]any{"alg": "RS256", "kid": "rsa-1", "crit": []string{"exp"}})); err == nil {
		t.Fatal("tokens with crit extensions must be rejected")
	}
}

func TestStrictBase64RejectsNonCanonicalSignature(t *testing.T) {
	idp := newIdP(t)
	now := time.Now()
	v := newVerifier(idp, now)
	tok := signRS256(t, idp.rsaKey, "rsa-1", good(now))
	// 256-byte RSA signatures encode to 342 chars; the last char carries 4 unused bits.
	last := tok[len(tok)-1]
	alt := byte('A')
	if last == 'A' {
		alt = 'B'
	}
	if _, err := v.Verify(tok[:len(tok)-1] + string(alt)); err == nil {
		t.Fatal("non-canonical base64 must be rejected")
	}
}
