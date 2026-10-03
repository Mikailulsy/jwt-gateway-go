package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// jwk is the subset of RFC 7517 fields this gateway understands.
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type jwks struct {
	Keys []jwk `json:"keys"`
}

// KeySet fetches and caches signing keys from a JWKS endpoint.
//
// Unknown key ids trigger at most one refresh per minRefresh, so a flood of
// tokens with random kids cannot turn the gateway into a DoS amplifier
// against the identity provider.
type KeySet struct {
	url        string
	client     *http.Client
	ttl        time.Duration
	minRefresh time.Duration
	now        func() time.Time

	// maxStale bounds how long known keys keep being served while the IdP
	// is unreachable. Past it, verification fails closed.
	maxStale time.Duration

	refreshMu sync.Mutex // serializes fetches; never held by readers
	mu        sync.RWMutex
	keys      map[string]any // kid -> *rsa.PublicKey | *ecdsa.PublicKey
	fetchedAt time.Time
	lastTry   time.Time
}

func NewKeySet(url string, ttl, minRefresh time.Duration) *KeySet {
	return &KeySet{
		url:        url,
		client:     &http.Client{Timeout: 5 * time.Second},
		ttl:        ttl,
		minRefresh: minRefresh,
		maxStale:   24 * time.Hour,
		now:        time.Now,
		keys:       map[string]any{},
	}
}

var ErrUnknownKey = errors.New("unknown signing key")

// Key returns the public key for kid, refreshing the cache when it is stale
// or when the kid is unknown (key rotation).
func (k *KeySet) Key(kid string) (any, error) {
	k.mu.RLock()
	key, ok := k.keys[kid]
	fresh := k.now().Sub(k.fetchedAt) < k.ttl
	k.mu.RUnlock()
	if ok && fresh {
		return key, nil
	}

	if err := k.refresh(); err != nil {
		// Serve a known key through a temporary IdP outage rather than
		// failing every request; an unknown key still fails closed.
		k.mu.RLock()
		usable := ok && k.now().Sub(k.fetchedAt) < k.ttl+k.maxStale
		k.mu.RUnlock()
		if usable {
			return key, nil
		}
		return nil, err
	}

	k.mu.RLock()
	defer k.mu.RUnlock()
	if key, ok := k.keys[kid]; ok {
		return key, nil
	}
	return nil, ErrUnknownKey
}

func (k *KeySet) refresh() error {
	// Only one goroutine fetches at a time; the others wait here, but
	// requests served from a fresh cache never touch this mutex, and the
	// data lock is never held across the network call.
	k.refreshMu.Lock()
	defer k.refreshMu.Unlock()

	k.mu.Lock()
	if k.now().Sub(k.lastTry) < k.minRefresh {
		k.mu.Unlock()
		return nil // refreshed very recently (possibly by the caller we waited on)
	}
	k.lastTry = k.now()
	k.mu.Unlock()

	resp, err := k.client.Get(k.url)
	if err != nil {
		return fmt.Errorf("fetch jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch jwks: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read jwks: %w", err)
	}
	var set jwks
	if err := json.Unmarshal(body, &set); err != nil {
		return fmt.Errorf("decode jwks: %w", err)
	}

	next := make(map[string]any, len(set.Keys))
	for _, j := range set.Keys {
		if j.Use != "" && j.Use != "sig" {
			continue
		}
		pub, err := j.publicKey()
		if err != nil || j.Kid == "" {
			continue // skip keys we cannot use instead of rejecting the set
		}
		next[j.Kid] = pub
	}
	if len(next) == 0 {
		return errors.New("jwks contains no usable signing keys")
	}
	k.mu.Lock()
	k.keys = next
	k.fetchedAt = k.now()
	k.mu.Unlock()
	return nil
}

func (j jwk) publicKey() (any, error) {
	switch j.Kty {
	case "RSA":
		n, err := b64BigInt(j.N)
		if err != nil {
			return nil, err
		}
		e, err := b64BigInt(j.E)
		if err != nil {
			return nil, err
		}
		if !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31-1 {
			return nil, errors.New("bad rsa exponent")
		}
		if n.BitLen() < 2048 {
			return nil, errors.New("rsa key too small")
		}
		return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
	case "EC":
		if j.Crv != "P-256" {
			return nil, errors.New("unsupported curve")
		}
		x, err := b64BigInt(j.X)
		if err != nil {
			return nil, err
		}
		y, err := b64BigInt(j.Y)
		if err != nil {
			return nil, err
		}
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
		if !pub.Curve.IsOnCurve(x, y) {
			return nil, errors.New("point not on curve")
		}
		return pub, nil
	}
	return nil, errors.New("unsupported key type")
}

func b64BigInt(s string) (*big.Int, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}
