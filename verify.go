package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// Claims holds the registered claims the gateway cares about.
type Claims struct {
	Subject   string   `json:"sub"`
	Issuer    string   `json:"iss"`
	Audience  Audience `json:"aud"`
	ExpiresAt int64    `json:"exp"`
	NotBefore int64    `json:"nbf"`
	IssuedAt  int64    `json:"iat"`
	Role      string   `json:"role"`
}

// Audience accepts both the string and array forms allowed by RFC 7519.
type Audience []string

func (a *Audience) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*a = Audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*a = many
	return nil
}

func (a Audience) contains(want string) bool {
	for _, v := range a {
		if v == want {
			return true
		}
	}
	return false
}

// Verifier validates access tokens. Only algorithms in allowed are accepted;
// the header's alg is never used to pick a verification strategy for a key of
// a different type, which closes the classic RS256-to-HS256 confusion attack.
type Verifier struct {
	Keys     *KeySet
	Issuer   string
	Audience string
	Leeway   time.Duration
	Now      func() time.Time
	// RequiredTyp, when set (for example "at+jwt" per RFC 9068), rejects
	// tokens whose typ header differs, so an ID token for the same audience
	// cannot be replayed as an access token.
	RequiredTyp string
}

var (
	ErrMalformed = errors.New("malformed token")
	ErrAlg       = errors.New("unsupported algorithm")
	ErrSignature = errors.New("invalid signature")
	ErrExpired   = errors.New("token expired")
	ErrNotYet    = errors.New("token not yet valid")
	ErrIssuer    = errors.New("unexpected issuer")
	ErrAudience  = errors.New("unexpected audience")
)

type header struct {
	Alg  string   `json:"alg"`
	Kid  string   `json:"kid"`
	Typ  string   `json:"typ"`
	Crit []string `json:"crit"`
}

func (v *Verifier) Verify(token string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrMalformed
	}
	var h header
	if err := decodeSegment(parts[0], &h); err != nil {
		return nil, ErrMalformed
	}
	if h.Alg != "RS256" && h.Alg != "ES256" {
		return nil, ErrAlg // rejects "none", HS*, and everything else
	}
	if h.Kid == "" || len(h.Crit) > 0 { // we understand no critical extensions
		return nil, ErrMalformed
	}
	if v.RequiredTyp != "" && !strings.EqualFold(h.Typ, v.RequiredTyp) {
		return nil, ErrMalformed
	}

	key, err := v.Keys.Key(h.Kid)
	if err != nil {
		return nil, fmt.Errorf("key lookup: %w", err)
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil {
		return nil, ErrMalformed
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))

	switch pub := key.(type) {
	case *rsa.PublicKey:
		if h.Alg != "RS256" {
			return nil, ErrAlg
		}
		if rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig) != nil {
			return nil, ErrSignature
		}
	case *ecdsa.PublicKey:
		if h.Alg != "ES256" || len(sig) != 64 {
			return nil, ErrAlg
		}
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(pub, digest[:], r, s) {
			return nil, ErrSignature
		}
	default:
		return nil, ErrAlg
	}

	var c Claims
	if err := decodeSegment(parts[1], &c); err != nil {
		return nil, ErrMalformed
	}
	now := v.Now().Unix()
	leeway := int64(v.Leeway.Seconds())
	if c.ExpiresAt == 0 || now > c.ExpiresAt+leeway {
		return nil, ErrExpired // a token without exp is never accepted
	}
	if c.NotBefore != 0 && now+leeway < c.NotBefore {
		return nil, ErrNotYet
	}
	if c.Issuer != v.Issuer {
		return nil, ErrIssuer
	}
	if !c.Audience.contains(v.Audience) {
		return nil, ErrAudience
	}
	if c.Subject == "" {
		return nil, ErrMalformed
	}
	return &c, nil
}

func decodeSegment(seg string, out any) error {
	b, err := base64.RawURLEncoding.Strict().DecodeString(seg)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}
