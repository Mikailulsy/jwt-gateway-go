package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"
)

type ctxKey struct{}

// ClaimsFrom returns the verified claims stored by Authenticate.
func ClaimsFrom(ctx context.Context) (*Claims, bool) {
	c, ok := ctx.Value(ctxKey{}).(*Claims)
	return c, ok
}

// Authenticate rejects requests without a valid bearer token. Failures never
// reveal why verification failed to the caller; the reason is logged instead.
func Authenticate(v *Verifier, log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearer(r.Header.Get("Authorization"))
		if !ok {
			deny(w, "invalid_request")
			return
		}
		claims, err := v.Verify(token)
		if err != nil {
			level := slog.LevelInfo
			if errors.Is(err, ErrSignature) || errors.Is(err, ErrAlg) {
				level = slog.LevelWarn // possible tampering, worth alerting on
			}
			log.Log(r.Context(), level, "auth rejected", "reason", err.Error(), "remote", r.RemoteAddr)
			deny(w, "invalid_token")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, claims)))
	})
}

func bearer(h string) (string, bool) {
	scheme, token, found := strings.Cut(h, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || token == "" || strings.ContainsAny(token, " \t") {
		return "", false
	}
	return token, true
}

func deny(w http.ResponseWriter, code string) {
	w.Header().Set("WWW-Authenticate", `Bearer error="`+code+`"`)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

// NewProxy forwards authenticated requests upstream. Identity headers set by
// the client are always stripped and replaced with the verified values, so
// upstream services can trust X-User-Id and X-User-Role.
func NewProxy(upstream *url.URL) http.Handler {
	p := httputil.NewSingleHostReverseProxy(upstream)
	base := p.Director
	p.Director = func(r *http.Request) {
		claims, _ := ClaimsFrom(r.Context())
		r.Header.Del("X-User-Id")
		r.Header.Del("X-User-Role")
		r.Header.Del("Authorization")
		base(r)
		if claims != nil {
			r.Header.Set("X-User-Id", claims.Subject)
			if claims.Role != "" {
				r.Header.Set("X-User-Role", claims.Role)
			}
		}
	}
	return p
}

// RateLimit is a per-key token bucket, enough to blunt credential stuffing
// and runaway clients without an external dependency.
type RateLimit struct {
	rate  float64 // tokens per second
	burst float64
	now   func() time.Time

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func NewRateLimit(rate float64, burst int) *RateLimit {
	return &RateLimit{rate: rate, burst: float64(burst), now: time.Now, buckets: map[string]*bucket{}}
}

func (l *RateLimit) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) > 100_000 { // bound memory against key churn
			l.buckets = map[string]*bucket{}
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (l *RateLimit) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.RemoteAddr
		if i := strings.LastIndex(key, ":"); i > 0 {
			key = key[:i]
		}
		if !l.Allow(key) {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}
