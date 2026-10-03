package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
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

// NewProxy forwards authenticated requests upstream.
//
// It uses Rewrite (not Director) so the verified identity headers are set
// after Go's hop-by-hop cleanup; with Director a client could send
// "Connection: X-User-Id" and make the proxy delete the trusted header.
// Every client-supplied identity-looking header is dropped, including
// underscore variants that CGI-style upstreams fold into the same name, and
// X-Forwarded-* values are replaced rather than appended to.
func NewProxy(upstream *url.URL) http.Handler {
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(upstream)
			pr.SetXForwarded()
			stripIdentityHeaders(pr.Out.Header)
			pr.Out.Header.Del("Authorization")
			pr.Out.Header.Del("Forwarded")
			if claims, ok := ClaimsFrom(pr.In.Context()); ok {
				pr.Out.Header.Set("X-User-Id", claims.Subject)
				if claims.Role != "" {
					pr.Out.Header.Set("X-User-Role", claims.Role)
				}
			}
		},
	}
}

func stripIdentityHeaders(h http.Header) {
	for name := range h {
		n := strings.ToLower(strings.ReplaceAll(name, "_", "-"))
		if strings.HasPrefix(n, "x-user") || strings.HasPrefix(n, "x-auth") || strings.HasPrefix(n, "x-forwarded-user") {
			delete(h, name)
		}
	}
}

// RateLimit is a per-key token bucket, enough to blunt credential stuffing
// and runaway clients without an external dependency.
//
// Idle buckets (fully refilled) are evicted when the table reaches maxKeys.
// If it is still full, new keys are denied instead of resetting everyone's
// state, so key churn cannot be used to wipe other clients' limits.
type RateLimit struct {
	rate    float64 // tokens per second
	burst   float64
	maxKeys int
	now     func() time.Time

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func NewRateLimit(rate float64, burst int) *RateLimit {
	return &RateLimit{rate: rate, burst: float64(burst), maxKeys: 100_000, now: time.Now, buckets: map[string]*bucket{}}
}

func (l *RateLimit) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= l.maxKeys {
			l.evictIdle(now)
			if len(l.buckets) >= l.maxKeys {
				return false
			}
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

func (l *RateLimit) evictIdle(now time.Time) {
	for k, b := range l.buckets {
		if b.tokens+now.Sub(b.last).Seconds()*l.rate >= l.burst {
			delete(l.buckets, k)
		}
	}
}

// clientKey identifies a client by peer address. IPv6 peers are grouped by
// /64 because a single host usually controls the whole prefix.
func clientKey(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return host
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String()
}

func (l *RateLimit) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !l.Allow(clientKey(r.RemoteAddr)) {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}
