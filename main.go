// Command jwt-gateway is a small authenticating reverse proxy: it verifies
// RS256/ES256 access tokens against a JWKS endpoint, then forwards the request
// upstream with trusted identity headers.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	jwksURL := mustEnv(log, "JWKS_URL")
	issuer := mustEnv(log, "TOKEN_ISSUER")
	audience := mustEnv(log, "TOKEN_AUDIENCE")
	upstream, err := url.Parse(mustEnv(log, "UPSTREAM_URL"))
	if err != nil {
		log.Error("bad UPSTREAM_URL", "err", err)
		os.Exit(1)
	}

	verifier := &Verifier{
		Keys:     NewKeySet(jwksURL, 10*time.Minute, 30*time.Second),
		Issuer:   issuer,
		Audience: audience,
		Leeway:   30 * time.Second,
		Now:      time.Now,
		// Optional: set TOKEN_TYP=at+jwt to require RFC 9068 access tokens.
		RequiredTyp: os.Getenv("TOKEN_TYP"),
	}
	limiter := NewRateLimit(50, 100)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.Handle("/", limiter.Middleware(Authenticate(verifier, log, NewProxy(upstream))))

	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()

	log.Info("listening", "addr", addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("server failed", "err", err)
		os.Exit(1)
	}
}

func mustEnv(log *slog.Logger, name string) string {
	v := os.Getenv(name)
	if v == "" {
		log.Error("missing required environment variable", "name", name)
		os.Exit(1)
	}
	return v
}
