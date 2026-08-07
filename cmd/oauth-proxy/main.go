package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"example.com/mcp-oauth-memory-go/internal/oauthproxy"
)

const (
	proxyAddr            = "127.0.0.1:8082"
	proxyIssuer          = "http://127.0.0.1:8082"
	mcpResourceURL       = "http://127.0.0.1:8080/mcp"
	upstreamAuthorizeURL = "http://127.0.0.1:8081/oauth/authorize"
	upstreamTokenURL     = "http://127.0.0.1:8081/oauth/token"
	upstreamClientID     = "memory-oauth-proxy"
	upstreamClientSecret = ""
	upstreamRedirectURI  = "http://127.0.0.1:8082/oauth/callback/upstream"
	introspectionSecret  = "local-dev-introspection-secret"
)

func main() {
	addr := proxyAddr
	issuer := proxyIssuer
	resource := mcpResourceURL

	cfg := oauthproxy.Config{
		Issuer:               issuer,
		Resource:             resource,
		UpstreamAuthorizeURL: upstreamAuthorizeURL,
		UpstreamTokenURL:     upstreamTokenURL,
		UpstreamClientID:     upstreamClientID,
		UpstreamClientSecret: upstreamClientSecret,
		UpstreamRedirectURI:  upstreamRedirectURI,
		IntrospectionSecret:  introspectionSecret,
		UpstreamPKCE:         true,
		SendResource:         true,
	}
	proxy, err := oauthproxy.New(cfg)
	if err != nil {
		slog.Error("create OAuth proxy", "error", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	proxy.RegisterRoutes(mux)
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"name":               "oauth-proxy",
			"issuer":             issuer,
			"mcp_resource":       resource,
			"upstream_authorize": cfg.UpstreamAuthorizeURL,
			"upstream_token":     cfg.UpstreamTokenURL,
			"introspection":      issuer + "/oauth/introspect",
			"upstream_callback":  cfg.UpstreamRedirectURI,
		})
	})

	serve(addr, mux)
}

func serve(addr string, handler http.Handler) {
	server := &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 2 * time.Minute}
	go func() {
		slog.Info("OAuth proxy started", "listen", "http://"+addr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("serve", "error", err)
			os.Exit(1)
		}
	}()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdownCtx)
}
