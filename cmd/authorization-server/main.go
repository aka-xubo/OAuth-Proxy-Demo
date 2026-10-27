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

	"example.com/mcp-oauth-memory-go/internal/oauthserver"
)

const (
	authorizationServerAddr = "127.0.0.1:8081"
	authorizationServerURL  = "http://127.0.0.1:8081"
	mcpResourceURL          = "http://127.0.0.1:8080/mcp"
	introspectionSecret     = "local-dev-introspection-secret"
	proxyClientID           = "memory-oauth-proxy"
	proxyCallbackURL        = "http://127.0.0.1:8082/oauth/callback/upstream"
)

func main() {
	addr := authorizationServerAddr
	issuer := authorizationServerURL
	resource := mcpResourceURL
	secret := introspectionSecret

	oauth, err := oauthserver.New(oauthserver.Config{
		Issuer:              issuer,
		Resource:            resource,
		IntrospectionSecret: secret,
		Accounts: []oauthserver.Account{
			{TenantID: "acme", Username: "demo", Password: "demo"},
			{TenantID: "globex", Username: "demo", Password: "demo"},
			{TenantID: "globex", Username: "ops", Password: "ops"},
		},
		StaticClients: []oauthserver.StaticClient{{
			ID: proxyClientID, Name: "Local OAuth Proxy",
			RedirectURIs: []string{proxyCallbackURL},
			Scopes:       []string{"openid", "profile", "email", "offline_access", "mcp:tools"},
		}},
		AccessTokenTTL:  time.Hour,
		RefreshTokenTTL: 24 * time.Hour,
		CodeTTL:         2 * time.Minute,
		TransactionTTL:  10 * time.Minute,
	})
	if err != nil {
		slog.Error("create authorization server", "error", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	oauth.RegisterRoutes(mux)
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"name":                   "memory-oauth-authorization-server",
			"issuer":                 issuer,
			"mcp_resource":           resource,
			"introspection":          issuer + "/oauth/introspect",
			"userinfo":               issuer + "/userinfo",
			"authorization_metadata": issuer + "/.well-known/oauth-authorization-server",
		})
	})

	serve("authorization server", addr, mux)
}

func serve(name, addr string, handler http.Handler) {
	server := &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 2 * time.Minute}
	go func() {
		slog.Info(name+" started", "listen", "http://"+addr)
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
