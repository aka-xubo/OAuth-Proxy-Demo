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

	"example.com/mcp-oauth-memory-go/internal/mcpserver"
)

const (
	mcpServerAddr       = "127.0.0.1:8080"
	mcpResourceURL      = "http://127.0.0.1:8080/mcp"
	authorizationIssuer = "http://127.0.0.1:8082"
	introspectionSecret = "local-dev-introspection-secret"
)

func main() {
	addr := mcpServerAddr
	baseURL := "http://" + addr
	resource := mcpResourceURL
	authIssuer := authorizationIssuer
	secret := introspectionSecret
	metadataURL := baseURL + "/.well-known/oauth-protected-resource/mcp"

	mcpHandler, err := mcpserver.New(mcpserver.Config{
		Resource:            resource,
		ResourceMetadataURL: metadataURL,
		IntrospectionURL:    authIssuer + "/oauth/introspect",
		IntrospectionSecret: secret,
	})
	if err != nil {
		slog.Error("create MCP server", "error", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.Handle("/mcp", mcpHandler)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"resource":                 resource,
			"authorization_servers":    []string{authIssuer},
			"bearer_methods_supported": []string{"header"},
			"scopes_supported":         []string{"openid", "profile", "email", "offline_access", "mcp:tools"},
		})
	})
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"name":                        "memory-mcp-server",
			"mcp":                         resource,
			"authorization_server":        authIssuer,
			"protected_resource_metadata": metadataURL,
		})
	})

	serve("MCP server", addr, mux)
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
