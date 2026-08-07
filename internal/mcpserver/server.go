package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	mcpauth "github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type Config struct {
	Resource            string
	ResourceMetadataURL string
	IntrospectionURL    string
	IntrospectionSecret string
}

type counterStore struct {
	mu     sync.Mutex
	values map[string]int
}

type whoAmIOutput struct {
	UserID   string   `json:"user_id" jsonschema:"authenticated resource owner"`
	ClientID string   `json:"client_id" jsonschema:"OAuth client that requested the token"`
	Scopes   []string `json:"scopes" jsonschema:"granted OAuth scopes"`
}

type echoInput struct {
	Message string `json:"message" jsonschema:"message to echo"`
}

type echoOutput struct {
	Message string `json:"message"`
	UserID  string `json:"user_id"`
}

type counterInput struct {
	Delta int `json:"delta" jsonschema:"amount added to this user's in-memory counter"`
}

type counterOutput struct {
	Value  int    `json:"value"`
	UserID string `json:"user_id"`
}

func New(cfg Config) (http.Handler, error) {
	if cfg.Resource == "" || cfg.ResourceMetadataURL == "" || cfg.IntrospectionURL == "" || cfg.IntrospectionSecret == "" {
		return nil, errors.New("resource, resource metadata URL, introspection URL, and introspection secret are required")
	}
	if _, err := url.ParseRequestURI(cfg.IntrospectionURL); err != nil {
		return nil, fmt.Errorf("invalid introspection URL: %w", err)
	}
	server := mcp.NewServer(
		&mcp.Implementation{
			Name:        "memory-oauth-demo",
			Version:     "1.0.0",
			Description: "OAuth-protected in-memory MCP server for learning DCR and PKCE",
		},
		&mcp.ServerOptions{
			Instructions: "Use whoami to inspect the authenticated identity. echo is read-only. add_to_counter changes only an in-memory per-user counter.",
		},
	)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "whoami",
		Description: "Return the user, OAuth client, and scopes carried by the current access token.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, whoAmIOutput, error) {
		info, err := identityFromContext(ctx)
		if err != nil {
			return nil, whoAmIOutput{}, err
		}
		clientID, _ := info.Extra["client_id"].(string)
		return nil, whoAmIOutput{
			UserID:   info.UserID,
			ClientID: clientID,
			Scopes:   slices.Clone(info.Scopes),
		}, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "echo",
		Description: "Echo a message and include the authenticated user id.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input echoInput) (*mcp.CallToolResult, echoOutput, error) {
		info, err := identityFromContext(ctx)
		if err != nil {
			return nil, echoOutput{}, err
		}
		return nil, echoOutput{Message: input.Message, UserID: info.UserID}, nil
	})

	counters := &counterStore{values: make(map[string]int)}
	mcp.AddTool(server, &mcp.Tool{
		Name:        "add_to_counter",
		Description: "Add delta to an in-memory counter isolated by authenticated user.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input counterInput) (*mcp.CallToolResult, counterOutput, error) {
		info, err := identityFromContext(ctx)
		if err != nil {
			return nil, counterOutput{}, err
		}
		counters.mu.Lock()
		counters.values[info.UserID] += input.Delta
		value := counters.values[info.UserID]
		counters.mu.Unlock()
		return nil, counterOutput{Value: value, UserID: info.UserID}, nil
	})

	streamable := mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return server },
		&mcp.StreamableHTTPOptions{
			JSONResponse: true,
			Stateless:    true,
		},
	)
	verifier := &remoteTokenVerifier{cfg: cfg, client: &http.Client{Timeout: 5 * time.Second}}
	protect := mcpauth.RequireBearerToken(verifier.Verify, &mcpauth.RequireBearerTokenOptions{
		ResourceMetadataURL: cfg.ResourceMetadataURL,
		Scopes:              []string{"mcp:tools"},
	})
	return protect(streamable), nil
}

type remoteTokenVerifier struct {
	cfg    Config
	client *http.Client
}

type introspectionResponse struct {
	Active   bool   `json:"active"`
	ClientID string `json:"client_id"`
	Resource string `json:"resource"`
	Scope    string `json:"scope"`
	UserID   string `json:"user_id"`
	Exp      int64  `json:"exp"`
}

func (v *remoteTokenVerifier) Verify(ctx context.Context, token string, _ *http.Request) (*mcpauth.TokenInfo, error) {
	form := url.Values{"token": {token}, "resource": {v.cfg.Resource}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.cfg.IntrospectionURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create introspection request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+v.cfg.IntrospectionSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := v.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("introspection request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, mcpauth.ErrInvalidToken
	}
	var result introspectionResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode introspection response: %w", err)
	}
	if !result.Active || result.UserID == "" || result.Resource != v.cfg.Resource || result.Exp <= 0 {
		return nil, mcpauth.ErrInvalidToken
	}
	return &mcpauth.TokenInfo{
		Scopes:     strings.Fields(result.Scope),
		Expiration: time.Unix(result.Exp, 0),
		UserID:     result.UserID,
		Extra: map[string]any{
			"client_id": result.ClientID,
			"resource":  result.Resource,
		},
	}, nil
}

func identityFromContext(ctx context.Context) (*mcpauth.TokenInfo, error) {
	info := mcpauth.TokenInfoFromContext(ctx)
	if info == nil || info.UserID == "" {
		return nil, errors.New("authenticated identity missing from request context")
	}
	return info, nil
}
