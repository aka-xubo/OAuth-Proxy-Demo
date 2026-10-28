package oauthserver

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	mcpauth "github.com/modelcontextprotocol/go-sdk/auth"
	"golang.org/x/crypto/bcrypt"
)

var supportedScopes = []string{"openid", "profile", "email", "offline_access", "mcp:tools"}

const genericLoginError = "登录信息不正确"

type Account struct {
	TenantID string
	Username string
	Password string
}

type Config struct {
	Issuer              string
	Resource            string
	IntrospectionSecret string
	Accounts            []Account
	// DatabasePath selects the local account database; empty uses DefaultDatabasePath.
	DatabasePath    string
	StaticClients   []StaticClient
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	CodeTTL         time.Duration
	TransactionTTL  time.Duration
}

// StaticClient 是服务启动时预置的 OAuth 客户端，适合代理等不支持 DCR 的调用方。
type StaticClient struct {
	ID                      string
	Name                    string
	RedirectURIs            []string
	Scopes                  []string
	GrantTypes              []string
	ResponseTypes           []string
	TokenEndpointAuthMethod string
}

type Server struct {
	cfg Config
	now func() time.Time
	rng io.Reader

	mu            sync.Mutex
	accountStore  *accountStore
	clients       map[string]*client
	transactions  map[string]*authorizationTransaction
	codes         map[string]*authorizationCode
	accessTokens  map[string]*accessToken
	refreshTokens map[string]*refreshToken
}

type client struct {
	ID                      string
	Name                    string
	RedirectURIs            []string
	Scopes                  []string
	GrantTypes              []string
	ResponseTypes           []string
	TokenEndpointAuthMethod string
	IssuedAt                time.Time
}

type authorizationTransaction struct {
	ID            string
	CSRF          string
	ClientID      string
	RedirectURI   string
	Scope         []string
	State         string
	Resource      string
	CodeChallenge string
	UserID        string
	TenantID      string
	ExpiresAt     time.Time
}

type authorizationCode struct {
	ClientID      string
	RedirectURI   string
	Scope         []string
	Resource      string
	CodeChallenge string
	UserID        string
	TenantID      string
	ExpiresAt     time.Time
}

type accessToken struct {
	ClientID  string
	Scope     []string
	Resource  string
	UserID    string
	TenantID  string
	ExpiresAt time.Time
}

type refreshToken struct {
	ClientID  string
	Scope     []string
	Resource  string
	UserID    string
	TenantID  string
	ExpiresAt time.Time
}

type registrationRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Scope                   string   `json:"scope"`
}

type registrationResponse struct {
	ClientID                string   `json:"client_id"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name,omitempty"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Scope                   string   `json:"scope"`
}

type pageData struct {
	TransactionID string
	CSRF          string
	ClientName    string
	Scopes        []string
	Tenants       []string
	Error         string
}

var loginTemplate = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>登录内存 OAuth Server</title>
<style>body{font-family:system-ui,sans-serif;max-width:520px;margin:64px auto;padding:0 20px;color:#18201c}main{border:1px solid #aeb6b0;padding:28px}label{display:block;margin:14px 0 5px}input,select{box-sizing:border-box;width:100%;padding:10px}button{margin-top:20px;padding:10px 16px}.error{color:#a22}code{background:#eef0ed;padding:2px 5px}</style></head>
<body><main><h1>登录并授权</h1><p>客户端 <strong>{{.ClientName}}</strong> 请求访问内存 MCP Server。</p>{{if .Error}}<p class="error">{{.Error}}</p>{{end}}
<form method="post" action="/oauth/login"><input type="hidden" name="transaction_id" value="{{.TransactionID}}"><input type="hidden" name="csrf" value="{{.CSRF}}">
<label for="tenant">租户</label><select id="tenant" name="tenant" required>{{range .Tenants}}<option value="{{.}}"{{if eq . "acme"}} selected{{end}}>{{.}}</option>{{end}}</select>
<label for="username">用户名</label><input id="username" name="username" autocomplete="username" required value="demo">
<label for="password">密码</label><input id="password" name="password" type="password" autocomplete="current-password" required value="demo">
<button type="submit">登录</button></form><p>默认教学账号：租户 <code>acme</code>，用户名 <code>demo</code>，密码 <code>demo</code></p></main></body></html>`))

var consentTemplate = template.Must(template.New("consent").Parse(`<!doctype html>
<html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>授权确认</title>
<style>body{font-family:system-ui,sans-serif;max-width:520px;margin:64px auto;padding:0 20px;color:#18201c}main{border:1px solid #aeb6b0;padding:28px}li{margin:8px 0}.actions{display:flex;gap:10px;margin-top:24px}button{padding:10px 16px}.deny{background:white;border:1px solid #999}</style></head>
<body><main><h1>确认授权范围</h1><p><strong>{{.ClientName}}</strong> 将获得以下权限：</p><ul>{{range .Scopes}}<li><code>{{.}}</code></li>{{end}}</ul>
<form method="post" action="/oauth/consent"><input type="hidden" name="transaction_id" value="{{.TransactionID}}"><input type="hidden" name="csrf" value="{{.CSRF}}">
<div class="actions"><button type="submit" name="decision" value="approve">允许</button><button class="deny" type="submit" name="decision" value="deny">拒绝</button></div></form></main></body></html>`))

func New(cfg Config) (*Server, error) {
	if cfg.Issuer == "" || cfg.Resource == "" {
		return nil, errors.New("issuer and resource are required")
	}
	issuer, err := url.Parse(cfg.Issuer)
	if err != nil || issuer.Scheme == "" || issuer.Host == "" {
		return nil, fmt.Errorf("invalid issuer %q", cfg.Issuer)
	}
	resource, err := url.Parse(cfg.Resource)
	if err != nil || resource.Scheme == "" || resource.Host == "" {
		return nil, fmt.Errorf("invalid resource %q", cfg.Resource)
	}
	cfg.Issuer = strings.TrimRight(cfg.Issuer, "/")
	bootstrap := cfg.Accounts
	cfg.Accounts = nil
	if cfg.DatabasePath == "" {
		cfg.DatabasePath = DefaultDatabasePath
	}
	if cfg.AccessTokenTTL == 0 {
		cfg.AccessTokenTTL = time.Hour
	}
	if cfg.RefreshTokenTTL == 0 {
		cfg.RefreshTokenTTL = 24 * time.Hour
	}
	if cfg.CodeTTL == 0 {
		cfg.CodeTTL = 2 * time.Minute
	}
	if cfg.TransactionTTL == 0 {
		cfg.TransactionTTL = 10 * time.Minute
	}
	server := &Server{
		cfg:           cfg,
		now:           time.Now,
		rng:           rand.Reader,
		clients:       make(map[string]*client),
		transactions:  make(map[string]*authorizationTransaction),
		codes:         make(map[string]*authorizationCode),
		accessTokens:  make(map[string]*accessToken),
		refreshTokens: make(map[string]*refreshToken),
	}
	for _, static := range cfg.StaticClients {
		if static.ID == "" || len(static.RedirectURIs) == 0 {
			return nil, errors.New("static client must have an id and redirect URI")
		}
		scopes := slices.Clone(static.Scopes)
		if len(scopes) == 0 {
			scopes = slices.Clone(supportedScopes)
		}
		grantTypes := slices.Clone(static.GrantTypes)
		if len(grantTypes) == 0 {
			grantTypes = []string{"authorization_code", "refresh_token"}
		}
		responseTypes := slices.Clone(static.ResponseTypes)
		if len(responseTypes) == 0 {
			responseTypes = []string{"code"}
		}
		authMethod := static.TokenEndpointAuthMethod
		if authMethod == "" {
			authMethod = "none"
		}
		server.clients[static.ID] = &client{
			ID: static.ID, Name: static.Name, RedirectURIs: slices.Clone(static.RedirectURIs),
			Scopes: scopes, GrantTypes: grantTypes, ResponseTypes: responseTypes,
			TokenEndpointAuthMethod: authMethod, IssuedAt: time.Now(),
		}
		if server.clients[static.ID].Name == "" {
			server.clients[static.ID].Name = "Static OAuth Client"
		}
	}
	server.accountStore, err = openAccountStore(context.Background(), cfg.DatabasePath, bootstrap)
	if err != nil {
		return nil, err
	}
	return server, nil
}

// Close releases the account database after HTTP requests have finished.
func (s *Server) Close() error {
	return s.accountStore.db.Close()
}

func (s *Server) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.handleAuthorizationServerMetadata)
	mux.HandleFunc("POST /oauth/register", s.handleRegister)
	mux.HandleFunc("GET /oauth/authorize", s.handleAuthorize)
	mux.HandleFunc("POST /oauth/login", s.handleLogin)
	mux.HandleFunc("POST /oauth/consent", s.handleConsent)
	mux.HandleFunc("POST /oauth/token", s.handleToken)
	mux.HandleFunc("POST /oauth/introspect", s.handleIntrospection)
	mux.HandleFunc("GET /userinfo", s.handleUserinfo)
}

func (s *Server) ResourceMetadataURL() string {
	return s.cfg.Issuer + "/.well-known/oauth-protected-resource/mcp"
}

func (s *Server) Resource() string {
	return s.cfg.Resource
}

func (s *Server) handleAuthorizationServerMetadata(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                s.cfg.Issuer,
		"authorization_endpoint":                s.cfg.Issuer + "/oauth/authorize",
		"token_endpoint":                        s.cfg.Issuer + "/oauth/token",
		"registration_endpoint":                 s.cfg.Issuer + "/oauth/register",
		"response_types_supported":              []string{"code"},
		"response_modes_supported":              []string{"query"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"code_challenge_methods_supported":      []string{"S256"},
		"scopes_supported":                      supportedScopes,
	})
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	defer r.Body.Close()
	var req registrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "invalid JSON registration document")
		return
	}
	if len(req.RedirectURIs) == 0 {
		writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uris is required")
		return
	}
	redirectURIs := make([]string, 0, len(req.RedirectURIs))
	for _, raw := range req.RedirectURIs {
		canonical, err := validateRedirectURI(raw)
		if err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", err.Error())
			return
		}
		if !slices.Contains(redirectURIs, canonical) {
			redirectURIs = append(redirectURIs, canonical)
		}
	}
	grantTypes := req.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = []string{"authorization_code"}
	}
	if !onlyAllowed(grantTypes, "authorization_code", "refresh_token") || !slices.Contains(grantTypes, "authorization_code") {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "only authorization_code and refresh_token grants are supported")
		return
	}
	responseTypes := req.ResponseTypes
	if len(responseTypes) == 0 {
		responseTypes = []string{"code"}
	}
	if len(responseTypes) != 1 || responseTypes[0] != "code" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "only code response type is supported")
		return
	}
	authMethod := req.TokenEndpointAuthMethod
	if authMethod == "" {
		authMethod = "none"
	}
	if authMethod != "none" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "only public clients using token_endpoint_auth_method=none are supported")
		return
	}
	scopes, err := normalizeScopes(req.Scope)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", err.Error())
		return
	}
	if len(scopes) == 0 {
		scopes = slices.Clone(supportedScopes)
	}
	clientID, err := s.randomValue("client", 24)
	if err != nil {
		http.Error(w, "failed to generate client id", http.StatusInternalServerError)
		return
	}
	now := s.now()
	c := &client{
		ID:                      clientID,
		Name:                    strings.TrimSpace(req.ClientName),
		RedirectURIs:            redirectURIs,
		Scopes:                  scopes,
		GrantTypes:              slices.Clone(grantTypes),
		ResponseTypes:           slices.Clone(responseTypes),
		TokenEndpointAuthMethod: authMethod,
		IssuedAt:                now,
	}
	if c.Name == "" {
		c.Name = "Dynamic MCP Client"
	}
	s.mu.Lock()
	s.clients[c.ID] = c
	s.mu.Unlock()
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, registrationResponse{
		ClientID:                c.ID,
		ClientIDIssuedAt:        now.Unix(),
		RedirectURIs:            c.RedirectURIs,
		ClientName:              c.Name,
		GrantTypes:              c.GrantTypes,
		ResponseTypes:           c.ResponseTypes,
		TokenEndpointAuthMethod: c.TokenEndpointAuthMethod,
		Scope:                   strings.Join(c.Scopes, " "),
	})
}

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	s.mu.Lock()
	c, ok := s.clients[clientID]
	s.mu.Unlock()
	if !ok {
		http.Error(w, "invalid client_id", http.StatusBadRequest)
		return
	}
	redirectURI, err := validateRedirectURI(q.Get("redirect_uri"))
	if err != nil || !slices.Contains(c.RedirectURIs, redirectURI) {
		http.Error(w, "redirect_uri is not registered for this client", http.StatusBadRequest)
		return
	}
	if q.Get("response_type") != "code" {
		redirectAuthorizationError(w, r, redirectURI, q.Get("state"), "unsupported_response_type", "only response_type=code is supported")
		return
	}
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		redirectAuthorizationError(w, r, redirectURI, q.Get("state"), "invalid_request", "PKCE S256 is required")
		return
	}
	if q.Get("resource") != s.cfg.Resource {
		redirectAuthorizationError(w, r, redirectURI, q.Get("state"), "invalid_target", "resource must match the MCP resource")
		return
	}
	scopes, err := normalizeScopes(q.Get("scope"))
	if err != nil || len(scopes) == 0 || !isSubset(scopes, c.Scopes) {
		redirectAuthorizationError(w, r, redirectURI, q.Get("state"), "invalid_scope", "requested scope is not registered for this client")
		return
	}
	txID, err := s.randomValue("tx", 24)
	if err != nil {
		http.Error(w, "failed to generate transaction", http.StatusInternalServerError)
		return
	}
	csrf, err := s.randomValue("csrf", 24)
	if err != nil {
		http.Error(w, "failed to generate csrf token", http.StatusInternalServerError)
		return
	}
	tx := &authorizationTransaction{
		ID:            txID,
		CSRF:          csrf,
		ClientID:      c.ID,
		RedirectURI:   redirectURI,
		Scope:         scopes,
		State:         q.Get("state"),
		Resource:      s.cfg.Resource,
		CodeChallenge: q.Get("code_challenge"),
		ExpiresAt:     s.now().Add(s.cfg.TransactionTTL),
	}
	s.mu.Lock()
	s.transactions[tx.ID] = tx
	s.mu.Unlock()
	slog.Info("oauth authorization transaction created", "tx_fp", fingerprint(tx.ID), "client_fp", fingerprint(tx.ClientID))
	s.renderLogin(w, r, tx, c, "")
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if err := parseForm(w, r); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	tx, c, ok := s.transaction(r.Form.Get("transaction_id"), r.Form.Get("csrf"))
	if !ok {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "authorization transaction is invalid or expired")
		return
	}
	account, ok, err := s.authenticate(r.Context(), r.Form.Get("tenant"), r.Form.Get("username"), r.Form.Get("password"))
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if !ok {
		s.renderLogin(w, r, tx, c, genericLoginError)
		return
	}
	userID := account.TenantID + ":" + account.Username
	s.mu.Lock()
	if current, exists := s.transactions[tx.ID]; exists {
		current.UserID = userID
		current.TenantID = account.TenantID
	}
	s.mu.Unlock()
	tx.UserID = userID
	tx.TenantID = account.TenantID
	slog.Info("oauth authorization transaction user bound", "tx_fp", fingerprint(tx.ID))
	s.renderConsent(w, tx, c)
}

func (s *Server) handleConsent(w http.ResponseWriter, r *http.Request) {
	if err := parseForm(w, r); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	tx, c, ok := s.transaction(r.Form.Get("transaction_id"), r.Form.Get("csrf"))
	if !ok {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "authorization transaction is invalid or not authenticated")
		return
	}
	if tx.UserID == "" {
		s.renderLogin(w, r, tx, c, "本次授权事务尚未完成登录，请重新登录后再确认授权")
		return
	}
	s.mu.Lock()
	delete(s.transactions, tx.ID)
	s.mu.Unlock()
	if r.Form.Get("decision") != "approve" {
		redirectAuthorizationError(w, r, tx.RedirectURI, tx.State, "access_denied", "the resource owner denied the request")
		return
	}
	slog.Info("oauth authorization consent approved", "tx_fp", fingerprint(tx.ID), "redirect_origin", cspOrigin(tx.RedirectURI))
	rawCode, err := s.randomValue("code", 32)
	if err != nil {
		http.Error(w, "failed to generate authorization code", http.StatusInternalServerError)
		return
	}
	code := &authorizationCode{
		ClientID:      tx.ClientID,
		RedirectURI:   tx.RedirectURI,
		Scope:         slices.Clone(tx.Scope),
		Resource:      tx.Resource,
		CodeChallenge: tx.CodeChallenge,
		UserID:        tx.UserID,
		TenantID:      tx.TenantID,
		ExpiresAt:     s.now().Add(s.cfg.CodeTTL),
	}
	s.mu.Lock()
	s.codes[valueKey(rawCode)] = code
	s.mu.Unlock()
	u, _ := url.Parse(tx.RedirectURI)
	q := u.Query()
	q.Set("code", rawCode)
	if tx.State != "" {
		q.Set("state", tx.State)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if err := parseForm(w, r); err != nil {
		writeTokenError(w, "invalid_request", err.Error())
		return
	}
	if _, _, ok := r.BasicAuth(); ok {
		writeTokenError(w, "invalid_client", "this server only accepts public clients")
		return
	}
	switch r.Form.Get("grant_type") {
	case "authorization_code":
		s.exchangeAuthorizationCode(w, r)
	case "refresh_token":
		s.exchangeRefreshToken(w, r)
	default:
		writeTokenError(w, "unsupported_grant_type", "supported grants are authorization_code and refresh_token")
	}
}

func (s *Server) handleIntrospection(w http.ResponseWriter, r *http.Request) {
	if !s.validIntrospectionRequest(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	if err := parseForm(w, r); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	info, err := s.VerifyAccessToken(r.Context(), r.Form.Get("token"), r)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"active": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"active":    true,
		"client_id": info.Extra["client_id"],
		"resource":  info.Extra["resource"],
		"scope":     strings.Join(info.Scopes, " "),
		"user_id":   info.UserID,
		"tenant_id": info.Extra["tenant_id"],
		"exp":       info.Expiration.Unix(),
	})
}

func (s *Server) handleUserinfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	raw, ok := bearerToken(r)
	if !ok {
		writeUserinfoError(w)
		return
	}
	info, err := s.VerifyAccessToken(r.Context(), raw, r)
	if err != nil {
		writeUserinfoError(w)
		return
	}
	tenantID, _ := info.Extra["tenant_id"].(string)
	if info.UserID == "" || tenantID == "" {
		writeUserinfoError(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"sub":       info.UserID,
		"user_id":   info.UserID,
		"tenant_id": tenantID,
	})
}

func writeUserinfoError(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
}

func bearerToken(r *http.Request) (string, bool) {
	scheme, value, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(value) == "" {
		return "", false
	}
	return value, true
}

func (s *Server) validIntrospectionRequest(r *http.Request) bool {
	scheme, value, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	return ok && strings.EqualFold(scheme, "Bearer") &&
		subtle.ConstantTimeCompare([]byte(value), []byte(s.cfg.IntrospectionSecret)) == 1
}

func (s *Server) exchangeAuthorizationCode(w http.ResponseWriter, r *http.Request) {
	rawCode := r.Form.Get("code")
	s.mu.Lock()
	code, ok := s.codes[valueKey(rawCode)]
	if ok {
		delete(s.codes, valueKey(rawCode))
	}
	s.mu.Unlock()
	if !ok || s.now().After(code.ExpiresAt) {
		writeTokenError(w, "invalid_grant", "authorization code is invalid or expired")
		return
	}
	if r.Form.Get("client_id") != code.ClientID || r.Form.Get("redirect_uri") != code.RedirectURI {
		writeTokenError(w, "invalid_grant", "client_id or redirect_uri does not match the authorization code")
		return
	}
	if resource := r.Form.Get("resource"); resource != "" && resource != code.Resource {
		writeTokenError(w, "invalid_target", "resource does not match the authorization code")
		return
	}
	verifier := r.Form.Get("code_verifier")
	challenge := pkceChallenge(verifier)
	if verifier == "" || subtle.ConstantTimeCompare([]byte(challenge), []byte(code.CodeChallenge)) != 1 {
		writeTokenError(w, "invalid_grant", "PKCE verification failed")
		return
	}
	response, err := s.issueTokens(code.ClientID, code.UserID, code.TenantID, code.Scope, code.Resource)
	if err != nil {
		http.Error(w, "failed to issue token", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) exchangeRefreshToken(w http.ResponseWriter, r *http.Request) {
	rawRefreshToken := r.Form.Get("refresh_token")
	s.mu.Lock()
	token, ok := s.refreshTokens[valueKey(rawRefreshToken)]
	if ok {
		delete(s.refreshTokens, valueKey(rawRefreshToken))
	}
	s.mu.Unlock()
	if !ok || s.now().After(token.ExpiresAt) {
		writeTokenError(w, "invalid_grant", "refresh token is invalid or expired")
		return
	}
	if r.Form.Get("client_id") != token.ClientID {
		writeTokenError(w, "invalid_grant", "client_id does not match refresh token")
		return
	}
	if resource := r.Form.Get("resource"); resource != "" && resource != token.Resource {
		writeTokenError(w, "invalid_target", "resource does not match refresh token")
		return
	}
	response, err := s.issueTokens(token.ClientID, token.UserID, token.TenantID, token.Scope, token.Resource)
	if err != nil {
		http.Error(w, "failed to issue token", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) issueTokens(clientID, userID, tenantID string, scopes []string, resource string) (map[string]any, error) {
	accessRaw, err := s.randomValue("at", 32)
	if err != nil {
		return nil, err
	}
	now := s.now()
	access := &accessToken{
		ClientID:  clientID,
		Scope:     slices.Clone(scopes),
		Resource:  resource,
		UserID:    userID,
		TenantID:  tenantID,
		ExpiresAt: now.Add(s.cfg.AccessTokenTTL),
	}
	response := map[string]any{
		"access_token": accessRaw,
		"token_type":   "Bearer",
		"expires_in":   int(s.cfg.AccessTokenTTL.Seconds()),
		"scope":        strings.Join(scopes, " "),
	}
	s.mu.Lock()
	s.accessTokens[valueKey(accessRaw)] = access
	s.mu.Unlock()
	if slices.Contains(scopes, "offline_access") {
		refreshRaw, err := s.randomValue("rt", 32)
		if err != nil {
			return nil, err
		}
		refresh := &refreshToken{
			ClientID:  clientID,
			Scope:     slices.Clone(scopes),
			Resource:  resource,
			UserID:    userID,
			TenantID:  tenantID,
			ExpiresAt: now.Add(s.cfg.RefreshTokenTTL),
		}
		s.mu.Lock()
		s.refreshTokens[valueKey(refreshRaw)] = refresh
		s.mu.Unlock()
		response["refresh_token"] = refreshRaw
	}
	return response, nil
}

func (s *Server) VerifyAccessToken(_ context.Context, raw string, _ *http.Request) (*mcpauth.TokenInfo, error) {
	s.mu.Lock()
	token, ok := s.accessTokens[valueKey(raw)]
	if ok && s.now().After(token.ExpiresAt) {
		delete(s.accessTokens, valueKey(raw))
		ok = false
	}
	s.mu.Unlock()
	if !ok || token.Resource != s.cfg.Resource {
		return nil, mcpauth.ErrInvalidToken
	}
	return &mcpauth.TokenInfo{
		Scopes:     slices.Clone(token.Scope),
		Expiration: token.ExpiresAt,
		UserID:     token.UserID,
		Extra: map[string]any{
			"client_id": token.ClientID,
			"resource":  token.Resource,
			"tenant_id": token.TenantID,
		},
	}, nil
}

func (s *Server) authenticate(ctx context.Context, tenantID, username, password string) (account, bool, error) {
	found, ok, err := s.accountStore.lookup(ctx, tenantID, username)
	if err != nil {
		return account{}, false, err
	}
	expected := s.accountStore.dummyHash
	if ok {
		expected = found.PasswordHash
	}
	err = bcrypt.CompareHashAndPassword(expected, []byte(password))
	if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) || (err == nil && !ok) {
		return account{}, false, nil
	}
	if err != nil {
		return account{}, false, err
	}
	return found, true, nil
}

func (s *Server) transaction(id, csrf string) (*authorizationTransaction, *client, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, ok := s.transactions[id]
	if !ok {
		slog.Warn("oauth authorization transaction rejected", "reason", "missing", "tx_fp", fingerprint(id), "id_len", len(id), "csrf_len", len(csrf))
		return nil, nil, false
	}
	if s.now().After(tx.ExpiresAt) {
		delete(s.transactions, id)
		slog.Warn("oauth authorization transaction rejected", "reason", "expired", "tx_fp", fingerprint(id), "id_len", len(id), "csrf_len", len(csrf))
		return nil, nil, false
	}
	if subtle.ConstantTimeCompare([]byte(tx.CSRF), []byte(csrf)) != 1 {
		delete(s.transactions, id)
		slog.Warn("oauth authorization transaction rejected", "reason", "csrf_mismatch", "tx_fp", fingerprint(id), "id_len", len(id), "csrf_len", len(csrf))
		return nil, nil, false
	}
	c, ok := s.clients[tx.ClientID]
	if !ok {
		slog.Warn("oauth authorization transaction rejected", "reason", "client_missing", "tx_fp", fingerprint(id), "id_len", len(id), "csrf_len", len(csrf))
		return nil, nil, false
	}
	copyTx := *tx
	copyTx.Scope = slices.Clone(tx.Scope)
	copyClient := *c
	copyClient.RedirectURIs = slices.Clone(c.RedirectURIs)
	copyClient.Scopes = slices.Clone(c.Scopes)
	return &copyTx, &copyClient, true
}

func (s *Server) renderLogin(w http.ResponseWriter, r *http.Request, tx *authorizationTransaction, c *client, message string) {
	tenants, err := s.accountStore.tenants(r.Context())
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	s.setPageHeaders(w)
	w.WriteHeader(http.StatusOK)
	_ = loginTemplate.Execute(w, pageData{TransactionID: tx.ID, CSRF: tx.CSRF, ClientName: c.Name, Tenants: tenants, Error: message})
}

func (s *Server) renderConsent(w http.ResponseWriter, tx *authorizationTransaction, c *client) {
	s.setPageHeaders(w)
	w.WriteHeader(http.StatusOK)
	_ = consentTemplate.Execute(w, pageData{TransactionID: tx.ID, CSRF: tx.CSRF, ClientName: c.Name, Scopes: tx.Scope})
}

func (s *Server) randomValue(prefix string, byteCount int) (string, error) {
	b := make([]byte, byteCount)
	if _, err := io.ReadFull(s.rng, b); err != nil {
		return "", err
	}
	return prefix + "_" + base64.RawURLEncoding.EncodeToString(b), nil
}

func validateRedirectURI(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return "", errors.New("redirect URI must be absolute")
	}
	if u.User != nil || u.Fragment != "" {
		return "", errors.New("redirect URI must not contain userinfo or fragment")
	}
	if u.Scheme == "https" {
		return u.String(), nil
	}
	if u.Scheme != "http" || !isLoopbackHost(u.Hostname()) {
		return "", errors.New("redirect URI must use HTTPS, except HTTP loopback callbacks")
	}
	return u.String(), nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func normalizeScopes(raw string) ([]string, error) {
	requested := strings.Fields(raw)
	seen := make(map[string]bool, len(requested))
	for _, scope := range requested {
		if !slices.Contains(supportedScopes, scope) {
			return nil, fmt.Errorf("unsupported scope %q", scope)
		}
		seen[scope] = true
	}
	result := make([]string, 0, len(seen))
	for _, scope := range supportedScopes {
		if seen[scope] {
			result = append(result, scope)
		}
	}
	return result, nil
}

func isSubset(values, allowed []string) bool {
	for _, value := range values {
		if !slices.Contains(allowed, value) {
			return false
		}
	}
	return true
}

func onlyAllowed(values []string, allowed ...string) bool {
	return isSubset(values, allowed)
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func valueKey(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func fingerprint(value string) string {
	if value == "" {
		return "empty"
	}
	return valueKey(value)[:12]
}

func parseForm(w http.ResponseWriter, r *http.Request) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		return errors.New("invalid form body")
	}
	return nil
}

func redirectAuthorizationError(w http.ResponseWriter, r *http.Request, redirectURI, state, code, description string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, description, http.StatusBadRequest)
		return
	}
	q := u.Query()
	q.Set("error", code)
	q.Set("error_description", description)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func writeTokenError(w http.ResponseWriter, code, description string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeOAuthError(w, http.StatusBadRequest, code, description)
}

func writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": description})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (s *Server) setPageHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	// 本地教学服务可能通过 127.0.0.1、localhost 或随机 loopback 端口打开，
	// 因此允许 loopback 主机的任意端口，但不允许公网 origin 提交表单。
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action http://127.0.0.1:* http://localhost:* http://[::1]:*; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

func cspOrigin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}
