package oauthproxy

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
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

var supportedScopes = []string{"openid", "profile", "email", "offline_access", "mcp:tools"}

// Config describes the proxy-facing issuer and the pre-registered upstream OAuth client.
// The proxy returns upstream access tokens to the OAuth client; it does not mint a replacement access token.
type Config struct {
	Issuer                string
	Resource              string
	UpstreamAuthorizeURL  string
	UpstreamTokenURL      string
	UpstreamUserinfoURL   string
	UpstreamIntrospectURL string
	UpstreamClientID      string
	UpstreamClientSecret  string
	UpstreamRedirectURI   string
	IntrospectionSecret   string
	UpstreamPKCE          bool
	SendResource          bool
	AccessTokenTTL        time.Duration
	RefreshTokenTTL       time.Duration
	CodeTTL               time.Duration
	TransactionTTL        time.Duration
	HTTPClient            *http.Client
}

type Server struct {
	cfg Config
	now func() time.Time
	rng io.Reader

	mu            sync.Mutex
	clients       map[string]*client
	transactions  map[string]*transaction
	upstreamCodes map[string]string
	knownTokens   map[string]*upstreamToken
}

type client struct {
	ID           string
	Name         string
	RedirectURIs []string
	Scopes       []string
}

type transaction struct {
	ID              string
	ClientID        string
	RedirectURI     string
	Scope           []string
	State           string
	Resource        string
	ClientChallenge string
	UpstreamState   string
	UpstreamCode    string
	ExpiresAt       time.Time
}

type upstreamToken struct {
	AccessToken  string
	RefreshToken string
	TokenType    string
	Scope        []string
	UserID       string
	ClientID     string
	Resource     string
	ExpiresAt    time.Time
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

type upstreamTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	ExpiresIn    int64  `json:"expires_in"`
}

type upstreamIntrospectionResponse struct {
	Active   bool   `json:"active"`
	ClientID string `json:"client_id"`
	Resource string `json:"resource"`
	Scope    string `json:"scope"`
	UserID   string `json:"user_id"`
	Subject  string `json:"sub"`
	Username string `json:"username"`
	Exp      int64  `json:"exp"`
}

func New(cfg Config) (*Server, error) {
	if cfg.Issuer == "" || cfg.Resource == "" || cfg.UpstreamAuthorizeURL == "" || cfg.UpstreamTokenURL == "" || cfg.UpstreamClientID == "" || cfg.UpstreamRedirectURI == "" || cfg.IntrospectionSecret == "" {
		return nil, errors.New("issuer, resource, upstream OAuth endpoints/client, redirect URI, and introspection secret are required")
	}
	for name, raw := range map[string]string{
		"issuer": cfg.Issuer, "resource": cfg.Resource, "upstream authorization URL": cfg.UpstreamAuthorizeURL,
		"upstream token URL": cfg.UpstreamTokenURL, "upstream redirect URI": cfg.UpstreamRedirectURI,
	} {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return nil, fmt.Errorf("invalid %s", name)
		}
	}
	redirectURI, err := validateRedirectURI(cfg.UpstreamRedirectURI)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream redirect URI: %w", err)
	}
	cfg.Issuer = strings.TrimRight(cfg.Issuer, "/")
	cfg.Resource = strings.TrimRight(cfg.Resource, "/")
	cfg.UpstreamAuthorizeURL = strings.TrimRight(cfg.UpstreamAuthorizeURL, "?")
	cfg.UpstreamTokenURL = strings.TrimRight(cfg.UpstreamTokenURL, "?")
	cfg.UpstreamRedirectURI = redirectURI
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
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &Server{
		cfg:           cfg,
		now:           time.Now,
		rng:           rand.Reader,
		clients:       make(map[string]*client),
		transactions:  make(map[string]*transaction),
		upstreamCodes: make(map[string]string),
		knownTokens:   make(map[string]*upstreamToken),
	}, nil
}

func (s *Server) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET "+s.route("/.well-known/oauth-authorization-server"), s.handleMetadata)
	mux.HandleFunc("POST "+s.route("/oauth/register"), s.handleRegister)
	mux.HandleFunc("GET "+s.route("/oauth/authorize"), s.handleAuthorize)
	mux.HandleFunc("GET "+s.route("/oauth/callback/upstream"), s.handleUpstreamCallback)
	mux.HandleFunc("POST "+s.route("/oauth/token"), s.handleToken)
	mux.HandleFunc("POST "+s.route("/oauth/introspect"), s.handleIntrospection)
}

func (s *Server) route(suffix string) string {
	u, _ := url.Parse(s.cfg.Issuer)
	prefix := strings.TrimRight(u.Path, "/")
	if prefix == "" {
		return suffix
	}
	return prefix + suffix
}

func (s *Server) endpoint(suffix string) string {
	return s.cfg.Issuer + suffix
}

func (s *Server) handleMetadata(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                s.cfg.Issuer,
		"authorization_endpoint":                s.endpoint("/oauth/authorize"),
		"token_endpoint":                        s.endpoint("/oauth/token"),
		"registration_endpoint":                 s.endpoint("/oauth/register"),
		"response_types_supported":              []string{"code"},
		"response_modes_supported":              []string{"query"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"code_challenge_methods_supported":      []string{"S256"},
		"scopes_supported":                      supportedScopes,
	})
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req registrationRequest
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "invalid JSON body")
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
	scopes, err := normalizeScopes(req.Scope)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_scope", err.Error())
		return
	}
	if len(scopes) == 0 {
		scopes = slices.Clone(supportedScopes)
	}
	id, err := s.randomValue("proxy_client", 24)
	if err != nil {
		http.Error(w, "failed to create client", http.StatusInternalServerError)
		return
	}
	c := &client{ID: id, Name: strings.TrimSpace(req.ClientName), RedirectURIs: redirectURIs, Scopes: scopes}
	if c.Name == "" {
		c.Name = "OAuth Proxy Client"
	}
	s.mu.Lock()
	s.clients[id] = c
	s.mu.Unlock()
	writeJSON(w, http.StatusCreated, registrationResponse{
		ClientID:                id,
		ClientIDIssuedAt:        s.now().Unix(),
		RedirectURIs:            redirectURIs,
		ClientName:              c.Name,
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
		Scope:                   strings.Join(scopes, " "),
	})
}

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	c, ok := s.client(q.Get("client_id"))
	if !ok {
		http.Error(w, "invalid client_id", http.StatusBadRequest)
		return
	}
	redirectURI, err := validateRedirectURI(q.Get("redirect_uri"))
	if err != nil || !slices.Contains(c.RedirectURIs, redirectURI) {
		http.Error(w, "redirect_uri is not registered for this client", http.StatusBadRequest)
		return
	}
	if q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		s.redirectError(w, r, redirectURI, q.Get("state"), "invalid_request", "authorization code and PKCE S256 are required")
		return
	}
	if q.Get("resource") != "" && q.Get("resource") != s.cfg.Resource {
		s.redirectError(w, r, redirectURI, q.Get("state"), "invalid_target", "resource does not match this proxy")
		return
	}
	scopes, err := normalizeScopes(q.Get("scope"))
	if err != nil || len(scopes) == 0 || !isSubset(scopes, c.Scopes) {
		s.redirectError(w, r, redirectURI, q.Get("state"), "invalid_scope", "requested scope is not registered")
		return
	}
	txID, err := s.randomValue("proxy_tx", 24)
	if err != nil {
		http.Error(w, "failed to create transaction", http.StatusInternalServerError)
		return
	}
	upstreamState, err := s.randomValue("upstream_state", 24)
	if err != nil {
		http.Error(w, "failed to create state", http.StatusInternalServerError)
		return
	}
	tx := &transaction{ID: txID, ClientID: c.ID, RedirectURI: redirectURI, Scope: scopes, State: q.Get("state"), Resource: s.cfg.Resource, ClientChallenge: q.Get("code_challenge"), UpstreamState: upstreamState, ExpiresAt: s.now().Add(s.cfg.TransactionTTL)}
	s.mu.Lock()
	s.transactions[tx.ID] = tx
	s.mu.Unlock()

	u, err := url.Parse(s.cfg.UpstreamAuthorizeURL)
	if err != nil {
		http.Error(w, "invalid upstream authorization URL", http.StatusInternalServerError)
		return
	}
	upstream := u.Query()
	upstream.Set("response_type", "code")
	upstream.Set("client_id", s.cfg.UpstreamClientID)
	upstream.Set("redirect_uri", s.cfg.UpstreamRedirectURI)
	upstream.Set("scope", strings.Join(scopes, " "))
	upstream.Set("state", upstreamState)
	if s.cfg.SendResource {
		upstream.Set("resource", s.cfg.Resource)
	}
	if s.cfg.UpstreamPKCE {
		upstream.Set("code_challenge_method", "S256")
		// The proxy forwards Codex's PKCE challenge. The token endpoint later
		// forwards Codex's verifier to the upstream token endpoint.
		upstream.Set("code_challenge", tx.ClientChallenge)
	}
	u.RawQuery = upstream.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (s *Server) handleUpstreamCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	tx, ok := s.transactionByUpstreamState(q.Get("state"))
	if !ok {
		http.Error(w, "authorization transaction is invalid or expired", http.StatusBadRequest)
		return
	}
	if upstreamErr := q.Get("error"); upstreamErr != "" {
		s.redirectError(w, r, tx.RedirectURI, tx.State, upstreamErr, q.Get("error_description"))
		return
	}
	if q.Get("code") == "" {
		s.redirectError(w, r, tx.RedirectURI, tx.State, "invalid_request", "upstream authorization code is missing")
		return
	}
	s.mu.Lock()
	current, exists := s.transactions[tx.ID]
	if !exists || current.UpstreamCode != "" {
		s.mu.Unlock()
		http.Error(w, "authorization code has already been delivered", http.StatusBadRequest)
		return
	}
	current.UpstreamCode = q.Get("code")
	s.upstreamCodes[valueKey(current.UpstreamCode)] = current.ID
	s.mu.Unlock()
	u, _ := url.Parse(tx.RedirectURI)
	callback := u.Query()
	// The upstream authorization code is intentionally passed through unchanged.
	// The proxy translates client_id, redirect_uri and PKCE at /oauth/token.
	callback.Set("code", q.Get("code"))
	if tx.State != "" {
		callback.Set("state", tx.State)
	}
	u.RawQuery = callback.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (s *Server) exchangeUpstreamCode(ctx context.Context, code, verifier string, tx *transaction) (upstreamToken, error) {
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {s.cfg.UpstreamRedirectURI}}
	if s.cfg.UpstreamClientSecret == "" {
		form.Set("client_id", s.cfg.UpstreamClientID)
	}
	if s.cfg.UpstreamPKCE {
		form.Set("code_verifier", verifier)
	}
	token, err := s.requestUpstreamToken(ctx, form)
	if err != nil {
		return upstreamToken{}, err
	}
	if len(token.Scope) == 0 {
		token.Scope = slices.Clone(tx.Scope)
	}
	token.UserID = s.userID(ctx, token.AccessToken)
	return token, nil
}

func (s *Server) requestUpstreamToken(ctx context.Context, form url.Values) (upstreamToken, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.UpstreamTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return upstreamToken{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if s.cfg.UpstreamClientSecret != "" {
		req.SetBasicAuth(s.cfg.UpstreamClientID, s.cfg.UpstreamClientSecret)
	}
	resp, err := s.cfg.HTTPClient.Do(req)
	if err != nil {
		return upstreamToken{}, fmt.Errorf("upstream token request failed: %w", err)
	}
	defer resp.Body.Close()
	var payload upstreamTokenResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&payload); err != nil {
		return upstreamToken{}, fmt.Errorf("decode upstream token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK || payload.AccessToken == "" {
		return upstreamToken{}, errors.New("upstream token exchange failed")
	}
	scope := strings.Fields(payload.Scope)
	expiresIn := payload.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = int64(s.cfg.AccessTokenTTL.Seconds())
	}
	return upstreamToken{AccessToken: payload.AccessToken, RefreshToken: payload.RefreshToken, TokenType: firstNonEmpty(payload.TokenType, "Bearer"), Scope: scope, ExpiresAt: s.now().Add(time.Duration(expiresIn) * time.Second)}, nil
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := parseForm(w, r); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if _, _, ok := r.BasicAuth(); ok {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client", "proxy clients are public")
		return
	}
	switch r.Form.Get("grant_type") {
	case "authorization_code":
		s.exchangeLocalCode(w, r)
	case "refresh_token":
		s.exchangeLocalRefreshToken(w, r)
	default:
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "authorization_code and refresh_token are supported")
	}
}

func (s *Server) exchangeLocalCode(w http.ResponseWriter, r *http.Request) {
	rawCode := r.Form.Get("code")
	key := valueKey(rawCode)
	s.mu.Lock()
	txID, ok := s.upstreamCodes[key]
	if ok {
		delete(s.upstreamCodes, key)
	}
	tx, txOK := s.transactions[txID]
	if txOK {
		delete(s.transactions, txID)
	}
	var copyTx transaction
	if txOK {
		copyTx = *tx
		copyTx.Scope = slices.Clone(tx.Scope)
	}
	s.mu.Unlock()
	if !ok || !txOK || copyTx.UpstreamCode != rawCode || s.now().After(copyTx.ExpiresAt) || r.Form.Get("client_id") != copyTx.ClientID || r.Form.Get("redirect_uri") != copyTx.RedirectURI || r.Form.Get("resource") != "" && r.Form.Get("resource") != copyTx.Resource || subtle.ConstantTimeCompare([]byte(pkceChallenge(r.Form.Get("code_verifier"))), []byte(copyTx.ClientChallenge)) != 1 {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "authorization code or PKCE verification failed")
		return
	}
	token, err := s.exchangeUpstreamCode(r.Context(), rawCode, r.Form.Get("code_verifier"), &copyTx)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", err.Error())
		return
	}
	response, err := s.rememberUpstreamToken(copyTx.ClientID, copyTx.Resource, token)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) rememberUpstreamToken(clientID, resource string, token upstreamToken) (map[string]any, error) {
	if token.ExpiresAt.IsZero() || s.now().After(token.ExpiresAt) {
		return nil, errors.New("upstream access token is expired")
	}
	response := map[string]any{"access_token": token.AccessToken, "token_type": token.TokenType, "expires_in": int(time.Until(token.ExpiresAt).Seconds()), "scope": strings.Join(token.Scope, " ")}
	token.ClientID = clientID
	token.Resource = resource
	s.mu.Lock()
	s.knownTokens[valueKey(token.AccessToken)] = &token
	s.mu.Unlock()
	if token.RefreshToken != "" {
		response["refresh_token"] = token.RefreshToken
	}
	if token.RefreshToken != "" {
		s.mu.Lock()
		s.knownTokens[valueKey(token.RefreshToken)] = &token
		s.mu.Unlock()
	}
	return response, nil
}

func (s *Server) exchangeLocalRefreshToken(w http.ResponseWriter, r *http.Request) {
	raw := r.Form.Get("refresh_token")
	s.mu.Lock()
	token, ok := s.knownTokens[valueKey(raw)]
	s.mu.Unlock()
	if !ok || token.RefreshToken != raw || r.Form.Get("client_id") != token.ClientID {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token is invalid")
		return
	}
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {raw}}
	if s.cfg.UpstreamClientSecret == "" {
		form.Set("client_id", s.cfg.UpstreamClientID)
	}
	refreshed, err := s.requestUpstreamToken(r.Context(), form)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", err.Error())
		return
	}
	refreshed.UserID = token.UserID
	if len(refreshed.Scope) == 0 {
		refreshed.Scope = slices.Clone(token.Scope)
	}
	s.mu.Lock()
	delete(s.knownTokens, valueKey(raw))
	s.mu.Unlock()
	response, err := s.rememberUpstreamToken(token.ClientID, token.Resource, refreshed)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, response)
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
	raw := r.Form.Get("token")
	s.mu.Lock()
	token, ok := s.knownTokens[valueKey(raw)]
	if ok && s.now().After(token.ExpiresAt) {
		delete(s.knownTokens, valueKey(raw))
		ok = false
	}
	var copyToken upstreamToken
	if ok {
		copyToken = *token
	}
	s.mu.Unlock()
	if !ok || copyToken.Resource != r.Form.Get("resource") && r.Form.Get("resource") != "" {
		writeJSON(w, http.StatusOK, map[string]any{"active": false})
		return
	}
	if s.cfg.UpstreamIntrospectURL != "" {
		remote, err := s.introspectUpstream(r.Context(), raw)
		if err != nil || !remote.Active {
			writeJSON(w, http.StatusOK, map[string]any{"active": false})
			return
		}
		if remote.Resource != "" && remote.Resource != copyToken.Resource {
			writeJSON(w, http.StatusOK, map[string]any{"active": false})
			return
		}
		if remote.ClientID != "" {
			copyToken.ClientID = remote.ClientID
		}
		if remote.Resource != "" {
			copyToken.Resource = remote.Resource
		}
		if scopes := strings.Fields(remote.Scope); len(scopes) > 0 {
			copyToken.Scope = scopes
		}
		if remote.UserID != "" {
			copyToken.UserID = remote.UserID
		} else if remote.Subject != "" {
			copyToken.UserID = remote.Subject
		} else if remote.Username != "" {
			copyToken.UserID = remote.Username
		}
		if remote.Exp > 0 {
			copyToken.ExpiresAt = time.Unix(remote.Exp, 0)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"active": true, "client_id": copyToken.ClientID, "resource": copyToken.Resource, "scope": strings.Join(copyToken.Scope, " "), "user_id": copyToken.UserID, "exp": copyToken.ExpiresAt.Unix()})
}

func (s *Server) introspectUpstream(ctx context.Context, raw string) (upstreamIntrospectionResponse, error) {
	form := url.Values{"token": {raw}, "resource": {s.cfg.Resource}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.UpstreamIntrospectURL, strings.NewReader(form.Encode()))
	if err != nil {
		return upstreamIntrospectionResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if s.cfg.UpstreamClientSecret != "" {
		req.SetBasicAuth(s.cfg.UpstreamClientID, s.cfg.UpstreamClientSecret)
	}
	resp, err := s.cfg.HTTPClient.Do(req)
	if err != nil {
		return upstreamIntrospectionResponse{}, err
	}
	defer resp.Body.Close()
	var result upstreamIntrospectionResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&result); err != nil {
		return upstreamIntrospectionResponse{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return upstreamIntrospectionResponse{}, errors.New("upstream introspection failed")
	}
	return result, nil
}

func (s *Server) validIntrospectionRequest(r *http.Request) bool {
	scheme, value, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	return ok && strings.EqualFold(scheme, "Bearer") && subtle.ConstantTimeCompare([]byte(value), []byte(s.cfg.IntrospectionSecret)) == 1
}

func (s *Server) client(id string) (*client, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[id]
	if !ok {
		return nil, false
	}
	copyClient := *c
	copyClient.RedirectURIs = slices.Clone(c.RedirectURIs)
	copyClient.Scopes = slices.Clone(c.Scopes)
	return &copyClient, true
}

func (s *Server) transactionByUpstreamState(state string) (*transaction, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var tx *transaction
	var key string
	for candidateKey, candidate := range s.transactions {
		if candidate.UpstreamState == state {
			tx = candidate
			key = candidateKey
			break
		}
	}
	if tx == nil || s.now().After(tx.ExpiresAt) {
		if tx != nil {
			delete(s.transactions, key)
		}
		return nil, false
	}
	copyTx := *tx
	copyTx.Scope = slices.Clone(tx.Scope)
	return &copyTx, true
}

func (s *Server) randomValue(prefix string, byteCount int) (string, error) {
	b := make([]byte, byteCount)
	if _, err := io.ReadFull(s.rng, b); err != nil {
		return "", err
	}
	return prefix + "_" + base64.RawURLEncoding.EncodeToString(b), nil
}

func (s *Server) redirectError(w http.ResponseWriter, r *http.Request, redirectURI, state, code, description string) {
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

func (s *Server) userID(ctx context.Context, accessToken string) string {
	if s.cfg.UpstreamUserinfoURL == "" {
		return "upstream-user"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.UpstreamUserinfoURL, nil)
	if err != nil {
		return "upstream-user"
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := s.cfg.HTTPClient.Do(req)
	if err != nil {
		return "upstream-user"
	}
	defer resp.Body.Close()
	var payload map[string]any
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&payload) != nil {
		return "upstream-user"
	}
	for _, key := range []string{"sub", "user_id", "username", "preferred_username"} {
		if value, ok := payload[key].(string); ok && value != "" {
			return value
		}
	}
	return "upstream-user"
}

func parseForm(w http.ResponseWriter, r *http.Request) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	return r.ParseForm()
}

func validateRedirectURI(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" || u.User != nil || u.Fragment != "" {
		return "", errors.New("redirect URI must be absolute and contain no userinfo or fragment")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && isLoopbackHost(u.Hostname())) {
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

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func valueKey(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": description})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
