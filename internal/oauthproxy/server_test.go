package oauthproxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestProxyReturnsUpstreamTokensAndIntrospectsThem(t *testing.T) {
	upstreamToken := "upstream-access-1"
	upstreamRefresh := "upstream-refresh-1"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/authorize":
			q := r.URL.Query()
			redirect := q.Get("redirect_uri")
			callback, _ := url.Parse(redirect)
			params := callback.Query()
			params.Set("code", "upstream-code")
			params.Set("state", q.Get("state"))
			callback.RawQuery = params.Encode()
			http.Redirect(w, r, callback.String(), http.StatusFound)
		case "/token":
			if err := r.ParseForm(); err != nil {
				http.Error(w, "bad form", http.StatusBadRequest)
				return
			}
			if r.Form.Get("grant_type") == "refresh_token" {
				upstreamToken = "upstream-access-2"
				upstreamRefresh = "upstream-refresh-2"
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"access_token":  upstreamToken,
				"refresh_token": upstreamRefresh,
				"token_type":    "Bearer",
				"expires_in":    3600,
				"scope":         "openid profile mcp:tools",
			})
		case "/userinfo":
			writeJSON(w, http.StatusOK, map[string]string{"sub": "alice"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	proxyMux := http.NewServeMux()
	proxyCfg := Config{
		Issuer:               "http://127.0.0.1:18082",
		Resource:             "http://127.0.0.1:18080/mcp",
		UpstreamAuthorizeURL: upstream.URL + "/authorize",
		UpstreamTokenURL:     upstream.URL + "/token",
		UpstreamUserinfoURL:  upstream.URL + "/userinfo",
		UpstreamClientID:     "upstream-client",
		UpstreamClientSecret: "upstream-secret",
		UpstreamRedirectURI:  "http://127.0.0.1:18082/oauth/callback/upstream",
		IntrospectionSecret:  "proxy-secret",
		UpstreamPKCE:         true,
		HTTPClient:           upstream.Client(),
	}
	proxy, err := New(proxyCfg)
	if err != nil {
		t.Fatal(err)
	}
	proxy.RegisterRoutes(proxyMux)
	proxyServer := httptest.NewServer(proxyMux)
	defer proxyServer.Close()
	proxy.cfg.Issuer = proxyServer.URL
	proxy.cfg.UpstreamRedirectURI = proxyServer.URL + "/oauth/callback/upstream"

	clientID := registerTestClient(t, proxyServer.URL)
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := pkceChallenge(verifier)
	redirectURI := "http://127.0.0.1:65530/callback"
	authorizeURL := proxyServer.URL + "/oauth/authorize?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {"openid profile mcp:tools"},
		"state":                 {"client-state"},
		"resource":              {proxyCfg.Resource},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}.Encode()

	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := noRedirect.Get(authorizeURL)
	if err != nil {
		t.Fatal(err)
	}
	upstreamAuthorize := resp.Header.Get("Location")
	resp.Body.Close()
	if upstreamAuthorize == "" {
		t.Fatal("proxy did not redirect to upstream authorize endpoint")
	}
	resp, err = noRedirect.Get(upstreamAuthorize)
	if err != nil {
		t.Fatal(err)
	}
	upstreamCallback := resp.Header.Get("Location")
	resp.Body.Close()
	resp, err = noRedirect.Get(upstreamCallback)
	if err != nil {
		t.Fatal(err)
	}
	localCallback := resp.Header.Get("Location")
	resp.Body.Close()
	localURL, err := url.Parse(localCallback)
	if err != nil {
		t.Fatal(err)
	}
	localCode := localURL.Query().Get("code")
	if localCode != "upstream-code" || localURL.Query().Get("state") != "client-state" {
		t.Fatalf("invalid local callback: %s", localCallback)
	}

	tokenResp := postForm(t, noRedirect, proxyServer.URL+"/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {localCode},
		"client_id":     {clientID},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
		"resource":      {proxyCfg.Resource},
	})
	var token map[string]any
	decodeJSON(t, tokenResp, &token)
	if token["access_token"] != upstreamToken || token["refresh_token"] != upstreamRefresh {
		t.Fatalf("proxy did not return upstream tokens: %#v", token)
	}

	request, _ := http.NewRequest(http.MethodPost, proxyServer.URL+"/oauth/introspect", strings.NewReader(url.Values{"token": {upstreamToken}, "resource": {proxyCfg.Resource}}.Encode()))
	request.Header.Set("Authorization", "Bearer proxy-secret")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	introspection, err := noRedirect.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var active map[string]any
	decodeJSON(t, introspection, &active)
	if active["active"] != true || active["user_id"] != "alice" {
		t.Fatalf("unexpected introspection response: %#v", active)
	}
}

func registerTestClient(t *testing.T, endpoint string) string {
	t.Helper()
	resp, err := http.Post(endpoint+"/oauth/register", "application/json", strings.NewReader(`{"client_name":"test","redirect_uris":["http://127.0.0.1:65530/callback"],"scope":"openid profile mcp:tools"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var result registrationResponse
	decodeJSON(t, resp, &result)
	if result.ClientID == "" {
		t.Fatal("missing proxy client id")
	}
	return result.ClientID
}

func postForm(t *testing.T, client *http.Client, endpoint string, form url.Values) *http.Response {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func decodeJSON(t *testing.T, response *http.Response, target any) {
	t.Helper()
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("unexpected status %d: %s", response.StatusCode, body)
	}
	if err := json.NewDecoder(response.Body).Decode(target); err != nil {
		t.Fatal(err)
	}
}
