package oauthserver

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestTenantScopedLoginBindsTokenToSelectedTenant(t *testing.T) {
	server := newTestServer(t, []Account{
		{TenantID: "acme", Username: "demo", Password: "demo"},
		{TenantID: "globex", Username: "demo", Password: "demo"},
		{TenantID: "globex", Username: "ops", Password: "ops"},
	})
	defer server.Close()

	loginPage := authorize(t, server.URL)
	if !strings.Contains(loginPage, `<label for="tenant">租户</label>`) || !strings.Contains(loginPage, `<option value="acme" selected>`) || !strings.Contains(loginPage, `value="demo"`) {
		t.Fatalf("login form missing tenant field or defaults: %s", loginPage)
	}

	rejected := postLogin(t, server.URL, loginPage, "acme", "ops", "ops")
	if strings.Contains(rejected, "确认授权范围") || !strings.Contains(rejected, "登录失败") {
		t.Fatalf("cross-tenant password match was accepted: %s", rejected)
	}

	acmeAccess, acmeRefresh := issueTokens(t, server.URL, "acme", "demo", "demo")
	assertIdentity(t, server.URL, acmeAccess, "acme", "acme:demo")

	globexAccess, _ := issueTokens(t, server.URL, "globex", "demo", "demo")
	assertIdentity(t, server.URL, globexAccess, "globex", "globex:demo")

	refreshed := refresh(t, server.URL, acmeRefresh)
	assertIdentity(t, server.URL, refreshed, "acme", "acme:demo")
}

func TestDefaultAccountsSeedBothDemoTenants(t *testing.T) {
	server := newTestServer(t, nil)
	defer server.Close()

	access, _ := issueTokens(t, server.URL, "globex", "demo", "demo")
	assertIdentity(t, server.URL, access, "globex", "globex:demo")

	page := authorize(t, server.URL)
	rejected := postLogin(t, server.URL, page, "acme", "ops", "ops")
	if strings.Contains(rejected, "确认授权范围") {
		t.Fatal("default seed accepted an unconfigured account")
	}
}

func TestDuplicateAccountRejected(t *testing.T) {
	_, err := New(Config{
		Issuer:   "http://127.0.0.1:8081",
		Resource: "http://127.0.0.1:8080/mcp",
		Accounts: []Account{
			{TenantID: "acme", Username: "demo", Password: "demo"},
			{TenantID: "acme", Username: "demo", Password: "other"},
		},
	})
	if err == nil {
		t.Fatal("expected duplicate account to be rejected")
	}
}

func newTestServer(t *testing.T, accounts []Account) *httptest.Server {
	t.Helper()
	oauth, err := New(Config{
		Issuer:              "http://127.0.0.1:8081",
		Resource:            "http://127.0.0.1:8080/mcp",
		IntrospectionSecret: "secret",
		Accounts:            accounts,
		StaticClients: []StaticClient{{
			ID:           "test-client",
			Name:         "Test Client",
			RedirectURIs: []string{"http://127.0.0.1:65530/callback"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	oauth.RegisterRoutes(mux)
	return httptest.NewServer(mux)
}

func issueTokens(t *testing.T, endpoint, tenant, username, password string) (string, string) {
	t.Helper()
	page := authorize(t, endpoint)
	consented := postLogin(t, endpoint, page, tenant, username, password)
	if !strings.Contains(consented, "确认授权范围") {
		t.Fatalf("login rejected for %s/%s: %s", tenant, username, consented)
	}
	code := approve(t, endpoint, consented)
	body := postForm(t, endpoint+"/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {"test-client"},
		"redirect_uri":  {"http://127.0.0.1:65530/callback"},
		"code_verifier": {"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"},
		"resource":      {"http://127.0.0.1:8080/mcp"},
	})
	var token map[string]any
	if err := json.Unmarshal(body, &token); err != nil {
		t.Fatal(err)
	}
	access, _ := token["access_token"].(string)
	refreshToken, _ := token["refresh_token"].(string)
	if access == "" || refreshToken == "" {
		t.Fatalf("missing tokens: %s", body)
	}
	return access, refreshToken
}

func refresh(t *testing.T, endpoint, refreshToken string) string {
	t.Helper()
	body := postForm(t, endpoint+"/oauth/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {"test-client"},
		"resource":      {"http://127.0.0.1:8080/mcp"},
	})
	var token map[string]any
	if err := json.Unmarshal(body, &token); err != nil {
		t.Fatal(err)
	}
	access, _ := token["access_token"].(string)
	if access == "" {
		t.Fatalf("refresh did not return an access token: %s", body)
	}
	return access
}

func assertIdentity(t *testing.T, endpoint, access, tenantID, userID string) {
	t.Helper()
	introspection := postAuthorized(t, endpoint+"/oauth/introspect", "secret", url.Values{"token": {access}})
	if introspection["active"] != true || introspection["tenant_id"] != tenantID || introspection["user_id"] != userID {
		t.Fatalf("introspection = %#v, want tenant %s user %s", introspection, tenantID, userID)
	}
	userinfoReq, err := http.NewRequest(http.MethodGet, endpoint+"/userinfo", nil)
	if err != nil {
		t.Fatal(err)
	}
	userinfoReq.Header.Set("Authorization", "Bearer "+access)
	userinfoResp, err := http.DefaultClient.Do(userinfoReq)
	if err != nil {
		t.Fatal(err)
	}
	defer userinfoResp.Body.Close()
	var userinfo map[string]any
	if userinfoResp.StatusCode != http.StatusOK || json.NewDecoder(userinfoResp.Body).Decode(&userinfo) != nil {
		t.Fatalf("userinfo status %d", userinfoResp.StatusCode)
	}
	if userinfo["sub"] != userID || userinfo["user_id"] != userID || userinfo["tenant_id"] != tenantID {
		t.Fatalf("userinfo = %#v, want tenant %s user %s", userinfo, tenantID, userID)
	}
	if userinfo["tenant_id"] != introspection["tenant_id"] || userinfo["user_id"] != introspection["user_id"] {
		t.Fatalf("userinfo %#v does not match introspection %#v", userinfo, introspection)
	}
}

func authorize(t *testing.T, endpoint string) string {
	t.Helper()
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	query := url.Values{
		"response_type":         {"code"},
		"client_id":             {"test-client"},
		"redirect_uri":          {"http://127.0.0.1:65530/callback"},
		"scope":                 {"openid offline_access mcp:tools"},
		"state":                 {"state"},
		"resource":              {"http://127.0.0.1:8080/mcp"},
		"code_challenge":        {pkceChallenge(verifier)},
		"code_challenge_method": {"S256"},
	}
	resp, err := http.Get(endpoint + "/oauth/authorize?" + query.Encode())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "transaction_id") {
		t.Fatalf("authorize failed: %d %s", resp.StatusCode, body)
	}
	return string(body)
}

func postLogin(t *testing.T, endpoint, page, tenant, username, password string) string {
	t.Helper()
	resp, err := http.PostForm(endpoint+"/oauth/login", url.Values{
		"transaction_id": {formValue(t, page, "transaction_id")},
		"csrf":           {formValue(t, page, "csrf")},
		"tenant":         {tenant},
		"username":       {username},
		"password":       {password},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status %d: %s", resp.StatusCode, body)
	}
	return string(body)
}

func approve(t *testing.T, endpoint, page string) string {
	t.Helper()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.PostForm(endpoint+"/oauth/consent", url.Values{
		"transaction_id": {formValue(t, page, "transaction_id")},
		"csrf":           {formValue(t, page, "csrf")},
		"decision":       {"approve"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	location := resp.Header.Get("Location")
	redirect, err := url.Parse(location)
	if err != nil || redirect.Query().Get("code") == "" {
		t.Fatalf("consent did not return a code: %d %s", resp.StatusCode, location)
	}
	return redirect.Query().Get("code")
}

func postForm(t *testing.T, endpoint string, form url.Values) []byte {
	t.Helper()
	resp, err := http.PostForm(endpoint, form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("post %s status %d: %s", endpoint, resp.StatusCode, body)
	}
	return body
}

func postAuthorized(t *testing.T, endpoint, secret string, form url.Values) map[string]any {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var payload map[string]any
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&payload) != nil {
		t.Fatalf("introspection status %d", resp.StatusCode)
	}
	return payload
}

func formValue(t *testing.T, page, name string) string {
	t.Helper()
	marker := `name="` + name + `" value="`
	start := strings.Index(page, marker)
	if start < 0 {
		t.Fatalf("missing form field %s", name)
	}
	start += len(marker)
	end := strings.Index(page[start:], `"`)
	if end < 0 {
		t.Fatalf("unterminated form field %s", name)
	}
	return page[start : start+end]
}
