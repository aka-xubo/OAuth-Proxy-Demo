package oauthserver

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

func TestTenantLoginBindsTokenToSelectedAccount(t *testing.T) {
	server := newTestServer(t, teachingAccounts())
	defer server.Close()

	acme := loginAndExchange(t, server, "acme", "demo", "demo")
	if acme.introspection["tenant_id"] != "acme" || acme.introspection["user_id"] != "acme:demo" {
		t.Fatalf("acme introspection = %#v", acme.introspection)
	}
	if acme.userinfo["sub"] != "acme:demo" || acme.userinfo["user_id"] != acme.introspection["user_id"] || acme.userinfo["tenant_id"] != acme.introspection["tenant_id"] {
		t.Fatalf("userinfo = %#v, introspection = %#v", acme.userinfo, acme.introspection)
	}

	globex := loginAndExchange(t, server, "globex", "demo", "demo")
	if globex.introspection["tenant_id"] != "globex" || globex.introspection["user_id"] != "globex:demo" {
		t.Fatalf("globex introspection = %#v", globex.introspection)
	}
	if globex.introspection["user_id"] == acme.introspection["user_id"] {
		t.Fatal("globex demo was issued as the acme account")
	}

	refreshed := refresh(t, server, globex.refreshToken)
	if refreshed["tenant_id"] != "globex" || refreshed["user_id"] != "globex:demo" {
		t.Fatalf("refresh did not preserve identity: %#v", refreshed)
	}
}

func TestCrossTenantPasswordDoesNotAuthenticate(t *testing.T) {
	server := newTestServer(t, teachingAccounts())
	defer server.Close()

	body := failedLogin(t, server, "acme", "ops", "ops")
	if !strings.Contains(body, genericLoginError) {
		t.Fatalf("expected generic login error, got %s", body)
	}
	if strings.Contains(body, "确认授权范围") {
		t.Fatal("cross-tenant credentials were accepted")
	}
	wrongPassword := failedLogin(t, server, "acme", "demo", "ops")
	unknownUser := failedLogin(t, server, "acme", "missing", "demo")
	if !strings.Contains(wrongPassword, genericLoginError) || !strings.Contains(unknownUser, genericLoginError) {
		t.Fatal("login failures did not share one generic error")
	}
	for _, page := range []string{body, wrongPassword, unknownUser} {
		if strings.Contains(page, "密码错误") || strings.Contains(page, "用户名错误") || strings.Contains(page, "租户不存在") {
			t.Fatalf("login error revealed which field failed: %s", page)
		}
	}
}

func TestLoginFormRequiresTenantAndPrefillsTeachingAccount(t *testing.T) {
	server := newTestServer(t, teachingAccounts())
	defer server.Close()

	page := authorizePage(t, server)
	if !strings.Contains(page, `<label for="tenant">租户</label>`) {
		t.Fatalf("login form missing tenant field: %s", page)
	}
	if !strings.Contains(page, `<option value="acme" selected>acme</option>`) {
		t.Fatalf("tenant selection did not default to acme: %s", page)
	}
	if !strings.Contains(page, `<option value="globex">globex</option>`) {
		t.Fatalf("login form missing globex tenant: %s", page)
	}
	if !strings.Contains(page, `id="username" name="username" autocomplete="username" required value="demo"`) || !strings.Contains(page, `id="password" name="password" type="password" autocomplete="current-password" required value="demo"`) {
		t.Fatalf("username and password were not prefilled: %s", page)
	}
}

func TestEmptyAccountConfigSeedsDemoTenants(t *testing.T) {
	server := newTestServer(t, nil)
	defer server.Close()

	acme := loginAndExchange(t, server, "acme", "demo", "demo")
	globex := loginAndExchange(t, server, "globex", "demo", "demo")
	if acme.introspection["user_id"] != "acme:demo" || globex.introspection["user_id"] != "globex:demo" {
		t.Fatalf("default accounts = %#v %#v", acme.introspection, globex.introspection)
	}
	if strings.Contains(failedLogin(t, server, "globex", "ops", "ops"), "确认授权范围") {
		t.Fatal("default seed included the ops account")
	}
}

func TestRejectsInvalidAccounts(t *testing.T) {
	_, err := New(testConfig([]Account{{TenantID: "acme", Username: "demo", Password: "demo"}, {TenantID: "acme", Username: "demo", Password: "other"}}))
	if err == nil {
		t.Fatal("duplicate account was accepted")
	}
	_, err = New(testConfig([]Account{{TenantID: "ac:me", Username: "demo", Password: "demo"}}))
	if err == nil {
		t.Fatal("colon in tenant id was accepted")
	}
}

func teachingAccounts() []Account {
	return []Account{
		{TenantID: "acme", Username: "demo", Password: "demo"},
		{TenantID: "globex", Username: "demo", Password: "demo"},
		{TenantID: "globex", Username: "ops", Password: "ops"},
	}
}

type issuedIdentity struct {
	accessToken   string
	refreshToken  string
	introspection map[string]any
	userinfo      map[string]string
}

func newTestServer(t *testing.T, accounts []Account) *httptest.Server {
	t.Helper()
	handler := http.NewServeMux()
	oauth, err := New(testConfig(accounts))
	if err != nil {
		t.Fatal(err)
	}
	oauth.RegisterRoutes(handler)
	return httptest.NewServer(handler)
}

func testConfig(accounts []Account) Config {
	return Config{
		Issuer:              "http://127.0.0.1:8081",
		Resource:            "http://127.0.0.1:8080/mcp",
		IntrospectionSecret: "test-introspection-secret",
		Accounts:            accounts,
		StaticClients: []StaticClient{{
			ID:           "test-client",
			Name:         "Test Client",
			RedirectURIs: []string{"http://127.0.0.1:65530/callback"},
		}},
	}
}

func loginAndExchange(t *testing.T, server *httptest.Server, tenant, username, password string) issuedIdentity {
	t.Helper()
	page := authorizePage(t, server)
	consent := postLogin(t, server, page, tenant, username, password)
	if strings.Contains(consent, genericLoginError) {
		t.Fatalf("login failed for %s/%s", tenant, username)
	}
	code := approve(t, server, consent)
	token := exchangeCode(t, server, code)
	access, _ := token["access_token"].(string)
	refreshToken, _ := token["refresh_token"].(string)
	if access == "" || refreshToken == "" {
		t.Fatalf("missing tokens: %#v", token)
	}
	return issuedIdentity{
		accessToken:   access,
		refreshToken:  refreshToken,
		introspection: introspect(t, server, access),
		userinfo:      userinfo(t, server, access),
	}
}

func failedLogin(t *testing.T, server *httptest.Server, tenant, username, password string) string {
	t.Helper()
	return postLogin(t, server, authorizePage(t, server), tenant, username, password)
}

func authorizePage(t *testing.T, server *httptest.Server) string {
	t.Helper()
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	query := url.Values{
		"response_type":         {"code"},
		"client_id":             {"test-client"},
		"redirect_uri":          {"http://127.0.0.1:65530/callback"},
		"scope":                 {"openid profile offline_access mcp:tools"},
		"state":                 {"state-1"},
		"resource":              {"http://127.0.0.1:8080/mcp"},
		"code_challenge":        {pkceChallenge(verifier)},
		"code_challenge_method": {"S256"},
	}
	response, err := http.Get(server.URL + "/oauth/authorize?" + query.Encode())
	if err != nil {
		t.Fatal(err)
	}
	return readBody(t, response)
}

func postLogin(t *testing.T, server *httptest.Server, page, tenant, username, password string) string {
	t.Helper()
	fields := hiddenFields(t, page)
	response := postForm(t, server.URL+"/oauth/login", url.Values{
		"transaction_id": {fields["transaction_id"]},
		"csrf":           {fields["csrf"]},
		"tenant":         {tenant},
		"username":       {username},
		"password":       {password},
	})
	return readBody(t, response)
}

func approve(t *testing.T, server *httptest.Server, page string) string {
	t.Helper()
	fields := hiddenFields(t, page)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequest(http.MethodPost, server.URL+"/oauth/consent", strings.NewReader(url.Values{
		"transaction_id": {fields["transaction_id"]},
		"csrf":           {fields["csrf"]},
		"decision":       {"approve"},
	}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("consent status %d: %s", response.StatusCode, body)
	}
	location, err := url.Parse(response.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	code := location.Query().Get("code")
	if code == "" {
		t.Fatalf("missing authorization code: %s", response.Header.Get("Location"))
	}
	return code
}

func exchangeCode(t *testing.T, server *httptest.Server, code string) map[string]any {
	t.Helper()
	response := postForm(t, server.URL+"/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {"test-client"},
		"redirect_uri":  {"http://127.0.0.1:65530/callback"},
		"code_verifier": {"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"},
		"resource":      {"http://127.0.0.1:8080/mcp"},
	})
	var token map[string]any
	decodeJSON(t, response, &token)
	return token
}

func refresh(t *testing.T, server *httptest.Server, refreshToken string) map[string]any {
	t.Helper()
	response := postForm(t, server.URL+"/oauth/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {"test-client"},
		"resource":      {"http://127.0.0.1:8080/mcp"},
	})
	var token map[string]any
	decodeJSON(t, response, &token)
	access, _ := token["access_token"].(string)
	if access == "" || access == refreshToken {
		t.Fatalf("refresh did not issue an access token: %#v", token)
	}
	return introspect(t, server, access)
}

func introspect(t *testing.T, server *httptest.Server, accessToken string) map[string]any {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, server.URL+"/oauth/introspect", strings.NewReader(url.Values{"token": {accessToken}}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer test-introspection-secret")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	decodeJSON(t, response, &body)
	if body["active"] != true {
		t.Fatalf("token inactive: %#v", body)
	}
	return body
}

func userinfo(t *testing.T, server *httptest.Server, accessToken string) map[string]string {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, server.URL+"/userinfo", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+accessToken)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]string
	decodeJSON(t, response, &body)
	return body
}

func postForm(t *testing.T, endpoint string, form url.Values) *http.Response {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func readBody(t *testing.T, response *http.Response) string {
	t.Helper()
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", response.StatusCode, body)
	}
	return string(body)
}

func decodeJSON(t *testing.T, response *http.Response, target any) {
	t.Helper()
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("status %d: %s", response.StatusCode, body)
	}
	if err := json.NewDecoder(response.Body).Decode(target); err != nil {
		t.Fatal(err)
	}
}

var hiddenFieldPattern = regexp.MustCompile(`name="(transaction_id|csrf)" value="([^"]+)"`)

func hiddenFields(t *testing.T, page string) map[string]string {
	t.Helper()
	fields := map[string]string{}
	for _, match := range hiddenFieldPattern.FindAllStringSubmatch(page, -1) {
		fields[match[1]] = match[2]
	}
	if fields["transaction_id"] == "" || fields["csrf"] == "" {
		t.Fatalf("missing transaction fields: %s", page)
	}
	return fields
}
