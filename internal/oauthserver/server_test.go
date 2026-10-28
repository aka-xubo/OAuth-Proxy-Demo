package oauthserver

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
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
	unknownTenant := failedLogin(t, server, "missing", "demo", "demo")
	injectedUsername := failedLogin(t, server, "acme", "demo' OR 1=1 --", "demo")
	if !strings.Contains(wrongPassword, genericLoginError) || !strings.Contains(unknownUser, genericLoginError) {
		t.Fatal("login failures did not share one generic error")
	}
	for _, page := range []string{body, wrongPassword, unknownUser, unknownTenant, injectedUsername} {
		if !strings.Contains(page, genericLoginError) {
			t.Fatal("invalid credentials did not return the generic login error")
		}
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
	cases := map[string][]Account{
		"duplicate":           {{TenantID: "acme", Username: "demo", Password: "demo"}, {TenantID: "acme", Username: "demo", Password: "other"}},
		"tenant colon":        {{TenantID: "ac:me", Username: "demo", Password: "demo"}},
		"username colon":      {{TenantID: "acme", Username: "de:mo", Password: "demo"}},
		"tenant whitespace":   {{TenantID: "ac me", Username: "demo", Password: "demo"}},
		"username whitespace": {{TenantID: "acme", Username: "de\tmo", Password: "demo"}},
		"empty tenant":        {{Username: "demo", Password: "demo"}},
		"empty username":      {{TenantID: "acme", Password: "demo"}},
		"empty password":      {{TenantID: "acme", Username: "demo"}},
	}
	for name, accounts := range cases {
		t.Run(name, func(t *testing.T) {
			server, err := New(testConfig(t, accounts))
			if err == nil {
				server.Close()
				t.Fatal("invalid bootstrap accounts were accepted")
			}
		})
	}
}

func TestAccountsSurviveRestartWithoutReseeding(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.db")
	server, oauth := newTestServerAt(t, teachingAccounts(), path)
	original := storedHashes(t, oauth)
	if len(original) != 3 || oauth.cfg.Accounts != nil {
		t.Fatal("bootstrap accounts were not seeded or plaintext config was retained")
	}
	for _, item := range teachingAccounts() {
		hash := original[item.TenantID+":"+item.Username]
		if bytes.Equal(hash, []byte(item.Password)) || bcrypt.CompareHashAndPassword(hash, []byte(item.Password)) != nil {
			t.Fatal("stored credential is not a valid bcrypt hash")
		}
	}
	server.Close()
	if err := oauth.Close(); err != nil {
		t.Fatal(err)
	}

	server, oauth = newTestServerAt(t, teachingAccounts(), path)
	assertHashesEqual(t, original, storedHashes(t, oauth))
	loginAndExchange(t, server, "globex", "ops", "ops")
	changed := passwordHash(t, "changed-password")
	execAccounts(t, oauth, "UPDATE accounts SET password_hash = ? WHERE tenant_id = ? AND username = ?", changed, "acme", "demo")
	execAccounts(t, oauth, "INSERT INTO accounts (tenant_id, username, password_hash) VALUES (?, ?, ?)", "zeta", "demo", passwordHash(t, "new-password"))
	execAccounts(t, oauth, "INSERT INTO accounts (tenant_id, username, password_hash) VALUES (?, ?, ?)", "alpha", "reader", passwordHash(t, "reader-password"))
	execAccounts(t, oauth, "DELETE FROM accounts WHERE tenant_id = ? AND username = ?", "globex", "ops")
	updated := storedHashes(t, oauth)
	// Live queries must reflect changes even before restart.
	assertTenantOptions(t, authorizePage(t, server), []string{"acme", "alpha", "globex", "zeta"})
	loginAndExchange(t, server, "acme", "demo", "changed-password")
	server.Close()
	if err := oauth.Close(); err != nil {
		t.Fatal(err)
	}

	server, oauth = newTestServerAt(t, teachingAccounts(), path)
	assertHashesEqual(t, updated, storedHashes(t, oauth))
	assertTenantOptions(t, authorizePage(t, server), []string{"acme", "alpha", "globex", "zeta"})
	acme := loginAndExchange(t, server, "acme", "demo", "changed-password")
	zeta := loginAndExchange(t, server, "zeta", "demo", "new-password")
	if acme.userinfo["sub"] != "acme:demo" || zeta.userinfo["sub"] != "zeta:demo" {
		t.Fatal("persisted accounts lost tenant-scoped identity")
	}
	loginAndExchange(t, server, "globex", "demo", "demo")
	for _, credentials := range [][3]string{{"acme", "demo", "demo"}, {"globex", "ops", "ops"}, {"acme", "demo", "new-password"}, {"zeta", "demo", "changed-password"}} {
		if !strings.Contains(failedLogin(t, server, credentials[0], credentials[1], credentials[2]), genericLoginError) {
			t.Fatal("removed, old, or cross-tenant credential was accepted")
		}
	}
	// An empty initialized database remains empty, even with new bootstrap input.
	execAccounts(t, oauth, "DELETE FROM accounts")
	server.Close()
	oauth.Close()
	server, oauth = newTestServerAt(t, nil, path)
	if len(storedHashes(t, oauth)) != 0 {
		t.Fatal("empty initialized database was reseeded")
	}
	assertTenantOptions(t, authorizePage(t, server), nil)
	if !strings.Contains(failedLogin(t, server, "acme", "demo", "demo"), genericLoginError) {
		t.Fatal("empty database fell back to demo credentials")
	}
	server.Close()
	oauth.Close()
	// Bootstrap validation is only relevant to first initialization.
	_, oauth = newTestServerAt(t, []Account{{TenantID: "invalid:tenant"}}, path)
	if len(storedHashes(t, oauth)) != 0 {
		t.Fatal("reopen applied new bootstrap configuration")
	}
}

func TestInvalidStoredHashReturnsServerError(t *testing.T) {
	server, oauth := newTestServerAt(t, nil, filepath.Join(t.TempDir(), "accounts.db"))
	page := authorizePage(t, server)
	fields := hiddenFields(t, page)
	execAccounts(t, oauth, "UPDATE accounts SET password_hash = ? WHERE tenant_id = ? AND username = ?", []byte("not-a-password-hash"), "acme", "demo")
	response := postForm(t, server.URL+"/oauth/login", url.Values{
		"transaction_id": {fields["transaction_id"]}, "csrf": {fields["csrf"]},
		"tenant": {"acme"}, "username": {"demo"}, "password": {"demo"},
	})
	assertServerError(t, response)
	tx, _, ok := oauth.transaction(fields["transaction_id"], fields["csrf"])
	if !ok || tx.UserID != "" || tx.TenantID != "" {
		t.Fatal("invalid stored credential authenticated a user")
	}
}

func TestDatabaseInitializationFailures(t *testing.T) {
	t.Run("missing parent", func(t *testing.T) {
		cfg := testConfig(t, teachingAccounts())
		cfg.DatabasePath = filepath.Join(t.TempDir(), "missing", "accounts.db")
		if server, err := New(cfg); err == nil {
			server.Close()
			t.Fatal("inaccessible database did not prevent startup")
		}
	})
	t.Run("corrupt database", func(t *testing.T) {
		cfg := testConfig(t, teachingAccounts())
		if err := os.WriteFile(cfg.DatabasePath, []byte("not a SQLite database"), 0600); err != nil {
			t.Fatal(err)
		}
		if server, err := New(cfg); err == nil {
			server.Close()
			t.Fatal("corrupt database did not prevent startup")
		}
	})
	t.Run("seed rollback", func(t *testing.T) {
		cfg := testConfig(t, []Account{{TenantID: "acme", Username: "demo", Password: "demo"}, {TenantID: "globex", Username: "demo", Password: strings.Repeat("x", 73)}})
		if server, err := New(cfg); err == nil {
			server.Close()
			t.Fatal("unhashable password was accepted")
		}
		server, oauth := newTestServerAt(t, teachingAccounts(), cfg.DatabasePath)
		if len(storedHashes(t, oauth)) != 3 {
			t.Fatal("failed seed left partial accounts or initialization marker")
		}
		loginAndExchange(t, server, "globex", "ops", "ops")
	})
}

func TestRequestDatabaseFailuresDoNotAuthenticate(t *testing.T) {
	server, oauth := newTestServerAt(t, teachingAccounts(), filepath.Join(t.TempDir(), "accounts.db"))
	page := authorizePage(t, server)
	fields := hiddenFields(t, page)
	if err := oauth.Close(); err != nil {
		t.Fatal(err)
	}
	response := postForm(t, server.URL+"/oauth/login", url.Values{
		"transaction_id": {fields["transaction_id"]}, "csrf": {fields["csrf"]},
		"tenant": {"acme"}, "username": {"demo"}, "password": {"demo"},
	})
	assertServerError(t, response)
	tx, _, ok := oauth.transaction(fields["transaction_id"], fields["csrf"])
	if !ok || tx.UserID != "" || tx.TenantID != "" {
		t.Fatal("database failure bound a user to the transaction")
	}
	response = postForm(t, server.URL+"/oauth/consent", url.Values{
		"transaction_id": {fields["transaction_id"]}, "csrf": {fields["csrf"]}, "decision": {"approve"},
	})
	assertServerError(t, response)
	response, err := http.Get(server.URL + "/oauth/authorize?" + authorizationQuery().Encode())
	if err != nil {
		t.Fatal(err)
	}
	assertServerError(t, response)
}

func TestAccountQueriesHonorContextAndDummyHash(t *testing.T) {
	_, oauth := newTestServerAt(t, nil, filepath.Join(t.TempDir(), "accounts.db"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := oauth.authenticate(ctx, "acme", "demo", "demo"); err == nil {
		t.Fatal("lookup ignored canceled context")
	}
	if _, err := oauth.accountStore.tenants(ctx); err == nil {
		t.Fatal("tenant listing ignored canceled context")
	}
	if _, ok, err := oauth.authenticate(context.Background(), "missing", "demo", "dummy-password-not-a-real-account"); err != nil || ok {
		t.Fatal("unknown account did not use a valid dummy hash or was authenticated")
	}
}

func TestAccountSchemaConstraints(t *testing.T) {
	_, oauth := newTestServerAt(t, nil, filepath.Join(t.TempDir(), "accounts.db"))
	for _, pair := range [][2]string{{"", "demo"}, {"acme", ""}, {"ac:me", "demo"}, {"acme", "de:mo"}, {"ac me", "demo"}, {"acme", "de\nmo"}, {"acme", "demo"}} {
		if _, err := oauth.accountStore.db.ExecContext(context.Background(), "INSERT INTO accounts (tenant_id, username, password_hash) VALUES (?, ?, ?)", pair[0], pair[1], passwordHash(t, "password")); err == nil {
			t.Fatalf("invalid or duplicate stored account was accepted: %q", pair)
		}
	}
}

func passwordHash(t *testing.T, password string) []byte {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	return hash
}

func execAccounts(t *testing.T, oauth *Server, query string, args ...any) {
	t.Helper()
	if _, err := oauth.accountStore.db.ExecContext(context.Background(), query, args...); err != nil {
		t.Fatal(err)
	}
}

func storedHashes(t *testing.T, oauth *Server) map[string][]byte {
	t.Helper()
	rows, err := oauth.accountStore.db.QueryContext(context.Background(), "SELECT tenant_id, username, password_hash FROM accounts")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	hashes := map[string][]byte{}
	for rows.Next() {
		var tenant, username string
		var hash []byte
		if err := rows.Scan(&tenant, &username, &hash); err != nil {
			t.Fatal(err)
		}
		hashes[tenant+":"+username] = hash
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return hashes
}

func assertHashesEqual(t *testing.T, want, got map[string][]byte) {
	t.Helper()
	if len(want) != len(got) {
		t.Fatal("account count changed on restart")
	}
	for key, hash := range want {
		if !bytes.Equal(hash, got[key]) {
			t.Fatalf("credential changed on restart for %s", key)
		}
	}
}

func assertTenantOptions(t *testing.T, page string, want []string) {
	t.Helper()
	matches := regexp.MustCompile(`<option value="([^"]+)"`).FindAllStringSubmatch(page, -1)
	if len(matches) != len(want) {
		t.Fatalf("tenant dropdown count = %d, want %d", len(matches), len(want))
	}
	for i, tenant := range want {
		if matches[i][1] != tenant {
			t.Fatalf("tenant dropdown = %v, want %v", matches, want)
		}
	}
}

func assertServerError(t *testing.T, response *http.Response) {
	t.Helper()
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusInternalServerError || string(body) != "internal server error\n" {
		t.Fatalf("database failure did not return a generic server error: status %d, body %s", response.StatusCode, body)
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
	server, _ := newTestServerAt(t, accounts, filepath.Join(t.TempDir(), "accounts.db"))
	return server
}

func newTestServerAt(t *testing.T, accounts []Account, path string) (*httptest.Server, *Server) {
	t.Helper()
	handler := http.NewServeMux()
	cfg := testConfig(t, accounts)
	cfg.DatabasePath = path
	oauth, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	oauth.RegisterRoutes(handler)
	server := httptest.NewServer(handler)
	t.Cleanup(func() {
		server.Close()
		if err := oauth.Close(); err != nil {
			t.Error(err)
		}
	})
	return server, oauth
}

func testConfig(t *testing.T, accounts []Account) Config {
	t.Helper()
	return Config{
		Issuer:              "http://127.0.0.1:8081",
		Resource:            "http://127.0.0.1:8080/mcp",
		IntrospectionSecret: "test-introspection-secret",
		Accounts:            accounts,
		DatabasePath:        filepath.Join(t.TempDir(), "accounts.db"),
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
	page := postLogin(t, server, authorizePage(t, server), tenant, username, password)
	if strings.Contains(page, "确认授权范围") {
		t.Fatal("invalid credentials advanced to consent")
	}
	fields := hiddenFields(t, page)
	response := postForm(t, server.URL+"/oauth/consent", url.Values{
		"transaction_id": {fields["transaction_id"]}, "csrf": {fields["csrf"]}, "decision": {"approve"},
	})
	if strings.Contains(readBody(t, response), "确认授权范围") {
		t.Fatal("invalid credentials authenticated the transaction")
	}
	return page
}

func authorizePage(t *testing.T, server *httptest.Server) string {
	t.Helper()
	response, err := http.Get(server.URL + "/oauth/authorize?" + authorizationQuery().Encode())
	if err != nil {
		t.Fatal(err)
	}
	return readBody(t, response)
}

func authorizationQuery() url.Values {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	return url.Values{
		"response_type":         {"code"},
		"client_id":             {"test-client"},
		"redirect_uri":          {"http://127.0.0.1:65530/callback"},
		"scope":                 {"openid profile offline_access mcp:tools"},
		"state":                 {"state-1"},
		"resource":              {"http://127.0.0.1:8080/mcp"},
		"code_challenge":        {pkceChallenge(verifier)},
		"code_challenge_method": {"S256"},
	}
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
