package oauthserver

import (
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

func TestTeachingLoginAcceptsOAuthDemoPassword(t *testing.T) {
	const (
		resource    = "http://127.0.0.1:8080/mcp"
		clientID    = "memory-oauth-proxy"
		redirectURI = "http://127.0.0.1:8082/oauth/callback/upstream"
	)
	server, err := New(Config{
		Issuer:   "http://127.0.0.1:8081",
		Resource: resource,
		StaticClients: []StaticClient{{
			ID:           clientID,
			Name:         "Local OAuth Proxy",
			RedirectURIs: []string{redirectURI},
			Scopes:       []string{"openid", "profile", "mcp:tools"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	authorize := "/oauth/authorize?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {"openid profile mcp:tools"},
		"state":                 {"login-state"},
		"resource":              {resource},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}.Encode()

	login := getPage(t, mux, authorize)
	if !strings.Contains(login, `value="demo"`) || !strings.Contains(login, `value="oauth-demo"`) || !strings.Contains(login, "demo / oauth-demo") {
		t.Fatalf("login page does not show teaching account demo / oauth-demo: %s", login)
	}
	transactionID := hiddenValue(t, login, "transaction_id")
	csrf := hiddenValue(t, login, "csrf")

	for _, password := range []string{"admin", "demo"} {
		body := postLogin(t, mux, transactionID, csrf, "demo", password)
		if !strings.Contains(body, "用户名或密码错误") {
			t.Fatalf("password %q did not fail login: %s", password, body)
		}
		if strings.Contains(body, "确认授权范围") {
			t.Fatalf("password %q reached consent", password)
		}
	}

	consent := postLogin(t, mux, transactionID, csrf, "demo", "oauth-demo")
	if !strings.Contains(consent, "确认授权范围") {
		t.Fatalf("oauth-demo did not reach consent: %s", consent)
	}
	if strings.Contains(consent, "用户名或密码错误") {
		t.Fatalf("oauth-demo was rejected: %s", consent)
	}
}

func getPage(t *testing.T, handler http.Handler, target string) string {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, target, nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	response := recorder.Result()
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET %s status %d: %s", target, response.StatusCode, body)
	}
	return string(body)
}

func postLogin(t *testing.T, handler http.Handler, transactionID, csrf, username, password string) string {
	t.Helper()
	form := url.Values{
		"transaction_id": {transactionID},
		"csrf":           {csrf},
		"username":       {username},
		"password":       {password},
	}
	request := httptest.NewRequest(http.MethodPost, "/oauth/login", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	response := recorder.Result()
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("POST /oauth/login status %d: %s", response.StatusCode, body)
	}
	return string(body)
}

func hiddenValue(t *testing.T, body, name string) string {
	t.Helper()
	re := regexp.MustCompile(`name="` + regexp.QuoteMeta(name) + `" value="([^"]+)"`)
	match := re.FindStringSubmatch(body)
	if match == nil {
		t.Fatalf("missing hidden field %s", name)
	}
	return match[1]
}
