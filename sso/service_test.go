package sso

import (
	"auth-proxy/config"
	"auth-proxy/database"
	"auth-proxy/logging"
	"auth-proxy/models"
	"auth-proxy/types"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func testService(t *testing.T, source ...string) (*Service, *types.User) {
	t.Helper()
	logging.InitLoggers()
	oldDB, oldPaths := database.DB, config.Paths
	t.Setenv("DATABASE_URL", "")
	if len(source) != 0 {
		t.Setenv("DATABASE_URL", source[0])
	}
	t.Setenv("DATABASE_PATH", filepath.Join(t.TempDir(), "test.db"))
	t.Setenv("SESSION_SECRET", strings.Repeat("s", 48))
	config.Paths.RegisterEnabled = true
	database.InitDB()
	t.Cleanup(func() { database.CloseDB(); database.DB, config.Paths = oldDB, oldPaths })
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "signing.pem")
	if err = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSO_SIGNING_KEY_FILE", path)
	c := &config.SSOConfig{Issuer: "https://auth.example.com", TrustedGatewayCIDRs: []string{"127.0.0.1/32"}, Applications: []config.Application{
		{ID: "app-a", Origin: "https://app-a.example.com", RedirectURI: "https://app-a.example.com/_auth/callback", Roles: []string{"user", "admin"}},
		{ID: "app-b", Origin: "https://app-b.other.net", RedirectURI: "https://app-b.other.net/_auth/callback", Roles: []string{"user", "admin"}},
	}}
	c.WebAuthn.RPID, c.WebAuthn.Origins = "auth.example.com", []string{c.Issuer}
	user, err := models.CreatePasskeyUser("alice", "user")
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(c, func(username, password, ip string) (*types.User, error) {
		if username != "alice" || password != "correct" {
			return nil, errInvalid
		}
		return models.GetUserByID(user.ID)
	}, &types.RateLimiter{Requests: make(map[string][]int64), Max: 1000, Window: time.Minute}, &types.RateLimiter{Requests: make(map[string][]int64), Max: 1000, Window: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	return s, user
}

func request(s *Service, method, path string, cookies []*http.Cookie, headers map[string]string, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://auth.example.com"+path, strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:12345"
	for _, c := range cookies {
		r.AddCookie(c)
	}
	for key, value := range headers {
		r.Header.Set(key, value)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func appHeaders(s *Service, app string) map[string]string {
	u, _ := url.Parse(s.client(app).Origin)
	return map[string]string{"X-Auth-App-ID": app, "X-Original-Host": u.Host, "X-Original-Method": "GET", "X-Original-URI": "/deep/link?q=hello", "X-Original-Accept": "text/html", "X-Original-Fetch-Mode": "navigate", "X-Original-Fetch-Dest": "document"}
}

func requireCode(t *testing.T, w *httptest.ResponseRecorder, want int) {
	t.Helper()
	if w.Code != want {
		t.Fatalf("status %d, want %d: %s", w.Code, want, w.Body.String())
	}
}

func appLogin(t *testing.T, s *Service, app, ssoRaw string) (*http.Cookie, string, []*http.Cookie) {
	t.Helper()
	headers := appHeaders(s, app)
	start := request(s, "GET", "/gateway/start", nil, headers, "")
	requireCode(t, start, 302)
	location, err := url.Parse(start.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	auth := request(s, "GET", location.RequestURI(), []*http.Cookie{{Name: ssoCookie, Value: ssoRaw}}, nil, "")
	requireCode(t, auth, 302)
	callback, _ := url.Parse(auth.Header().Get("Location"))
	path := "/gateway/callback?" + callback.RawQuery
	result := request(s, "GET", path, start.Result().Cookies(), headers, "")
	requireCode(t, result, 302)
	if result.Header().Get("Location") != s.client(app).Origin+"/deep/link?q=hello" {
		t.Fatal("return path was lost")
	}
	for _, c := range result.Result().Cookies() {
		if c.Name == appCookie {
			return c, path, start.Result().Cookies()
		}
	}
	t.Fatal("missing app session")
	return nil, "", nil
}

func TestCrossDomainSSOConcurrentDevicesAndLogout(t *testing.T) {
	s, user := testService(t)
	device1, err := s.createSSO(user)
	if err != nil {
		t.Fatal(err)
	}
	device2, err := s.createSSO(user)
	if err != nil {
		t.Fatal(err)
	}
	a, callbackPath, binding := appLogin(t, s, "app-a", device1)
	b, _, _ := appLogin(t, s, "app-b", device1)
	other, _, _ := appLogin(t, s, "app-a", device2)
	for _, tc := range []struct {
		app    string
		cookie *http.Cookie
	}{{"app-a", a}, {"app-b", b}, {"app-a", other}} {
		w := request(s, "GET", "/internal/authz", []*http.Cookie{tc.cookie}, appHeaders(s, tc.app), "")
		requireCode(t, w, 204)
		if w.Header().Get("X-Auth-Request-User") != "alice" {
			t.Fatal("missing identity")
		}
		c := tc.cookie
		if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Domain != "" || c.Path != "/" {
			t.Fatalf("unsafe cookie: %+v", c)
		}
	}
	// State and code replay cannot create a second app session.
	requireCode(t, request(s, "GET", callbackPath, binding, appHeaders(s, "app-a"), ""), 400)
	// An app-a credential cannot authorize app-b, even with the same user.
	requireCode(t, request(s, "GET", "/internal/authz", []*http.Cookie{a}, appHeaders(s, "app-b"), ""), 401)
	logoutHeaders := appHeaders(s, "app-a")
	logoutHeaders["X-Original-Origin"], logoutHeaders["X-Original-Method"] = s.client("app-a").Origin, "POST"
	requireCode(t, request(s, "POST", "/gateway/logout", []*http.Cookie{a}, logoutHeaders, ""), 204)
	requireCode(t, request(s, "GET", "/internal/authz", []*http.Cookie{a}, appHeaders(s, "app-a"), ""), 401)
	requireCode(t, request(s, "GET", "/internal/authz", []*http.Cookie{b}, appHeaders(s, "app-b"), ""), 204)
	// Signing out device 1 revokes its app-b session, but device 2 stays live.
	requireCode(t, request(s, "POST", "/sso/logout", []*http.Cookie{{Name: ssoCookie, Value: device1}}, map[string]string{"Origin": s.config.Issuer}, ""), 204)
	requireCode(t, request(s, "GET", "/internal/authz", []*http.Cookie{b}, appHeaders(s, "app-b"), ""), 401)
	requireCode(t, request(s, "GET", "/internal/authz", []*http.Cookie{other}, appHeaders(s, "app-a"), ""), 204)
}

func TestGatewayCSRFAndNavigationPolicy(t *testing.T) {
	s, user := testService(t)
	raw, err := s.createSSO(user)
	if err != nil {
		t.Fatal(err)
	}
	cookie, _, _ := appLogin(t, s, "app-a", raw)
	for _, tc := range []struct {
		method, origin, mode, site, upgrade string
		want                                int
	}{
		{"POST", s.client("app-a").Origin, "cors", "same-origin", "", 204},
		{"POST", "https://evil.example", "cors", "cross-site", "", 403},
		{"POST", "", "cors", "", "", 403},
		{"GET", s.client("app-a").Origin, "websocket", "same-origin", "websocket", 204},
		{"GET", "", "websocket", "", "websocket", 403},
		{"GET", "https://evil.example", "websocket", "cross-site", "websocket", 403},
		{"GET", "", "cors", "same-site", "", 403},
		{"GET", "", "navigate", "cross-site", "", 204},
	} {
		h := appHeaders(s, "app-a")
		h["X-Original-Method"], h["X-Original-Origin"], h["X-Original-Fetch-Mode"], h["X-Original-Fetch-Site"], h["X-Original-Upgrade"] = tc.method, tc.origin, tc.mode, tc.site, tc.upgrade
		requireCode(t, request(s, "GET", "/internal/authz", []*http.Cookie{cookie}, h, ""), tc.want)
		if tc.method != "GET" || tc.mode != "navigate" {
			requireCode(t, request(s, "GET", "/gateway/start", nil, h, ""), 401)
		}
	}
	for _, path := range []string{"//evil.example/", "/%2f/evil.example", "/%5cevil.example", "https://evil.example/", "/_auth/callback"} {
		h := appHeaders(s, "app-a")
		h["X-Original-URI"] = path
		requireCode(t, request(s, "GET", "/gateway/start", nil, h, ""), 400)
	}
	h := appHeaders(s, "app-a")
	h["X-Original-Accept"] = "application/json"
	requireCode(t, request(s, "GET", "/gateway/start", nil, h, ""), 401)
	h = appHeaders(s, "app-a")
	h["X-Original-URI"] = "/api/items"
	requireCode(t, request(s, "GET", "/gateway/start", nil, h, ""), 401)
	h = appHeaders(s, "app-a")
	h["X-Original-Host"] = "app-b.other.net"
	requireCode(t, request(s, "GET", "/internal/authz", []*http.Cookie{cookie}, h, ""), 403)
}

func TestGatewayTrustBoundaryAndCookieFiltering(t *testing.T) {
	s, user := testService(t)
	raw, err := s.createSSO(user)
	if err != nil {
		t.Fatal(err)
	}
	cookie, _, _ := appLogin(t, s, "app-a", raw)
	w := request(s, "GET", "/internal/authz", []*http.Cookie{cookie, {Name: "application", Value: "retained"}, {Name: ssoCookie, Value: "secret"}, {Name: "__Host-sso_flow_test", Value: "binding"}, {Name: "auth_token", Value: "legacy"}}, appHeaders(s, "app-a"), "")
	requireCode(t, w, 204)
	if w.Header().Get("X-Auth-Request-Cookie") != "application=retained" {
		t.Fatal("gateway credentials leaked upstream")
	}
	r := httptest.NewRequest("GET", s.config.Issuer+"/internal/authz", nil)
	r.RemoteAddr = "192.0.2.2:1000"
	r.Header.Set("X-Forwarded-For", "127.0.0.1")
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	requireCode(t, w, 403)
	r = httptest.NewRequest("GET", "https://evil.example/oauth2/jwks", nil)
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	requireCode(t, w, 421)
	// Ambiguous cookie headers cannot smuggle a second credential.
	requireCode(t, request(s, "GET", "/internal/authz", []*http.Cookie{cookie, cookie}, appHeaders(s, "app-a"), ""), 401)
}

func makeCode(t *testing.T, s *Service, user *types.User, app, verifier string) string {
	t.Helper()
	raw, err := s.createSSO(user)
	if err != nil {
		t.Fatal(err)
	}
	q := url.Values{"client_id": {app}, "redirect_uri": {s.client(app).RedirectURI}, "response_type": {"code"}, "scope": {"openid profile"}, "state": {randomToken()}, "nonce": {randomToken()}, "code_challenge": {pkce(verifier)}, "code_challenge_method": {"S256"}}
	w := request(s, "GET", "/oauth2/authorize?"+q.Encode(), []*http.Cookie{{Name: ssoCookie, Value: raw}}, nil, "")
	requireCode(t, w, 302)
	u, _ := url.Parse(w.Header().Get("Location"))
	return u.Query().Get("code")
}

func TestOIDCPKCEClientBindingAndSingleUse(t *testing.T) {
	s, user := testService(t)
	verifier := randomToken()
	code := makeCode(t, s, user, "app-a", verifier)
	values := url.Values{"grant_type": {"authorization_code"}, "client_id": {"app-a"}, "code": {code}, "redirect_uri": {s.client("app-a").RedirectURI}, "code_verifier": {verifier}}
	w := request(s, "POST", "/oauth2/token", nil, map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, values.Encode())
	requireCode(t, w, 200)
	var tokens tokenResponse
	if err := json.Unmarshal(w.Body.Bytes(), &tokens); err != nil {
		t.Fatal(err)
	}
	if tokens.TokenType != "Bearer" || tokens.ExpiresIn != 300 || tokens.IDToken == "" || tokens.AccessToken == "" {
		t.Fatal("incomplete OIDC token response")
	}
	requireCode(t, request(s, "POST", "/oauth2/token", nil, map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, values.Encode()), 400)
	requireCode(t, request(s, "GET", "/oauth2/userinfo", nil, map[string]string{"Authorization": "Bearer " + tokens.AccessToken}, ""), 200)
	requireCode(t, request(s, "GET", "/oauth2/userinfo", nil, map[string]string{"Authorization": "Bearer " + tokens.IDToken}, ""), 401)
	for _, wrong := range []struct{ app, verifier string }{{"app-b", verifier}, {"app-a", randomToken()}} {
		c := makeCode(t, s, user, "app-a", verifier)
		if _, _, err := s.exchange(s.client(wrong.app), c, s.client(wrong.app).RedirectURI, wrong.verifier); err == nil {
			t.Fatal("wrong client or PKCE accepted")
		}
	}
	// Race the same code through the core token exchange: one winner.
	code = makeCode(t, s, user, "app-a", verifier)
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := s.exchange(s.client("app-a"), code, s.client("app-a").RedirectURI, verifier)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("code consumed %d times", winners)
	}
}

func TestOIDCRejectsRedirectAndClaimTampering(t *testing.T) {
	s, user := testService(t)
	for _, redirect := range []string{"https://evil.example/_auth/callback", s.client("app-a").RedirectURI + "/", s.client("app-a").RedirectURI + "?x=1"} {
		q := url.Values{"client_id": {"app-a"}, "redirect_uri": {redirect}, "response_type": {"code"}, "scope": {"openid"}, "state": {"x"}, "nonce": {"y"}, "code_challenge": {pkce(randomToken())}, "code_challenge_method": {"S256"}}
		requireCode(t, request(s, "GET", "/oauth2/authorize?"+q.Encode(), nil, nil, ""), 400)
	}
	verifier := randomToken()
	code := makeCode(t, s, user, "app-a", verifier)
	tokens, c, err := s.exchange(s.client("app-a"), code, s.client("app-a").RedirectURI, verifier)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.validateIDToken(tokens.IDToken, "app-a", c.Nonce); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ raw, audience, nonce string }{{tokens.IDToken, "app-b", c.Nonce}, {tokens.IDToken, "app-a", "wrong"}, {tokens.IDToken + "x", "app-a", c.Nonce}, {tokens.AccessToken, "app-a", c.Nonce}} {
		if _, err = s.validateIDToken(test.raw, test.audience, test.nonce); err == nil {
			t.Fatal("invalid ID token accepted")
		}
	}
}

func TestRolesCredentialVersionAndDatabaseOutageFailClosed(t *testing.T) {
	s, user := testService(t)
	raw, err := s.createSSO(user)
	if err != nil {
		t.Fatal(err)
	}
	cookie, _, _ := appLogin(t, s, "app-a", raw)
	s.client("app-a").Roles = []string{"admin"}
	requireCode(t, request(s, "GET", "/internal/authz", []*http.Cookie{cookie}, appHeaders(s, "app-a"), ""), 403)
	s.client("app-a").Roles = []string{"user"}
	if _, err = database.DB.Exec("UPDATE users SET credentials_version=credentials_version+1 WHERE id=?", user.ID); err != nil {
		t.Fatal(err)
	}
	requireCode(t, request(s, "GET", "/internal/authz", []*http.Cookie{cookie}, appHeaders(s, "app-a"), ""), 401)
	user, err = models.GetUserByID(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = s.createSSO(user)
	if err != nil {
		t.Fatal(err)
	}
	cookie, _, _ = appLogin(t, s, "app-a", raw)
	if err = database.DB.Close(); err != nil {
		t.Fatal(err)
	}
	requireCode(t, request(s, "GET", "/internal/authz", []*http.Cookie{cookie}, appHeaders(s, "app-a"), ""), 503)
}

func TestUntrustedOriginsCannotLoginRegisterOrLogout(t *testing.T) {
	s, _ := testService(t)
	for _, path := range []string{"/sso/password", "/sso/logout", "/webauthn/login/begin", "/webauthn/login/finish", "/webauthn/register/begin", "/webauthn/register/finish"} {
		for _, origin := range []string{"", "https://evil.example", "https://app-a.example.com"} {
			requireCode(t, request(s, "POST", path, nil, map[string]string{"Origin": origin}, "{}"), 403)
		}
	}
	// Correct Origin still cannot manufacture a passkey finish without a
	// browser-bound server-side challenge.
	requireCode(t, request(s, "POST", "/webauthn/login/finish", nil, map[string]string{"Origin": s.config.Issuer}, "{}"), 400)
	requireCode(t, request(s, "POST", "/webauthn/register/finish", nil, map[string]string{"Origin": s.config.Issuer}, "{}"), 400)
}

func TestProtocolSecretsAreNotStoredInPlaintext(t *testing.T) {
	s, user := testService(t)
	raw, err := s.createSSO(user)
	if err != nil {
		t.Fatal(err)
	}
	var stored string
	if err = database.DB.QueryRow("SELECT token_hash FROM sso_sessions").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == raw || stored != database.TokenHash(raw) {
		t.Fatal("raw session persisted")
	}
	state, verifier := randomToken(), randomToken()
	if err = s.putFlow("gateway", state, gatewayFlow{Verifier: verifier}); err != nil {
		t.Fatal(err)
	}
	if err = database.DB.QueryRow("SELECT payload FROM oauth_transactions WHERE token_hash=?", database.TokenHash(state)).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored, verifier) {
		t.Fatal("PKCE verifier persisted in plaintext")
	}
	var decoded gatewayFlow
	if err = s.takeRecord("oauth_transactions", "gateway", state, &decoded); err != nil || decoded.Verifier != verifier {
		t.Fatalf("encrypted flow round trip: %v", err)
	}
	// Ciphertext is authenticated against its record ID and purpose.
	sealed, err := s.seal(map[string]string{"secret": "value"}, "purpose-a")
	if err != nil {
		t.Fatal(err)
	}
	var data map[string]string
	if err = s.open(sealed, &data, "purpose-b"); err == nil {
		t.Fatal("ciphertext accepted for another purpose")
	}
}

func TestPasswordSSOLoginAndPublicMetadata(t *testing.T) {
	s, _ := testService(t)
	w := request(s, "POST", "/sso/password", nil, map[string]string{"Origin": s.config.Issuer}, `{"username":"alice","password":"correct","flow":""}`)
	requireCode(t, w, 200)
	if len(w.Result().Cookies()) != 1 || w.Result().Cookies()[0].Name != ssoCookie {
		t.Fatal("SSO password login did not issue the host-only SSO credential")
	}
	for _, path := range []string{"/.well-known/openid-configuration", "/oauth2/jwks", "/sso/login", "/sso/assets/passkeys.js", "/sso/assets/style.css"} {
		requireCode(t, request(s, "GET", path, nil, nil, ""), 200)
	}
	requireCode(t, request(s, "POST", "/sso/password", nil, map[string]string{"Origin": s.config.Issuer}, `{"username":"alice","password":"wrong"}`), 401)
}

func TestExpiredRecordsAndCallbackBrowserBinding(t *testing.T) {
	s, user := testService(t)
	raw, err := s.createSSO(user)
	if err != nil {
		t.Fatal(err)
	}
	h := appHeaders(s, "app-a")
	start := request(s, "GET", "/gateway/start", nil, h, "")
	requireCode(t, start, 302)
	u, _ := url.Parse(start.Header().Get("Location"))
	auth := request(s, "GET", u.RequestURI(), []*http.Cookie{{Name: ssoCookie, Value: raw}}, nil, "")
	requireCode(t, auth, 302)
	u, _ = url.Parse(auth.Header().Get("Location"))
	path := "/gateway/callback?" + u.RawQuery
	requireCode(t, request(s, "GET", path, nil, h, ""), 400)
	// A different app's browser binding is insufficient.
	requireCode(t, request(s, "GET", path, start.Result().Cookies(), appHeaders(s, "app-b"), ""), 400)
	verifier := randomToken()
	code := makeCode(t, s, user, "app-a", verifier)
	if _, err = database.DB.Exec("UPDATE authorization_codes SET expires_at=0 WHERE token_hash=?", database.TokenHash(code)); err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.exchange(s.client("app-a"), code, s.client("app-a").RedirectURI, verifier); err == nil {
		t.Fatal("expired code accepted")
	}
	if err = Cleanup(); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = database.DB.QueryRow("SELECT COUNT(*) FROM authorization_codes WHERE token_hash=?", database.TokenHash(code)).Scan(&count); err != nil || count != 0 {
		t.Fatal(fmt.Sprint("expired code retained: ", err))
	}
}

func TestReauthenticationRevokesPreviousSSOAndLinkedApplications(t *testing.T) {
	s, user := testService(t)
	old, err := s.createSSO(user)
	if err != nil {
		t.Fatal(err)
	}
	app, _, _ := appLogin(t, s, "app-a", old)
	login := request(s, "POST", "/sso/password", []*http.Cookie{{Name: ssoCookie, Value: old}}, map[string]string{"Origin": s.config.Issuer}, `{"username":"alice","password":"correct"}`)
	requireCode(t, login, 200)
	requireCode(t, request(s, "GET", "/internal/authz", []*http.Cookie{app}, appHeaders(s, "app-a"), ""), 401)
	if _, _, err = s.lookupSSO(old); err == nil {
		t.Fatal("old SSO session survived rotation")
	}
	current := login.Result().Cookies()[0]
	app, _, _ = appLogin(t, s, "app-a", current.Value)
	requireCode(t, request(s, "POST", "/sso/logout", []*http.Cookie{current}, map[string]string{"Origin": s.config.Issuer}, ""), 204)
	requireCode(t, request(s, "GET", "/internal/authz", []*http.Cookie{app}, appHeaders(s, "app-a"), ""), 401)
}

func TestPasswordChangesRevokeLegacyAndSSOCredentials(t *testing.T) {
	s, user := testService(t)
	raw, err := s.createSSO(user)
	if err != nil {
		t.Fatal(err)
	}
	app, _, _ := appLogin(t, s, "app-a", raw)
	legacy, err := models.CreateAuthToken(user.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	refresh, err := models.CreateRefreshToken(user.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err = models.UpdateUserPassword(user.ID, "replacement-password-hash"); err != nil {
		t.Fatal(err)
	}
	updated, err := models.GetUserByID(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.CredentialsVersion != user.CredentialsVersion+1 || updated.PasswordHash != "replacement-password-hash" {
		t.Fatal("credential change did not increment version")
	}
	if u, err := models.GetUserByToken(legacy.Token); err != nil || u != nil {
		t.Fatal("legacy browser session survived password change")
	}
	if v, err := models.GetRefreshTokenByToken(refresh.Token); err != nil || v != nil {
		t.Fatal("refresh credential survived password change")
	}
	requireCode(t, request(s, "GET", "/internal/authz", []*http.Cookie{app}, appHeaders(s, "app-a"), ""), 401)
}

func TestAuthorizationAndGatewayChecksUseSeparateRatePolicies(t *testing.T) {
	s, user := testService(t)
	raw, err := s.createSSO(user)
	if err != nil {
		t.Fatal(err)
	}
	app, _, _ := appLogin(t, s, "app-a", raw)
	s.handler = s.routes(&types.RateLimiter{Requests: make(map[string][]int64), Max: 1, Window: time.Minute})
	for range 3 {
		requireCode(t, request(s, "GET", "/internal/authz", []*http.Cookie{app}, appHeaders(s, "app-a"), ""), 204)
	}
	requireCode(t, request(s, "GET", "/oauth2/authorize", nil, nil, ""), 400)
	requireCode(t, request(s, "GET", "/oauth2/authorize", nil, nil, ""), 429)
	// Exhausting login attempts must not disable established app sessions.
	requireCode(t, request(s, "GET", "/internal/authz", []*http.Cookie{app}, appHeaders(s, "app-a"), ""), 204)
}

// Run only against disposable databases, using tests/sso-sql.sh. The same
// gateway/code/session paths used by the browser tests run against each driver.
func TestSSOSQLBackend(t *testing.T) {
	source := os.Getenv("SSO_TEST_DATABASE_URL")
	if source == "" {
		t.Skip("set SSO_TEST_DATABASE_URL to a disposable database")
	}
	s, user := testService(t, source)
	raw, err := s.createSSO(user)
	if err != nil {
		t.Fatal(err)
	}
	a, _, _ := appLogin(t, s, "app-a", raw)
	b, _, _ := appLogin(t, s, "app-b", raw)
	for _, test := range []struct {
		app    string
		cookie *http.Cookie
	}{{"app-a", a}, {"app-b", b}} {
		requireCode(t, request(s, "GET", "/internal/authz", []*http.Cookie{test.cookie}, appHeaders(s, test.app), ""), 204)
	}
	legacy, err := models.CreateAuthToken(user.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err = models.UpdateUserPassword(user.ID, "persisted-password-hash"); err != nil {
		t.Fatal(err)
	}
	if err = database.MigrateIdentity(); err != nil {
		t.Fatal(err)
	}
	updated, err := models.GetUserByID(user.ID)
	if err != nil || updated == nil || updated.PasswordHash != "persisted-password-hash" {
		t.Fatalf("credential migration round trip: %v", err)
	}
	if u, err := models.GetUserByToken(legacy.Token); err != nil || u != nil {
		t.Fatal("legacy session survived password change")
	}
	for _, test := range []struct {
		app    string
		cookie *http.Cookie
	}{{"app-a", a}, {"app-b", b}} {
		requireCode(t, request(s, "GET", "/internal/authz", []*http.Cookie{test.cookie}, appHeaders(s, test.app), ""), 401)
	}
	if err = Cleanup(); err != nil {
		t.Fatal(err)
	}
}

func TestConfidentialClientRequiresBasicAuthenticationAndPKCE(t *testing.T) {
	s, user := testService(t)
	a := s.client("app-a")
	a.ClientSecretEnv = "TEST_OIDC_SECRET"
	secret := strings.Repeat("s", 40) + "+:/&"
	t.Setenv(a.ClientSecretEnv, secret)
	verifier := randomToken()
	code := makeCode(t, s, user, a.ID, verifier)
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {a.ID}, "redirect_uri": {a.RedirectURI}, "code": {code}, "code_verifier": {verifier}}
	headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	requireCode(t, request(s, "POST", "/oauth2/token", nil, headers, form.Encode()), 401)
	headers["Authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte(a.ID+":wrong"))
	requireCode(t, request(s, "POST", "/oauth2/token", nil, headers, form.Encode()), 401)
	headers["Authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(a.ID)+":"+url.QueryEscape(secret)))
	requireCode(t, request(s, "POST", "/oauth2/token", nil, headers, form.Encode()), 200)
}

func TestRegistrationKeepsNewAccountsSeparateFromCredentialManagement(t *testing.T) {
	s, user := testService(t)
	raw, err := s.createSSO(user)
	if err != nil {
		t.Fatal(err)
	}
	cookies := []*http.Cookie{{Name: ssoCookie, Value: raw}}
	w := request(s, "GET", "/sso/login", cookies, nil, "")
	requireCode(t, w, 200)
	if strings.Contains(w.Body.String(), `id="passkey-register"`) {
		t.Fatal("new-account registration shown inside an existing account")
	}
	requireCode(t, request(s, "POST", "/webauthn/register/begin", cookies, map[string]string{"Origin": s.config.Issuer}, `{"username":"another-user"}`), 400)
	config.Paths.RegisterEnabled = false
	requireCode(t, request(s, "POST", "/webauthn/register/begin", nil, map[string]string{"Origin": s.config.Issuer}, `{"username":"another-user"}`), 403)
}

func TestPasskeyRegistrationAlsoHonorsAccountCreationLimits(t *testing.T) {
	s, _ := testService(t)
	s.registrationLimiter.Max = 1
	headers := map[string]string{"Origin": s.config.Issuer}
	begin := request(s, "POST", "/webauthn/register/begin", nil, headers, `{"username":"new-user"}`)
	requireCode(t, begin, 200)
	requireCode(t, request(s, "POST", "/webauthn/register/begin", nil, headers, `{"username":"other-user"}`), 429)
	// Completing the already-counted ceremony must still reach verification.
	requireCode(t, request(s, "POST", "/webauthn/register/finish", begin.Result().Cookies(), headers, `{}`), 400)
}
