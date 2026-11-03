package middleware

import (
	"auth-proxy/config"
	"auth-proxy/database"
	"auth-proxy/logging"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/haturatu/xsrftoken"
)

func setupBrowserSession(t *testing.T) (string, string) {
	t.Helper()
	logging.InitLoggers()
	oldDB := database.DB
	var err error
	database.DB, err = sql.Open("sqlite3", ":memory:")
	if err != nil { t.Fatal(err) }
	database.DB.SetMaxOpenConns(1)
	t.Cleanup(func() {
		_ = database.DB.Close()
		database.DB = oldDB
	})
	for _, stmt := range []string{
		`CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT, role TEXT, is_active BOOLEAN,
			failed_logins INTEGER, last_login_at DATETIME, created_at DATETIME, updated_at DATETIME)`,
		`CREATE TABLE auth_tokens (user_id INTEGER, token TEXT, expires_at DATETIME)`,
	} {
		if _, err := database.DB.Exec(stmt); err != nil { t.Fatal(err) }
	}
	if _, err := database.DB.Exec(`INSERT INTO users (id, username, password_hash, role, is_active,
		failed_logins, created_at, updated_at) VALUES (5, 'alice', '', 'user', 1, 0, ?, ?)`,
		time.Now(), time.Now()); err != nil { t.Fatal(err) }
	const session = "browser-cookie-session"
	if _, err := database.DB.Exec("INSERT INTO auth_tokens (user_id, token, expires_at) VALUES (5, ?, ?)",
		session, time.Now().Add(time.Hour)); err != nil { t.Fatal(err) }
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil { t.Fatal(err) }
	t.Setenv("XSRF_SECRET_KEY", base64.StdEncoding.EncodeToString(secret))
	t.Setenv("COOKIE_SECURE", "false")
	oldPaths := config.Paths
	config.Paths.APIPath = "/api/"
	config.Paths.Login = "/login"
	t.Cleanup(func() { config.Paths = oldPaths })
	return session, xsrftoken.Generate(string(secret), "auth:"+session, "/api/")
}

func TestSessionAPIOriginAndCSRF(t *testing.T) {
	session, token := setupBrowserSession(t)
	h := APIAuth("session", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Context().Value("invalid") != nil { t.Error("unreachable") }
		w.WriteHeader(http.StatusNoContent)
	}))
	check := func(method, origin, fetchSite, authorization, csrf string, want int) {
		t.Helper()
		req := httptest.NewRequest(method, "http://192.168.10.5:8080/api/events", nil)
		req.RemoteAddr = "192.168.20.14:5678"
		req.AddCookie(&http.Cookie{Name: "auth_token", Value: session})
		if origin != "" { req.Header.Set("Origin", origin) }
		if fetchSite != "" { req.Header.Set("Sec-Fetch-Site", fetchSite) }
		if authorization != "" { req.Header.Set("Authorization", authorization) }
		if csrf != "" { req.Header.Set("X-XSRF-Token", csrf) }
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != want { t.Errorf("%s %s %s auth=%t csrf=%t: got %d want %d: %s",
			method, origin, fetchSite, authorization != "", csrf != "", rec.Code, want, rec.Body.String()) }
	}
	check("GET", "", "same-origin", "", "", 204)
	check("GET", "http://192.168.10.5:8080", "same-origin", "", "", 204)
	check("GET", "http://evil.example", "cross-site", "", "", 403)
	check("GET", "", "same-site", "", "", 403)
	check("POST", "http://192.168.10.5:8080", "same-origin", "", "", 403)
	check("POST", "http://192.168.10.5:8080", "same-origin", "", token, 204)
	check("POST", "http://evil.example", "cross-site", "", token, 403)
	check("POST", "", "", "", token, 403)
	check("GET", "", "same-origin", "Bearer invalid", "", 401)
}

func TestAPIAuthModeSelection(t *testing.T) {
	session, _ := setupBrowserSession(t)
	for _, tc := range []struct{ mode string; want int }{
		{"bearer", 401},
		{"session", 204},
		{"either", 204},
	} {
		h := APIAuth(tc.mode, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(204)
		}))
		req := httptest.NewRequest("GET", "http://192.168.10.5:8080/api/events", nil)
		req.AddCookie(&http.Cookie{Name: "auth_token", Value: session})
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != tc.want { t.Errorf("%s: %d want %d", tc.mode, rec.Code, tc.want) }
	}
}

func TestWebSocketHandshakeRequiresSameOrigin(t *testing.T) {
	session, _ := setupBrowserSession(t)
	h := SessionAPIAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	for _, tc := range []struct{ origin string; want int }{
		{"http://192.168.10.5:8080", 204},
		{"http://evil.example", 403},
		{"", 403},
	} {
		req := httptest.NewRequest("GET", "http://192.168.10.5:8080/api/socket", nil)
		req.AddCookie(&http.Cookie{Name: "auth_token", Value: session})
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")
		if tc.origin != "" { req.Header.Set("Origin", tc.origin) }
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != tc.want { t.Errorf("origin %q got %d want %d", tc.origin, rec.Code, tc.want) }
	}
}

func TestSessionXSRFEndpointAndJSON401(t *testing.T) {
	session, _ := setupBrowserSession(t)
	req := httptest.NewRequest("GET", "http://192.168.10.5:8080/api/auth/csrf", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: session})
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()
	SessionXSRFEndpoint(rec, req)
	if rec.Code != 200 { t.Fatalf("token response: %d %s", rec.Code, rec.Body.String()) }
	var payload struct { Token string `json:"xsrf_token"` }
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil { t.Fatal(err) }
	if payload.Token == "" || rec.Header().Get("Cache-Control") != "no-store" { t.Fatal("missing token or no-store") }

	missing := httptest.NewRequest("GET", "http://192.168.10.5:8080/api/events", nil)
	result := httptest.NewRecorder()
	SessionAPIAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(result, missing)
	if result.Code != 401 || !strings.HasPrefix(result.Header().Get("Content-Type"), "application/json") ||
		result.Header().Get("X-Login-URL") != "/login" {
		t.Fatalf("expected JSON 401 with login URL: %d %+v", result.Code, result.Header())
	}
}
