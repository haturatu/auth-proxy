package router

import (
	"auth-proxy/config"
	"auth-proxy/database"
	"auth-proxy/handlers"
	"auth-proxy/logging"
	"auth-proxy/middleware"
	"auth-proxy/worker"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestEventSourceCookieOnlyViaRouter(t *testing.T) {
	logging.InitLoggers()
	oldDB := database.DB
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	database.DB = db
	t.Cleanup(func() { _ = db.Close(); database.DB = oldDB })
	for _, query := range []string{
		`CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT, role TEXT,
			is_active BOOLEAN, failed_logins INTEGER, last_login_at DATETIME,
			created_at DATETIME, updated_at DATETIME)`,
		`CREATE TABLE auth_tokens (user_id INTEGER, token TEXT, expires_at DATETIME)`,
	} {
		if _, err := db.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now()
	if _, err := db.Exec(`INSERT INTO users
		(id, username, password_hash, role, is_active, failed_logins, created_at, updated_at)
		VALUES (1, 'alice', '', 'user', 1, 0, ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO auth_tokens (user_id, token, expires_at) VALUES (1, ?, ?)",
		database.TokenHash("browser-session"), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/events" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("X-Auth-Request-User") != "alice" {
			t.Error("missing authenticated identity")
		}
		if r.Header.Get("Authorization") != "" {
			t.Error("client auth header leaked upstream")
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: connected\n\n"))
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
	}))
	defer upstream.Close()
	pool := worker.NewWorkerPool()
	defer worker.Close(pool)
	handlers.SetWorkerPool(pool)
	_ = logging.ConfigureTrustedProxies("")
	oldPaths := config.Paths
	t.Cleanup(func() { config.Paths = oldPaths })
	t.Setenv("TARGET_URL", upstream.URL)
	t.Setenv("FRONTEND_TYPE", "js")
	t.Setenv("PROTECT_API", "true")
	t.Setenv("API_AUTH_MODE", "session")
	config.Init()
	h := NewRouter(middleware.NewRateLimiter(), middleware.NewLoginRateLimiter())

	req := httptest.NewRequest("GET", "http://192.168.10.5:8080/api/events", nil)
	req.RemoteAddr = "192.168.20.14:45000"
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: "browser-session"})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "data: connected") {
		t.Fatalf("cookie-only SSE failed: %d %q", rr.Code, rr.Body.String())
	}
}
