package router

import (
	"auth-proxy/config"
	"auth-proxy/logging"
	"auth-proxy/middleware"
	"auth-proxy/types"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

// Deterministic, bounded chaos scenarios, directed at an isolated in-memory
// upstream, not a deployed server.
func TestSecurityChaosProtectedAPIPaths(t *testing.T) {
	logging.InitLoggers()
	var leaked atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		leaked.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	t.Setenv("TARGET_URL", upstream.URL)
	t.Setenv("FRONTEND_TYPE", "js")
	t.Setenv("XSRF_SECRET_KEY", "not-needed-on-unmatched-api")
	old := config.Paths
	t.Cleanup(func() { config.Paths = old })
	config.Paths = types.PathConfig{
		APIPath: "/api/", APIAuthMode: "bearer", ProtectAPI: true,
		ProtectFrontend: false, AdminUsersAPI: "/api/admin/users",
		Login: "/login", Logout: "/logout", Register: "/register",
		Account: "/account", AccountPassword: "/account/password",
		Admin: "/admin", Assets: "/assets",
	}
	h := NewRouter(middleware.NewRateLimiter(), middleware.NewLoginRateLimiter())
	for _, path := range []string{
		"/api", "/api/", "/api/secret", "/api/v1/users",
		"/api/admin/users", "/api/auth/token/", "/api//private",
		"/api/../api/secret", "/api/%2e%2e/api/secret",
		"/api/%2Fprivate", "/api/%252Fprivate",
	} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://auth.local"+path, nil)
			req.Header.Set("X-Forwarded-For", "198.51.100.99")
			req.Header.Set("Forwarded", "for=198.51.100.99")
			req.Header.Set("X-Real-IP", "198.51.100.99")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code == http.StatusOK {
				t.Fatalf("unauthenticated API access returned 200 for %q", path)
			}
		})
	}
	if got := leaked.Load(); got != 0 {
		t.Fatalf("%d unauthenticated API requests reached upstream", got)
	}
}

func FuzzAPIPrefixBoundary(f *testing.F) {
	for _, path := range []string{"/api", "/api/", "/api/a", "/api2", "/API", "/api//x", "/api/../admin", "/api%2Fprivate", "/", ""} {
		f.Add(path)
	}
	f.Fuzz(func(t *testing.T, path string) {
		if len(path) > 512 {
			return
		}
		got := isAPIPath(path, "/api/")
		want := path == "/api" || strings.HasPrefix(path, "/api/")
		if got != want {
			t.Fatalf("API prefix classification %q got %v want %v", path, got, want)
		}
		if got && (path == "/api2" || path == "/API") {
			t.Fatalf("invalid API prefix match for %q", path)
		}
		// Exercise escaped URL handling without relying on an external server.
		_ = (&url.URL{Path: path}).EscapedPath()
	})
}
