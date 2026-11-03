package router

import (
	"auth-proxy/config"
	"auth-proxy/logging"
	"auth-proxy/middleware"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAPIPrefixMatchesSegmentBoundary(t *testing.T) {
	for _, tc := range []struct {
		path string
		want bool
	}{
		{"/api", true},
		{"/api/", true},
		{"/api/private", true},
		{"/api2", false},
		{"/API", false},
		{"/x/api", false},
	} {
		if got := isAPIPath(tc.path, "/api/"); got != tc.want {
			t.Errorf("path %q matched=%v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestAPIRootDoesNotFallThroughToUnprotectedFrontend(t *testing.T) {
	logging.InitLoggers()
	old := config.Paths
	t.Cleanup(func() { config.Paths = old })
	t.Setenv("TARGET_URL", "http://127.0.0.1:1")
	t.Setenv("FRONTEND_TYPE", "js")
	config.Paths = old
	config.Paths.APIPath = "/api/"
	config.Paths.ProtectAPI = true
	config.Paths.ProtectFrontend = false
	config.Paths.APIAuthMode = "bearer"
	config.Paths.Login = "/login"
	config.Paths.Logout = "/logout"
	config.Paths.Register = "/register"
	config.Paths.Account = "/account"
	config.Paths.AccountPassword = "/account/password"
	config.Paths.Admin = "/admin"
	config.Paths.AdminUsersAPI = "/api/admin/users"
	config.Paths.Assets = "/assets"
	h := NewRouter(middleware.NewRateLimiter(), middleware.NewLoginRateLimiter())
	for _, path := range []string{"/api", "/api/", "/api/files"} {
		req := httptest.NewRequest(http.MethodGet, "http://app.local"+path, nil)
		got := httptest.NewRecorder()
		h.ServeHTTP(got, req)
		if got.Code != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want 401", path, got.Code)
		}
	}
}
