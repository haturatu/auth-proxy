package router

import (
	"auth-proxy/config"
	"auth-proxy/logging"
	"auth-proxy/middleware"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCustomAdminRouteRemainsInternalAndAuthenticated(t *testing.T) {
	logging.InitLoggers()
	old := config.Paths
	t.Cleanup(func() { config.Paths = old })
	t.Setenv("TARGET_URL", "http://127.0.0.1:1")
	t.Setenv("FRONTEND_TYPE", "js")
	config.Paths.APIPath = "/api/"
	config.Paths.ProtectAPI = false
	config.Paths.ProtectFrontend = false
	config.Paths.AdminUsersAPI = "/internal/users"
	config.Paths.Login = "/login"
	config.Paths.Logout = "/logout"
	config.Paths.Register = "/register"
	config.Paths.Account = "/account"
	config.Paths.AccountPassword = "/account/password"
	config.Paths.Admin = "/admin"
	config.Paths.Assets = "/assets"
	h := NewRouter(middleware.NewRateLimiter(), middleware.NewLoginRateLimiter())
	for _, path := range []string{"/internal/users", "/internal/users/1/role"} {
		r := httptest.NewRequest(http.MethodGet, "http://app.example"+path, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s: status=%d want 401", path, w.Code)
		}
	}
}
