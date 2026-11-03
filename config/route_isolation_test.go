package config

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestRejectOverlappingConfiguredRoutes(t *testing.T) {
	t.Setenv("SESSION_SECRET", strings.Repeat("a", 40))
	t.Setenv("XSRF_SECRET_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("TARGET_URL", "http://backend.internal")
	t.Setenv("API_PATH", "/api/")
	t.Setenv("API_AUTH_MODE", "bearer")
	t.Setenv("AUTH_PATH_LOGIN", "/login")
	t.Setenv("AUTH_PATH_ADMIN_USERS_API", "/api/admin/users")
	if err := Validate(); err != nil {
		t.Fatalf("valid settings: %v", err)
	}
	for _, tc := range []struct{ key, value string }{
		{"AUTH_PATH_LOGIN", "/api/login"},
		{"AUTH_PATH_LOGIN", "/api"},
		{"AUTH_PATH_LOGIN", "/auth/refresh"},
		{"AUTH_PATH_LOGIN", "/account"},
		{"AUTH_PATH_LOGIN", "/api/auth/token"},
		{"API_PATH", "/"},
		{"API_PATH", "/api"},
		{"API_PATH", "/api//"},
	} {
		t.Run(tc.key+"="+tc.value, func(t *testing.T) {
			t.Setenv(tc.key, tc.value)
			if err := Validate(); err == nil {
				t.Fatal("expected invalid routing configuration to fail at startup")
			}
		})
	}
}
