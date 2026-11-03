package router

import (
	"auth-proxy/config"
	"testing"
)

func TestAuthUIAliasesCannotReachUpstream(t *testing.T) {
	old := config.Paths
	t.Cleanup(func() { config.Paths = old })
	config.Paths.Login = "/login"
	config.Paths.Register = "/register"
	config.Paths.Logout = "/logout"
	config.Paths.Account = "/account"
	config.Paths.AccountPassword = "/account/password"
	config.Paths.Admin = "/admin"
	for _, path := range []string{
		"/admin/", "/admin//", "/ADMIN", "/Admin", "/account/",
		"/ACCOUNT/PASSWORD", "/Login/", "/REGISTER", "/logout/",
	} {
		if !isAuthUIAlias(path) {
			t.Errorf("expected %s to be reserved", path)
		}
	}
	for _, path := range []string{"/admin", "/account", "/app", "/admin-tools", "/api/admin"} {
		if isAuthUIAlias(path) {
			t.Errorf("expected %s to be normal path", path)
		}
	}
}
