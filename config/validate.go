package config

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// Validate fails closed before opening a database or starting the HTTP server.
func Validate() error {
	// CookieSecure() is the single source of truth for evaluating this setting.
	// Reject typos here rather than silently downgrading secure-cookie behavior.
	switch strings.ToLower(strings.TrimSpace(os.Getenv("COOKIE_SECURE"))) {
	case "", "true", "always", "false", "never", "auto":
	default:
		return fmt.Errorf("COOKIE_SECURE must be true, false, or auto")
	}
	if len(os.Getenv("SESSION_SECRET")) < 32 {
		return fmt.Errorf("SESSION_SECRET must contain at least 32 characters")
	}
	xsrfKey, err := base64.StdEncoding.DecodeString(os.Getenv("XSRF_SECRET_KEY"))
	if err != nil || len(xsrfKey) != 32 {
		return fmt.Errorf("XSRF_SECRET_KEY must be a base64-encoded 32-byte key")
	}
	target, err := url.Parse(os.Getenv("TARGET_URL"))
	if err != nil || target.Host == "" || (target.Scheme != "http" && target.Scheme != "https") || target.User != nil {
		return fmt.Errorf("TARGET_URL must be an absolute http(s) URL without userinfo")
	}
	apiPath := getEnv("API_PATH", "/api/")
	if !strings.HasPrefix(apiPath, "/") || !strings.HasSuffix(apiPath, "/") || apiPath == "/" ||
		strings.Contains(apiPath, "//") || strings.ContainsAny(apiPath, "?#%") || strings.Contains(apiPath, "..") {
		return fmt.Errorf("API_PATH must be an absolute non-root URL prefix ending in /")
	}
	paths := []struct{ key, value string }{
		{"AUTH_PATH_LOGIN", getEnv("AUTH_PATH_LOGIN", "/login")},
		{"AUTH_PATH_REGISTER", getEnv("AUTH_PATH_REGISTER", "/register")},
		{"AUTH_PATH_LOGOUT", getEnv("AUTH_PATH_LOGOUT", "/logout")},
		{"AUTH_PATH_ACCOUNT", getEnv("AUTH_PATH_ACCOUNT", "/account")},
		{"AUTH_PATH_ACCOUNT_PASSWORD", getEnv("AUTH_PATH_ACCOUNT_PASSWORD", "/account/password")},
		{"AUTH_PATH_ADMIN", getEnv("AUTH_PATH_ADMIN", "/admin")},
		{"AUTH_PATH_ADMIN_USERS_API", getEnv("AUTH_PATH_ADMIN_USERS_API", "/api/admin/users")},
		{"AUTH_ASSETS_PATH", getEnv("AUTH_ASSETS_PATH", "/assets")},
	}
	seen := make(map[string]string, len(paths))
	for _, entry := range paths {
		p := entry.value
		if p == "" || !strings.HasPrefix(p, "/") || p == "/" ||
			strings.ContainsAny(p, "?#%") || strings.Contains(p, "//") || strings.Contains(p, "..") {
			return fmt.Errorf("%s must be an absolute, canonical non-root path", entry.key)
		}
		if other, found := seen[p]; found {
			return fmt.Errorf("%s conflicts with %s at %s", entry.key, other, p)
		}
		seen[p] = entry.key
		if entry.key != "AUTH_PATH_ADMIN_USERS_API" &&
			(strings.TrimSuffix(apiPath, "/") == p || strings.HasPrefix(p, apiPath)) {
			return fmt.Errorf("%s must not be inside API_PATH", entry.key)
		}
		if p == "/api/auth/token" || p == "/auth/refresh" {
			return fmt.Errorf("%s conflicts with a reserved authentication endpoint", entry.key)
		}
	}

	mode := strings.ToLower(strings.TrimSpace(os.Getenv("API_AUTH_MODE")))
	switch mode {
	case "", "bearer":
	case "session", "either":
		if !getEnvAsBool("PROTECT_API", true) {
			return fmt.Errorf("PROTECT_API=true is required for API_AUTH_MODE=%s", mode)
		}
	default:
		return fmt.Errorf("API_AUTH_MODE must be bearer, session, or either")
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv("API_SESSION_CSRF"))) {
	case "", "origin", "xsrf":
	default:
		return fmt.Errorf("API_SESSION_CSRF must be origin or xsrf")
	}
	if os.Getenv("UPSTREAM_ASSERTION_AS_BEARER") == "true" &&
		os.Getenv("UPSTREAM_ASSERTION_ED25519_SEED") == "" {
		return fmt.Errorf("UPSTREAM_ASSERTION_AS_BEARER requires UPSTREAM_ASSERTION_ED25519_SEED")
	}
	if seed := os.Getenv("UPSTREAM_ASSERTION_ED25519_SEED"); seed != "" {
		key, err := base64.StdEncoding.DecodeString(seed)
		if err != nil || len(key) != 32 {
			return fmt.Errorf("UPSTREAM_ASSERTION_ED25519_SEED must be base64-encoded 32 bytes")
		}
	}
	return nil
}
