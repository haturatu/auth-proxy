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
	mode := os.Getenv("API_AUTH_MODE")
	switch mode {
	case "", "bearer":
	case "session", "either":
		if !getEnvAsBool("PROTECT_API", false) {
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
