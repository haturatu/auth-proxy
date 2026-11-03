package config

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	t.Setenv("SESSION_SECRET", strings.Repeat("a", 32))
	t.Setenv("XSRF_SECRET_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("TARGET_URL", "http://backend:80")
	if err := Validate(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SESSION_SECRET", "too-short")
	if err := Validate(); err == nil {
		t.Fatal("expected missing/short secret to be rejected")
	}
}

func TestAPIAuthModeValidation(t *testing.T) {
	t.Setenv("SESSION_SECRET", strings.Repeat("s", 32))
	t.Setenv("XSRF_SECRET_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("TARGET_URL", "http://backend:8081")
	t.Setenv("PROTECT_API", "false")
	t.Setenv("API_AUTH_MODE", "session")
	if err := Validate(); err == nil { t.Fatal("session mode without PROTECT_API must be rejected") }
	t.Setenv("PROTECT_API", "true")
	for _, mode := range []string{"bearer", "session", "either"} {
		t.Setenv("API_AUTH_MODE", mode)
		if err := Validate(); err != nil { t.Fatalf("%s: %v", mode, err) }
	}
	t.Setenv("API_AUTH_MODE", "invalid")
	if err := Validate(); err == nil { t.Fatal("invalid mode accepted") }
	t.Setenv("API_AUTH_MODE", "either")
	t.Setenv("UPSTREAM_ASSERTION_ED25519_SEED", "wrong")
	if err := Validate(); err == nil { t.Fatal("invalid assertion seed accepted") }
}
