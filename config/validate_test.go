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
	if err := Validate(); err == nil {
		t.Fatal("session mode without PROTECT_API must be rejected")
	}
	t.Setenv("PROTECT_API", "true")
	for _, mode := range []string{"bearer", "session", "either"} {
		t.Setenv("API_AUTH_MODE", mode)
		if err := Validate(); err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
	}
	t.Setenv("API_AUTH_MODE", "invalid")
	if err := Validate(); err == nil {
		t.Fatal("invalid mode accepted")
	}
	t.Setenv("API_AUTH_MODE", "either")
	t.Setenv("UPSTREAM_ASSERTION_ED25519_SEED", "wrong")
	if err := Validate(); err == nil {
		t.Fatal("invalid assertion seed accepted")
	}
}

func TestUpstreamAssertionBearerRequiresSigningKey(t *testing.T) {
	t.Setenv("SESSION_SECRET", strings.Repeat("s", 32))
	t.Setenv("XSRF_SECRET_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("TARGET_URL", "http://backend:8081")
	t.Setenv("API_AUTH_MODE", "bearer")
	t.Setenv("UPSTREAM_ASSERTION_AS_BEARER", "true")
	t.Setenv("UPSTREAM_ASSERTION_ED25519_SEED", "")
	if err := Validate(); err == nil {
		t.Fatal("Bearer injection without a signing key must be rejected")
	}
	t.Setenv("UPSTREAM_ASSERTION_ED25519_SEED", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if err := Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateCookieSecure(t *testing.T) {
	t.Setenv("SESSION_SECRET", strings.Repeat("x", 48))
	t.Setenv("XSRF_SECRET_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("TARGET_URL", "http://127.0.0.1:8081")
	t.Setenv("API_AUTH_MODE", "bearer")
	t.Setenv("UPSTREAM_ASSERTION_AS_BEARER", "false")
	t.Setenv("UPSTREAM_ASSERTION_ED25519_SEED", "")
	for _, tc := range []struct {
		value string
		valid bool
	}{
		{"", true}, {"true", true}, {"false", true}, {"auto", true},
		{"always", true}, {"never", true}, {"TRUE", true}, {"invalid", false},
	} {
		t.Run(tc.value, func(t *testing.T) {
			t.Setenv("COOKIE_SECURE", tc.value)
			if err := Validate(); (err == nil) != tc.valid {
				t.Fatalf("COOKIE_SECURE=%q: %v", tc.value, err)
			}
		})
	}
}
