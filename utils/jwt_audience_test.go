package utils

import (
	"auth-proxy/types"
	"strings"
	"testing"
	"time"
)

func TestJWTBoundToIssuerAndAudience(t *testing.T) {
	t.Setenv("SESSION_SECRET", strings.Repeat("a", 48))
	t.Setenv("TARGET_URL", "https://one.backend.local")
	t.Setenv("JWT_AUDIENCE", "gateway-one")
	token, err := GenerateJWT(&types.User{ID: 101, Role: "admin"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateJWT(token); err != nil {
		t.Fatal(err)
	}
	t.Setenv("JWT_AUDIENCE", "gateway-two")
	if _, err := ValidateJWT(token); err == nil {
		t.Fatal("cross-deployment access token must be rejected")
	}
	t.Setenv("JWT_AUDIENCE", "gateway-one")
	if _, err := ValidateJWT(token); err != nil {
		t.Fatal(err)
	}
}
