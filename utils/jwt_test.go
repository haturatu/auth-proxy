package utils

import (
	"auth-proxy/types"
	"strings"
	"testing"
	"time"
)

func TestJWTDerivesSeparateSigningKey(t *testing.T) {
	t.Setenv("SESSION_SECRET", strings.Repeat("S", 48))
	t.Setenv("JWT_ACCEPT_LEGACY_SIGNATURE", "false")
	token, err := GenerateJWT(&types.User{ID: 42, Role: "user"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := ValidateJWT(token)
	if err != nil || claims.UserID != 42 {
		t.Fatalf("roundtrip: %v %v", claims, err)
	}
	if _, err := ValidateJWT(token + "x"); err == nil {
		t.Fatal("tampered signature accepted")
	}
}
