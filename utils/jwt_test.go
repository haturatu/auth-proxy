package utils

import (
	"auth-proxy/types"
	"strings"
	"testing"
	"time"
)

func TestJWTDerivesSeparateSigningKey(t *testing.T) {
	t.Setenv("SESSION_SECRET", strings.Repeat("S", 48))
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
	// The old signer used SESSION_SECRET directly as its HMAC key.
	// The new implementation must reject it even if the same secret remains.
	parts := strings.Split(token, ".")
	signedData := parts[0] + "." + parts[1]
	legacyToken := signedData + "." + base64Encode(signHS256([]byte(strings.Repeat("S", 48)), signedData))
	if _, err := ValidateJWT(legacyToken); err == nil {
		t.Fatal("old raw-secret JWT signature unexpectedly accepted")
	}
}
