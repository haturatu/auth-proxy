package utils

import (
	"auth-proxy/types"
	"encoding/json"
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
	parts := strings.Split(token, ".")
	payloadJSON, err := base64Decode(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		t.Fatal(err)
	}
	if _, exists := payload["role"]; exists {
		t.Fatal("JWT must not embed stale role")
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
	parts = strings.Split(token, ".")
	signedData := parts[0] + "." + parts[1]
	legacyToken := signedData + "." + base64Encode(signHS256([]byte(strings.Repeat("S", 48)), signedData))
	if _, err := ValidateJWT(legacyToken); err == nil {
		t.Fatal("old raw-secret JWT signature unexpectedly accepted")
	}
}
