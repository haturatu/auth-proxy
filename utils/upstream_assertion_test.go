package utils

import (
	"auth-proxy/types"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestUpstreamAssertionIsEdDSAAndAudienceScoped(t *testing.T) {
	t.Setenv("UPSTREAM_ASSERTION_ED25519_SEED", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	tok, err := GenerateUpstreamAssertion(&types.User{ID: 43, Username: "alice", Role: "admin"}, "backend.internal:8081")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("invalid JWT: %q", tok)
	}
	pub, err := UpstreamAssertionPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		t.Fatal("invalid Ed25519 signature")
	}
	encoded, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		Iss string `json:"iss"`
		Aud string `json:"aud"`
		Sub string `json:"sub"`
		JTI string `json:"jti"`
		Iat int64  `json:"iat"`
		Exp int64  `json:"exp"`
	}
	if err := json.Unmarshal(encoded, &claims); err != nil {
		t.Fatal(err)
	}
	if claims.Iss != "auth-proxy" || claims.Aud != "backend.internal:8081" || claims.Sub != "43" || claims.JTI == "" {
		t.Fatalf("bad claims: %+v", claims)
	}
	if claims.Exp-claims.Iat != 60 || claims.Exp <= time.Now().Unix() {
		t.Fatal("invalid expiration")
	}
	t.Setenv("UPSTREAM_ASSERTION_ED25519_SEED", "")
	empty, err := GenerateUpstreamAssertion(&types.User{ID: 43}, "backend.internal")
	if err != nil || empty != "" {
		t.Fatal("assertion signing should be optional")
	}
}
