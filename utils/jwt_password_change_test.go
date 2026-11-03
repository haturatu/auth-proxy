package utils

import (
	"auth-proxy/types"
	"strings"
	"testing"
	"time"
)

func TestJWTInvalidatedWhenPasswordHashChanges(t *testing.T) {
	t.Setenv("SESSION_SECRET", strings.Repeat("p", 48))
	user := &types.User{ID: 8, PasswordHash: "$2a$14$original-hash"}
	token, err := GenerateJWT(user, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := ValidateJWT(token)
	if err != nil {
		t.Fatal(err)
	}
	if !JWTMatchesCredentials(payload, user) {
		t.Fatal("fresh token rejected")
	}
	user.PasswordHash = "$2a$14$rotated-hash"
	if JWTMatchesCredentials(payload, user) {
		t.Fatal("old token must be revoked immediately after password change")
	}
}
