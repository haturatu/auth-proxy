package utils

import (
	"auth-proxy/types"
	"strings"
	"testing"
	"time"
)

func FuzzValidateJWTNeverPanics(f *testing.F) {
	f.Add("")
	f.Add("a.b.c")
	f.Add(strings.Repeat("x", 5000))
	f.Add("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.e30.")
	f.Fuzz(func(t *testing.T, token string) {
		t.Setenv("SESSION_SECRET", strings.Repeat("z", 48))
		if len(token) > 10000 { return }
		_, _ = ValidateJWT(token)
	})
}

func TestJWTRejectsTamperedSignatureChaos(t *testing.T) {
	t.Setenv("SESSION_SECRET", strings.Repeat("z", 48))
	raw, err := GenerateJWT(&types.User{ID: 4, Role: "admin"}, time.Minute)
	if err != nil { t.Fatal(err) }
	parts := strings.Split(raw, ".")
	if len(parts) != 3 { t.Fatal("expected three JWT parts") }
	parts[2] = "a"
	if _, err := ValidateJWT(strings.Join(parts, ".")); err == nil {
		t.Fatal("tampered signature was accepted")
	}
}
