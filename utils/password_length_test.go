package utils

import (
	"strings"
	"testing"

	"auth-proxy/config"
)

func TestBcryptPasswordByteLimit(t *testing.T) {
	t.Setenv("PASSWORD_HASH_ALGORITHM", "bcrypt")
	old := config.Paths
	t.Cleanup(func() { config.Paths = old })
	config.Paths.PasswordPolicy = "none"
	if ok, _ := ValidatePassword(strings.Repeat("a", 72)); !ok {
		t.Fatal("72-byte bcrypt password must be permitted")
	}
	if ok, _ := ValidatePassword(strings.Repeat("a", 73)); ok {
		t.Fatal("73-byte bcrypt password must be rejected explicitly")
	}
	if ok, _ := ValidatePassword(strings.Repeat("あ", 25)); ok {
		t.Fatal("75-byte unicode input must be rejected in bcrypt mode")
	}
	t.Setenv("PASSWORD_HASH_ALGORITHM", "pbkdf2-sha256")
	if ok, _ := ValidatePassword(strings.Repeat("a", 73)); !ok {
		t.Fatal("PBKDF2 must accept longer credentials")
	}
}
