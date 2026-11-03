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
