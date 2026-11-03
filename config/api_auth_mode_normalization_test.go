package config

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestAPIAuthModeCanonicalization(t *testing.T) {
	t.Setenv("SESSION_SECRET", strings.Repeat("q", 48))
	t.Setenv("XSRF_SECRET_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("TARGET_URL", "http://backend.local")
	t.Setenv("PROTECT_API", "true")
	for _, tc := range []struct{ input, want string }{
		{" Bearer ", "bearer"},
		{" SESSION ", "session"},
		{" EITHER ", "either"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			t.Setenv("API_AUTH_MODE", tc.input)
			if err := Validate(); err != nil {
				t.Fatal(err)
			}
			Init()
			if Paths.APIAuthMode != tc.want {
				t.Fatalf("%q normalized to %q, want %q", tc.input, Paths.APIAuthMode, tc.want)
			}
		})
	}
	t.Setenv("API_AUTH_MODE", "unknown")
	if err := Validate(); err == nil {
		t.Fatal("unknown API authentication mode accepted")
	}
}
