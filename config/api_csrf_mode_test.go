package config

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestAPICSRFModeNormalizesAndRejectsUnknown(t *testing.T) {
	t.Setenv("SESSION_SECRET", strings.Repeat("s", 48))
	t.Setenv("XSRF_SECRET_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("TARGET_URL", "http://127.0.0.1:8888")
	t.Setenv("API_AUTH_MODE", "session")
	t.Setenv("PROTECT_API", "true")
	for _, value := range []string{"xsrf", " XSRF ", "XsRf"} {
		t.Setenv("API_SESSION_CSRF", value)
		if err := Validate(); err != nil { t.Fatal(err) }
		Init()
		if Paths.APISessionCSRF != "xsrf" { t.Fatalf("%q yields %q", value, Paths.APISessionCSRF) }
	}
	t.Setenv("API_SESSION_CSRF", "disabled")
	if err := Validate(); err == nil {
		t.Fatal("unknown API_SESSION_CSRF must fail startup")
	}
}
