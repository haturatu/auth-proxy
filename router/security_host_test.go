package router

import (
	"testing"
)

func TestAllowedRequestHost(t *testing.T) {
	t.Setenv("ALLOWED_HOSTS", "auth.example.com,localhost:8080")
	for _, tc := range []struct {
		host  string
		allow bool
	}{
		{"auth.example.com", true},
		{"AUTH.EXAMPLE.COM", true},
		{"localhost:8080", true},
		{"auth.example.com.evil.example", false},
		{"auth.example.com:8443", false},
		{"evil.example", false},
	} {
		if allowedRequestHost(tc.host) != tc.allow {
			t.Errorf("host %q: allowed=%v expected %v", tc.host, allowedRequestHost(tc.host), tc.allow)
		}
	}
}
