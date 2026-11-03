package logging

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClientIPTrustMatrix(t *testing.T) {
	if err := ConfigureTrustedProxies("10.0.0.0/8,127.0.0.1/32,::1/128"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ConfigureTrustedProxies("") })
	cases := []struct {
		name string
		peer string
		xff  string
		want string
	}{
		{"untrusted peer ignores XFF", "203.0.113.9:1234", "1.1.1.1", "203.0.113.9"},
		{"trusted peer honors XFF", "10.0.0.5:1234", "1.1.1.1", "1.1.1.1"},
		{"rightmost untrusted wins", "10.0.0.5:1234", "1.1.1.1, 2.2.2.2", "2.2.2.2"},
		{"trusted hops skipped", "10.0.0.5:1234", "1.1.1.1, 10.0.0.7", "1.1.1.1"},
		{"all trusted fallback", "10.0.0.5:1234", "10.0.0.7", "10.0.0.5"},
		{"garbage fallback", "10.0.0.5:1234", "not-an-ip", "10.0.0.5"},
		{"ports not accepted in XFF", "10.0.0.5:1234", "1.1.1.1:5555", "10.0.0.5"},
		{"ipv4 mapped trusted peer", "[::ffff:10.0.0.5]:1234", "1.1.1.1", "1.1.1.1"},
		{"empty chain", "10.0.0.5:1234", "", "10.0.0.5"},
		{"CIDR boundary", "11.0.0.1:1234", "1.1.1.1", "11.0.0.1"},
		{"long chain", "10.0.0.5:1234", strings.Repeat("1.1.1.1, ", 200) + "1.1.1.1", "10.0.0.5"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "http://auth.example/", nil)
			r.RemoteAddr = tc.peer
			if tc.xff != "" {
				r.Header.Set("X-Forwarded-For", tc.xff)
			}
			if got := GetClientIP(r); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestRejectWildcardTrustedProxy(t *testing.T) {
	for _, cidr := range []string{"0.0.0.0/0", "::/0"} {
		if err := ConfigureTrustedProxies(cidr); err == nil {
			t.Fatalf("must not trust every peer with %s", cidr)
		}
	}
}
