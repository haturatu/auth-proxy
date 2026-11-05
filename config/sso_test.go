package config

import "testing"

func validSSOConfig() *SSOConfig {
	c := &SSOConfig{Issuer: "https://auth.example.com", TrustedGatewayCIDRs: []string{"127.0.0.1/32"}, Applications: []Application{{ID: "app-a", Origin: "https://app-a.example.com", RedirectURI: "https://app-a.example.com/_auth/callback", Roles: []string{"user"}}}}
	c.WebAuthn.RPID = "auth.example.com"
	c.WebAuthn.Origins = []string{c.Issuer}
	return c
}

func TestSSOConfigRejectsTrustAndRedirectAmbiguity(t *testing.T) {
	if err := validSSOConfig().Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*SSOConfig){
		"wildcard":     func(c *SSOConfig) { c.Applications[0].Origin = "https://*.example.com" },
		"redirect":     func(c *SSOConfig) { c.Applications[0].RedirectURI += "?next=https://evil.example" },
		"http":         func(c *SSOConfig) { c.Issuer = "http://auth.example.com" },
		"rp":           func(c *SSOConfig) { c.WebAuthn.RPID = "example.com" },
		"origin":       func(c *SSOConfig) { c.WebAuthn.Origins = append(c.WebAuthn.Origins, "https://app-a.example.com") },
		"peer":         func(c *SSOConfig) { c.TrustedGatewayCIDRs = []string{"0.0.0.0/0"} },
		"missing-peer": func(c *SSOConfig) { c.TrustedGatewayCIDRs = nil },
		"same-host": func(c *SSOConfig) {
			c.Applications[0].Origin = c.Issuer
			c.Applications[0].RedirectURI = c.Issuer + "/_auth/callback"
		},
		"same-cookie-host": func(c *SSOConfig) {
			c.Applications[0].Origin = c.Issuer + ":8443"
			c.Applications[0].RedirectURI = c.Applications[0].Origin + "/_auth/callback"
		},
		"default-port": func(c *SSOConfig) {
			c.Applications[0].Origin = "https://app-a.example.com:443"
			c.Applications[0].RedirectURI = c.Applications[0].Origin + "/_auth/callback"
		},
		"duplicate": func(c *SSOConfig) { c.Applications = append(c.Applications, c.Applications[0]) },
		"empty-acl": func(c *SSOConfig) { c.Applications[0].Roles = nil },
	} {
		t.Run(name, func(t *testing.T) {
			c := validSSOConfig()
			mutate(c)
			if c.Validate() == nil {
				t.Fatal("unsafe configuration accepted")
			}
		})
	}
}
