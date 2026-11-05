package config

import (
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"
)

// SSOConfig is opt-in: without SSO_CONFIG the legacy proxy is unchanged.
type SSOConfig struct {
	Issuer   string `yaml:"issuer"`
	WebAuthn struct {
		RPID    string   `yaml:"rp_id"`
		Origins []string `yaml:"origins"`
	} `yaml:"webauthn"`
	TrustedGatewayCIDRs []string      `yaml:"trusted_gateway_cidrs"`
	Applications        []Application `yaml:"applications"`
}

type Application struct {
	ID          string   `yaml:"id"`
	Origin      string   `yaml:"origin"`
	RedirectURI string   `yaml:"redirect_uri"`
	Roles       []string `yaml:"roles"`
	// Optional confidential client authentication. Only the environment variable
	// name is placed in the configuration file.
	ClientSecretEnv string `yaml:"client_secret_env"`
}

func LoadSSO() (*SSOConfig, error) {
	path := os.Getenv("SSO_CONFIG")
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck
	var c SSOConfig
	d := yaml.NewDecoder(io.LimitReader(f, 1<<20))
	d.KnownFields(true)
	if err = d.Decode(&c); err != nil {
		return nil, err
	}
	var extra any
	if err = d.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("SSO_CONFIG must contain exactly one document")
	}
	if err = c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func originURL(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery || strings.ContainsAny(s, "*\\\r\n") || strings.ToLower(u.Host) != u.Host {
		return nil, fmt.Errorf("expected a canonical HTTPS origin: %q", s)
	}
	return u, nil
}

func (c *SSOConfig) Validate() error {
	u, err := originURL(c.Issuer)
	if err != nil {
		return err
	}
	if c.WebAuthn.RPID != u.Hostname() || len(c.WebAuthn.Origins) != 1 || c.WebAuthn.Origins[0] != c.Issuer {
		return fmt.Errorf("WebAuthn RP ID and sole origin must match the issuer")
	}
	if len(c.TrustedGatewayCIDRs) == 0 {
		return fmt.Errorf("trusted_gateway_cidrs must explicitly identify Nginx peers")
	}
	for _, cidr := range c.TrustedGatewayCIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("invalid gateway CIDR %q", cidr)
		}
		ones, _ := network.Mask.Size()
		if ones == 0 {
			return fmt.Errorf("gateway CIDRs must not trust the entire internet")
		}
	}
	if len(c.Applications) == 0 {
		return fmt.Errorf("at least one application is required")
	}
	ids, origins := map[string]bool{}, map[string]bool{}
	for _, a := range c.Applications {
		if !regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`).MatchString(a.ID) || ids[a.ID] {
			return fmt.Errorf("invalid or duplicate application ID %q", a.ID)
		}
		if _, err = originURL(a.Origin); err != nil {
			return err
		}
		if origins[a.Origin] || a.Origin == c.Issuer {
			return fmt.Errorf("application origins must be unique and separate from the issuer")
		}
		if a.RedirectURI != a.Origin+"/_auth/callback" {
			return fmt.Errorf("%s redirect_uri must exactly equal its origin plus /_auth/callback", a.ID)
		}
		if len(a.Roles) == 0 {
			return fmt.Errorf("%s must explicitly allow at least one role", a.ID)
		}
		for _, role := range a.Roles {
			if role != "user" && role != "admin" {
				return fmt.Errorf("unknown role %q", role)
			}
		}
		if a.ClientSecretEnv != "" && len(os.Getenv(a.ClientSecretEnv)) < 32 {
			return fmt.Errorf("%s client secret must contain at least 32 characters", a.ID)
		}
		ids[a.ID], origins[a.Origin] = true, true
	}
	return nil
}
