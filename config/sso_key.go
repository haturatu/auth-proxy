package config

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// LoadSSOSigningKey is shared by startup validation and the identity provider.
func LoadSSOSigningKey() (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(os.Getenv("SSO_SIGNING_KEY_FILE"))
	if err != nil {
		return nil, fmt.Errorf("read SSO_SIGNING_KEY_FILE: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("SSO signing key must be PEM encoded")
	}
	var key *rsa.PrivateKey
	if block.Type == "RSA PRIVATE KEY" {
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	} else {
		var parsed any
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		key, _ = parsed.(*rsa.PrivateKey)
	}
	if err != nil || key == nil || key.N.BitLen() < 2048 {
		return nil, fmt.Errorf("SSO signing key must be RSA with at least 2048 bits")
	}
	if err = key.Validate(); err != nil {
		return nil, err
	}
	return key, nil
}
