package config

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
)

// Validate fails closed before opening a database or starting the HTTP server.
func Validate() error {
	if len(os.Getenv("SESSION_SECRET")) < 32 {
		return fmt.Errorf("SESSION_SECRET must contain at least 32 characters")
	}
	xsrfKey, err := base64.StdEncoding.DecodeString(os.Getenv("XSRF_SECRET_KEY"))
	if err != nil || len(xsrfKey) != 32 {
		return fmt.Errorf("XSRF_SECRET_KEY must be a base64-encoded 32-byte key")
	}
	target, err := url.Parse(os.Getenv("TARGET_URL"))
	if err != nil || target.Host == "" || (target.Scheme != "http" && target.Scheme != "https") || target.User != nil {
		return fmt.Errorf("TARGET_URL must be an absolute http(s) URL without userinfo")
	}
	return nil
}
