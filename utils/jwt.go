package utils

import (
	"auth-proxy/types"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"net/url"
	"strings"
	"time"
)

func base64Encode(src []byte) string          { return base64.RawURLEncoding.EncodeToString(src) }
func base64Decode(src string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(src) }

func jwtSigningKey() ([]byte, error) {
	secret := os.Getenv("SESSION_SECRET")
	if len(secret) < 32 {
		return nil, errors.New("SESSION_SECRET must be at least 32 bytes")
	}
	return hkdf.Key(sha256.New, []byte(secret), nil, "auth-proxy/jwt-hs256/v1", 32)
}

func signHS256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte(data))
	return h.Sum(nil)
}

// jwtAudience separates access-token trust across independent deployments.
// Production requires TARGET_URL; an explicit audience is recommended if
// multiple gateways share one upstream service.
func jwtAudience() string {
	if configured := strings.TrimSpace(os.Getenv("JWT_AUDIENCE")); configured != "" {
		return configured
	}
	if target, err := url.Parse(os.Getenv("TARGET_URL")); err == nil && target.Host != "" {
		return "auth-proxy:" + target.Host
	}
	return "auth-proxy:local-test"
}

func GenerateJWT(user *types.User, duration time.Duration) (string, error) {
	key, err := jwtSigningKey()
	if err != nil {
		return "", err
	}
	headerJSON, err := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	payloadJSON, err := json.Marshal(types.JWTPayload{
		Issuer: "auth-proxy", Audience: jwtAudience(), IssuedAt: time.Now().Unix(), NotBefore: time.Now().Unix(),
		UserID: user.ID, Role: user.Role, Exp: time.Now().Add(duration).Unix(),
	})
	if err != nil {
		return "", err
	}
	signedData := base64Encode(headerJSON) + "." + base64Encode(payloadJSON)
	return signedData + "." + base64Encode(signHS256(key, signedData)), nil
}

func ValidateJWT(value string) (*types.JWTPayload, error) {
	if len(value) > 4096 {
		return nil, errors.New("token too long")
	}
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token format")
	}
	signedData := parts[0] + "." + parts[1]
	supplied, err := base64Decode(parts[2])
	if err != nil {
		return nil, errors.New("invalid signature encoding")
	}
	key, err := jwtSigningKey()
	if err != nil {
		return nil, err
	}
	// Only signatures derived through HKDF are accepted. We intentionally do
	// not support the previous raw-SESSION_SECRET signing key: all existing
	// access JWTs must be reissued after upgrading.
	if !hmac.Equal(supplied, signHS256(key, signedData)) {
		return nil, errors.New("invalid signature")
	}
	headerBytes, err := base64Decode(parts[0])
	if err != nil {
		return nil, errors.New("invalid JWT header")
	}
	var header struct {
		Algorithm string `json:"alg"`
		Type      string `json:"typ"`
	}
	if err = json.Unmarshal(headerBytes, &header); err != nil || header.Algorithm != "HS256" || header.Type != "JWT" {
		return nil, errors.New("unsupported JWT header")
	}
	data, err := base64Decode(parts[1])
	if err != nil {
		return nil, errors.New("invalid JWT claims")
	}
	var payload types.JWTPayload
	if err = json.Unmarshal(data, &payload); err != nil {
		return nil, fmt.Errorf("invalid JWT claims: %w", err)
	}
	now := time.Now().Unix()
	if payload.Issuer != "auth-proxy" || payload.Audience != jwtAudience() ||
		payload.IssuedAt <= 0 || payload.IssuedAt > now+60 ||
		payload.NotBefore <= 0 || payload.NotBefore > now+60 ||
		payload.UserID <= 0 || payload.Exp <= now {

		return nil, errors.New("token expired or invalid")
	}
	return &payload, nil
}
