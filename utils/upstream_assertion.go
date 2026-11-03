package utils

import (
	"auth-proxy/types"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"time"
)

// UpstreamAssertionPublicKey returns the public verification key for the
// optional assertion signer. Only distribute this public key to backends;
// never share the Ed25519 seed or SESSION_SECRET with upstream applications.
func UpstreamAssertionPublicKey() (ed25519.PublicKey, error) {
	key, err := upstreamAssertionKey()
	if err != nil {
		return nil, err
	}
	if key == nil {
		return nil, nil
	}
	return key.Public().(ed25519.PublicKey), nil
}

func upstreamAssertionKey() (ed25519.PrivateKey, error) {
	raw := os.Getenv("UPSTREAM_ASSERTION_ED25519_SEED")
	if raw == "" {
		return nil, nil
	}
	seed, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("UPSTREAM_ASSERTION_ED25519_SEED must be a base64-encoded 32-byte seed")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// GenerateUpstreamAssertion signs a short-lived identity assertion with a
// dedicated Ed25519 key. An empty result means assertion signing is disabled.
// The backend MUST verify signature, iss, aud, exp (and iat if relevant).
func GenerateUpstreamAssertion(user *types.User, audience string) (string, error) {
	private, err := upstreamAssertionKey()
	if err != nil {
		return "", err
	}
	if private == nil {
		return "", nil
	}
	if user == nil || user.ID <= 0 || audience == "" {
		return "", errors.New("invalid user or assertion audience")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	now := time.Now().Unix()
	header, err := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(struct {
		Issuer   string `json:"iss"`
		Audience string `json:"aud"`
		Subject  string `json:"sub"`
		Username string `json:"preferred_username"`
		Role     string `json:"role"`
		IssuedAt int64  `json:"iat"`
		Expires  int64  `json:"exp"`
		TokenID  string `json:"jti"`
	}{
		Issuer: "auth-proxy", Audience: audience,
		Subject:  strconv.FormatInt(user.ID, 10),
		Username: user.Username, Role: user.Role,
		IssuedAt: now, Expires: now + 60,
		TokenID: base64.RawURLEncoding.EncodeToString(nonce[:]),
	})
	if err != nil {
		return "", err
	}
	signed := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(claims)
	signature := ed25519.Sign(private, []byte(signed))
	return signed + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}
