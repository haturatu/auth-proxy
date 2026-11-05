package sso

import (
	"auth-proxy/config"
	"auth-proxy/database"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type authorizationCode struct {
	ClientID    string
	RedirectURI string
	Challenge   string
	Nonce       string
	UserID      int64
	SSOHash     string
	AuthTime    int64
}

type oidcClaims struct {
	jwt.RegisteredClaims
	Nonce    string `json:"nonce,omitempty"`
	AuthTime int64  `json:"auth_time"`
	SSOHash  string `json:"sid"`
	TokenUse string `json:"token_use"`
}

type tokenResponse struct {
	IDToken     string `json:"id_token"`
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

func (s *Service) discovery(w http.ResponseWriter, r *http.Request) {
	i := s.config.Issuer
	reply(w, map[string]any{
		"issuer": i, "authorization_endpoint": i + "/oauth2/authorize", "token_endpoint": i + "/oauth2/token", "jwks_uri": i + "/oauth2/jwks", "userinfo_endpoint": i + "/oauth2/userinfo",
		"response_types_supported": []string{"code"}, "response_modes_supported": []string{"query"}, "grant_types_supported": []string{"authorization_code"}, "subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"RS256"}, "scopes_supported": []string{"openid", "profile"}, "token_endpoint_auth_methods_supported": []string{"none", "client_secret_basic"}, "code_challenge_methods_supported": []string{"S256"}, "authorization_response_iss_parameter_supported": true,
		"claims_supported": []string{"iss", "sub", "aud", "iat", "exp", "auth_time", "nonce", "sid", "preferred_username"},
	})
}

func (s *Service) jwks(w http.ResponseWriter, r *http.Request) {
	e := big.NewInt(int64(s.key.E)).Bytes()
	reply(w, map[string]any{"keys": []any{map[string]string{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": s.kid, "n": base64.RawURLEncoding.EncodeToString(s.key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(e)}}})
}

func validB64Token(value string) bool {
	b, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(b) == 32 && len(value) == 43
}

func (s *Service) validateAuthorization(q url.Values) (*config.Application, error) {
	for _, key := range []string{"client_id", "redirect_uri", "response_type", "scope", "state", "nonce", "code_challenge", "code_challenge_method"} {
		if len(q[key]) != 1 || q.Get(key) == "" || len(q.Get(key)) > 2048 {
			return nil, errInvalid
		}
	}
	a := s.client(q.Get("client_id"))
	if a == nil || q.Get("redirect_uri") != a.RedirectURI || q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || !validB64Token(q.Get("code_challenge")) {
		return nil, errInvalid
	}
	openid := false
	for _, scope := range strings.Fields(q.Get("scope")) {
		if scope == "openid" {
			openid = true
		} else if scope != "profile" {
			return nil, errInvalid
		}
	}
	if !openid {
		return nil, errInvalid
	}
	// This provider deliberately supports only code + query and never silently
	// ignores security-sensitive request modes it cannot honor.
	for _, key := range []string{"response_mode", "prompt", "max_age", "request", "request_uri", "claims", "id_token_hint"} {
		if len(q[key]) != 0 {
			return nil, errInvalid
		}
	}
	return a, nil
}

func (s *Service) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	a, err := s.validateAuthorization(q)
	if err != nil {
		http.Error(w, "Invalid authorization request", http.StatusBadRequest)
		return
	}
	parent, user, err := s.currentSSO(r)
	if errors.Is(err, errInvalid) {
		// Only validated authorization requests reach this login continuation.
		// Store the request server-side; the browser carries an opaque handle.
		handle := randomToken()
		if err = s.putFlow("authorize", handle, q); err != nil {
			unavailable(w, err)
			return
		}
		http.Redirect(w, r, s.config.Issuer+"/sso/login?flow="+handle, http.StatusFound)
		return
	}
	if err != nil {
		unavailable(w, err)
		return
	}
	if !allowed(a, user) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	code := authorizationCode{ClientID: a.ID, RedirectURI: a.RedirectURI, Challenge: q.Get("code_challenge"), Nonce: q.Get("nonce"), UserID: user.ID, SSOHash: parent.Hash, AuthTime: parent.AuthTime}
	raw := randomToken()
	hash := database.TokenHash(raw)
	data, err := s.seal(code, "code:"+hash)
	if err != nil {
		unavailable(w, err)
		return
	}
	_, err = database.DB.Exec(database.Rebind("INSERT INTO authorization_codes (token_hash, payload, expires_at) VALUES (?, ?, ?)"), hash, data, time.Now().Add(time.Minute).Unix())
	if err != nil {
		unavailable(w, err)
		return
	}
	redirect, _ := url.Parse(a.RedirectURI)
	redirect.RawQuery = url.Values{"code": {raw}, "state": {q.Get("state")}, "iss": {s.config.Issuer}}.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

func validVerifier(v string) bool {
	if len(v) < 43 || len(v) > 128 {
		return false
	}
	for _, ch := range v {
		switch {
		case ch >= 'a' && ch <= 'z', ch >= 'A' && ch <= 'Z', ch >= '0' && ch <= '9', strings.ContainsRune("-._~", ch):
		default:
			return false
		}
	}
	return true
}

func (s *Service) exchange(a *config.Application, raw, redirect, verifier string) (*tokenResponse, *authorizationCode, error) {
	if !validVerifier(verifier) || redirect != a.RedirectURI {
		return nil, nil, errInvalid
	}
	var c authorizationCode
	if err := s.takeRecord("authorization_codes", "code", raw, &c); err != nil {
		return nil, nil, err
	}
	if c.ClientID != a.ID || c.RedirectURI != redirect || subtle.ConstantTimeCompare([]byte(c.Challenge), []byte(pkce(verifier))) != 1 {
		return nil, nil, errInvalid
	}
	_, user, err := s.lookupSSOHash(c.SSOHash)
	if err != nil {
		return nil, nil, err
	}
	if user.ID != c.UserID || !allowed(a, user) {
		return nil, nil, errInvalid
	}
	id, err := s.signClaims(&c, "id")
	if err != nil {
		return nil, nil, err
	}
	access, err := s.signClaims(&c, "access")
	if err != nil {
		return nil, nil, err
	}
	return &tokenResponse{IDToken: id, AccessToken: access, TokenType: "Bearer", ExpiresIn: 300}, &c, nil
}

func (s *Service) signClaims(c *authorizationCode, use string) (string, error) {
	now := time.Now()
	claims := oidcClaims{RegisteredClaims: jwt.RegisteredClaims{Issuer: s.config.Issuer, Subject: strconv.FormatInt(c.UserID, 10), Audience: jwt.ClaimStrings{c.ClientID}, ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)), IssuedAt: jwt.NewNumericDate(now), NotBefore: jwt.NewNumericDate(now), ID: randomToken()}, AuthTime: c.AuthTime, SSOHash: c.SSOHash, TokenUse: use}
	if use == "id" {
		claims.Nonce = c.Nonce
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.kid
	return token.SignedString(s.key)
}

func (s *Service) parseClaims(raw, audience, use string) (*oidcClaims, error) {
	if len(raw) > 8192 {
		return nil, errInvalid
	}
	var claims oidcClaims
	opts := []jwt.ParserOption{jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(s.config.Issuer), jwt.WithExpirationRequired(), jwt.WithIssuedAt()}
	if audience != "" {
		opts = append(opts, jwt.WithAudience(audience))
	}
	token, err := jwt.ParseWithClaims(raw, &claims, func(t *jwt.Token) (any, error) {
		if t.Header["kid"] != s.kid {
			return nil, errInvalid
		}
		return (*rsa.PublicKey)(&s.key.PublicKey), nil
	}, opts...)
	if err != nil || !token.Valid || claims.TokenUse != use || claims.Subject == "" || claims.IssuedAt == nil || claims.AuthTime <= 0 || claims.AuthTime > time.Now().Unix() || len(claims.Audience) != 1 || s.client(claims.Audience[0]) == nil {
		return nil, errInvalid
	}
	return &claims, nil
}

func (s *Service) validateIDToken(raw, audience, nonce string) (*oidcClaims, error) {
	claims, err := s.parseClaims(raw, audience, "id")
	if err != nil {
		return nil, err
	}
	if nonce == "" || subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(nonce)) != 1 {
		return nil, errInvalid
	}
	return claims, nil
}

func oauthError(w http.ResponseWriter, status int, code string) {
	w.WriteHeader(status)
	reply(w, map[string]string{"error": code})
}

func (s *Service) token(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	for _, name := range []string{"grant_type", "code", "redirect_uri", "code_verifier"} {
		if len(r.PostForm[name]) != 1 {
			oauthError(w, http.StatusBadRequest, "invalid_request")
			return
		}
	}
	if r.PostForm.Get("grant_type") != "authorization_code" {
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type")
		return
	}
	id := r.PostForm.Get("client_id")
	basicID, secret, basic := r.BasicAuth()
	if basic {
		var err error
		basicID, err = url.QueryUnescape(basicID)
		if err != nil {
			oauthError(w, http.StatusUnauthorized, "invalid_client")
			return
		}
		secret, err = url.QueryUnescape(secret)
		if err != nil || id != "" && id != basicID {
			oauthError(w, http.StatusUnauthorized, "invalid_client")
			return
		}
		id = basicID
	}
	a := s.client(id)
	if a == nil || len(r.PostForm["client_id"]) > 1 || r.PostForm.Has("client_secret") {
		oauthError(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	if a.ClientSecretEnv != "" {
		if !basic || subtle.ConstantTimeCompare([]byte(secret), []byte(os.Getenv(a.ClientSecretEnv))) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="oauth2/token"`)
			oauthError(w, http.StatusUnauthorized, "invalid_client")
			return
		}
	} else if basic || r.Header.Get("Authorization") != "" {
		oauthError(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	result, _, err := s.exchange(a, r.PostForm.Get("code"), r.PostForm.Get("redirect_uri"), r.PostForm.Get("code_verifier"))
	if err != nil {
		if errors.Is(err, errInvalid) {
			oauthError(w, http.StatusBadRequest, "invalid_grant")
		} else {
			unavailable(w, err)
		}
		return
	}
	reply(w, result)
}

func (s *Service) userinfo(w http.ResponseWriter, r *http.Request) {
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	claims, err := s.parseClaims(strings.TrimPrefix(header, "Bearer "), "", "access")
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	_, user, err := s.lookupSSOHash(claims.SSOHash)
	if errors.Is(err, errInvalid) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if err != nil {
		unavailable(w, err)
		return
	}
	if claims.Subject != strconv.FormatInt(user.ID, 10) || !allowed(s.client(claims.Audience[0]), user) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	reply(w, map[string]string{"sub": claims.Subject, "preferred_username": user.Username})
}
