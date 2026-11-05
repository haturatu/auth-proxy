// Package sso implements the opt-in identity provider and Nginx gateway.
package sso

import (
	"auth-proxy/config"
	"auth-proxy/logging"
	"auth-proxy/middleware"
	"auth-proxy/types"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

const (
	ssoCookie    = "__Host-sso_session"
	appCookie    = "__Host-app_session"
	ssoLifetime  = 12 * time.Hour
	appLifetime  = 8 * time.Hour
	flowLifetime = 5 * time.Minute
)

var errInvalid = errors.New("invalid or expired credential")

type PasswordAuthenticator func(username, password, ip string) (*types.User, error)

type Service struct {
	config              *config.SSOConfig
	wa                  *webauthn.WebAuthn
	key                 *rsa.PrivateKey
	kid                 string
	box                 cipher.AEAD
	peers               []*net.IPNet
	issuerHost          string
	password            PasswordAuthenticator
	registrationLimiter *types.RateLimiter
	handler             http.Handler
}

// New requires a persistent RSA signing key so restarts and multiple replicas
// publish the same JWKS. No ephemeral production signing keys are generated.
func New(c *config.SSOConfig, password PasswordAuthenticator, limiter, registrationLimiter *types.RateLimiter) (*Service, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	key, err := config.LoadSSOSigningKey()
	if err != nil {
		return nil, err
	}
	if len(os.Getenv("SESSION_SECRET")) < 32 {
		return nil, errors.New("SESSION_SECRET must contain at least 32 characters")
	}
	secret, err := hkdf.Key(sha256.New, []byte(os.Getenv("SESSION_SECRET")), nil, "auth-proxy/sso-records/v1", 32)
	if err != nil {
		return nil, err
	}
	aesBlock, err := aes.NewCipher(secret)
	if err != nil {
		return nil, err
	}
	box, err := cipher.NewGCM(aesBlock)
	if err != nil {
		return nil, err
	}
	wa, err := webauthn.New(&webauthn.Config{
		RPID: c.WebAuthn.RPID, RPDisplayName: "auth-proxy", RPOrigins: c.WebAuthn.Origins,
		AuthenticatorSelection: protocol.AuthenticatorSelection{ResidentKey: protocol.ResidentKeyRequirementRequired, UserVerification: protocol.VerificationRequired},
	})
	if err != nil {
		return nil, err
	}
	u, _ := url.Parse(c.Issuer)
	digest := sha256.Sum256(x509.MarshalPKCS1PublicKey(&key.PublicKey))
	s := &Service{config: c, key: key, kid: base64.RawURLEncoding.EncodeToString(digest[:16]), box: box, wa: wa, issuerHost: u.Host, password: password, registrationLimiter: registrationLimiter}
	for _, cidr := range c.TrustedGatewayCIDRs {
		_, network, _ := net.ParseCIDR(cidr)
		s.peers = append(s.peers, network)
	}
	if err = s.syncClients(); err != nil {
		return nil, err
	}
	s.handler = s.routes(limiter)
	return s, nil
}

func (s *Service) routes(limiter *types.RateLimiter) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /internal/authz", s.authz)
	mux.HandleFunc("GET /gateway/start", s.start)
	mux.HandleFunc("GET /gateway/callback", s.callback)
	mux.HandleFunc("POST /gateway/logout", s.appLogout)
	mux.HandleFunc("GET /.well-known/openid-configuration", s.discovery)
	mux.HandleFunc("GET /oauth2/jwks", s.jwks)
	mux.HandleFunc("GET /oauth2/authorize", s.authorize)
	mux.HandleFunc("POST /oauth2/token", s.token)
	mux.HandleFunc("GET /oauth2/userinfo", s.userinfo)
	mux.HandleFunc("GET /sso/login", s.loginPage)
	mux.HandleFunc("GET /sso/account", s.accountPage)
	mux.HandleFunc("GET /sso/assets/passkeys.js", s.javascript)
	mux.HandleFunc("GET /sso/assets/style.css", s.stylesheet)
	mux.HandleFunc("POST /sso/password", s.passwordLogin)
	mux.HandleFunc("POST /sso/logout", s.logout)
	mux.Handle("POST /webauthn/register/begin", middleware.RateLimitMiddleware(s.registrationLimiter)(http.HandlerFunc(s.registerBegin)))
	mux.HandleFunc("POST /webauthn/register/finish", s.registerFinish)
	mux.HandleFunc("POST /webauthn/login/begin", s.loginBegin)
	mux.HandleFunc("POST /webauthn/login/finish", s.loginFinish)
	mux.HandleFunc("GET /webauthn/credentials", s.listCredentials)
	mux.HandleFunc("DELETE /webauthn/credentials/{id}", s.deleteCredential)
	limited := middleware.RateLimitAllMethods(limiter)(mux)
	return middleware.LimitAuthBody(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/sso/password" || r.URL.Path == "/oauth2/token" || r.URL.Path == "/oauth2/authorize" || strings.HasPrefix(r.URL.Path, "/webauthn/") && r.Method != "GET" {
			limited.ServeHTTP(w, r)
		} else {
			mux.ServeHTTP(w, r)
		}
	}))
}

// Owns reserves namespaces even when the feature is disabled, so authentication
// URLs cannot fall through to an application with different path semantics.
func Owns(path string) bool {
	return config.SSOPath(path)
}

func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	if r.Host != s.issuerHost {
		http.Error(w, "Misdirected Request", http.StatusMisdirectedRequest)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/internal/") || strings.HasPrefix(r.URL.Path, "/gateway/") {
		if !s.trustedPeer(r) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
	} else if r.Method != "GET" && r.URL.Path != "/oauth2/token" {
		// Origin is mandatory, including for login and passkey registration.
		// Lax alone does not prevent same-site sibling-domain CSRF.
		if r.Header.Get("Origin") != s.config.Issuer {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
	}
	s.handler.ServeHTTP(w, r)
}

func (s *Service) trustedPeer(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	for _, peer := range s.peers {
		if peer.Contains(ip) {
			return true
		}
	}
	return false
}

func (s *Service) application(r *http.Request) (*config.Application, error) {
	for i := range s.config.Applications {
		a := &s.config.Applications[i]
		u, _ := url.Parse(a.Origin)
		if a.ID == r.Header.Get("X-Auth-App-ID") && u.Host == r.Header.Get("X-Original-Host") {
			return a, nil
		}
	}
	return nil, errInvalid
}

func (s *Service) client(id string) *config.Application {
	for i := range s.config.Applications {
		if s.config.Applications[i].ID == id {
			return &s.config.Applications[i]
		}
	}
	return nil
}

func allowed(a *config.Application, u *types.User) bool {
	return u != nil && u.IsActive && slices.Contains(a.Roles, u.Role)
}

func setCookie(w http.ResponseWriter, name, value string, lifetime time.Duration) {
	c := &http.Cookie{Name: name, Value: value, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, Path: "/", MaxAge: int(lifetime.Seconds()), Expires: time.Now().Add(lifetime)}
	if lifetime < 0 {
		c.MaxAge = -1
		c.Expires = time.Unix(1, 0)
	}
	http.SetCookie(w, c)
}

// Duplicate cookies fail closed rather than accepting an ambiguous credential.
func readCookie(r *http.Request, name string) (string, error) {
	var result string
	for _, c := range r.Cookies() {
		if c.Name == name {
			if result != "" || c.Value == "" {
				return "", errInvalid
			}
			result = c.Value
		}
	}
	if result == "" || len(result) > 128 {
		return "", errInvalid
	}
	return result, nil
}

func randomToken() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func reply(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		logging.AppLog.Error("Failed to encode SSO response", "error", err)
	}
}

func unavailable(w http.ResponseWriter, err error) {
	logging.AppLog.Error("SSO operation failed", "error", err)
	http.Error(w, "Authentication service unavailable", http.StatusServiceUnavailable)
}

func localPath(raw string) (string, error) {
	u, err := url.ParseRequestURI(raw)
	if err != nil || u.IsAbs() || u.Host != "" || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.ContainsAny(raw, "\\\r\n") {
		return "", errInvalid
	}
	// Decode before checking, so encoded slashes/backslashes cannot become an
	// authority in a browser or a later proxy normalization step.
	if strings.HasPrefix(u.Path, "//") || strings.ContainsAny(u.Path, "\\\r\n") || strings.HasPrefix(u.Path, "/_auth/") {
		return "", errInvalid
	}
	return raw, nil
}

func (s *Service) currentSSO(r *http.Request) (*session, *types.User, error) {
	raw, err := readCookie(r, ssoCookie)
	if err != nil {
		return nil, nil, errInvalid
	}
	return s.lookupSSO(raw)
}

func (s *Service) issueSSO(w http.ResponseWriter, r *http.Request, user *types.User) error {
	previous, _ := readCookie(r, ssoCookie)
	raw, err := s.replaceSSO(user, previous)
	if err != nil {
		return err
	}
	setCookie(w, ssoCookie, raw, ssoLifetime)
	logging.SecurityLog.Info("SSO login succeeded", "user_id", user.ID)
	return nil
}
