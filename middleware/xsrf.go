package middleware

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"os"
	"time"

	"github.com/haturatu/xsrftoken"
)

const (
	xsrfHeaderName      = "X-XSRF-Token"
	xsrfFormField       = "xsrf_token"
	anonymousCSRFCookie = "anon_xsrf"
)

type xsrfContextKey string

const xsrfTokenKey = xsrfContextKey("xsrfToken")

func xsrfSecret() ([]byte, bool) {
	secret, err := base64.StdEncoding.DecodeString(os.Getenv("XSRF_SECRET_KEY"))
	return secret, err == nil && len(secret) == 32
}

func sessionID(r *http.Request) string {
	if cookie, err := r.Cookie("auth_token"); err == nil && cookie.Value != "" {
		return "auth:" + cookie.Value
	}
	if cookie, err := r.Cookie(anonymousCSRFCookie); err == nil && cookie.Value != "" {
		return "anonymous:" + cookie.Value
	}
	return ""
}

func isUnsafeMethod(method string) bool {
	return method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions
}

// Keep xsrftoken even when using Go 1.25+ http.CrossOriginProtection.
// CrossOriginProtection checks cross-origin signals (Sec-Fetch-Site / Origin),
// but it does NOT mint or validate a per-session CSRF token. In particular,
// requests without these browser headers (e.g. older clients or scripts) can
// pass its origin check. xsrftoken independently binds unsafe form submissions
// to the caller's session (anonymous or authenticated), the requested action,
// and a 15-minute expiration. These are complementary defenses, not duplicates.
// A browser on another home VLAN accessing http://192.168.x.x:8080 at the same
// origin is still allowed without trusting the source IP address.
func verifyXSRF(r *http.Request, scope string, secret []byte) bool {
	sid := sessionID(r)
	if sid == "" {
		return false
	}
	token := r.Header.Get(xsrfHeaderName)
	if token == "" {
		token = r.FormValue(xsrfFormField)
	}
	return xsrftoken.ValidFor(token, string(secret), sid, scope, 15*time.Minute)
}

// ValidateSessionXSRF validates dashboard-issued tokens used by cookie-authenticated
// admin API writes. Requests authenticated with a Bearer token do not need a CSRF token.
func ValidateSessionXSRF(r *http.Request, scope string) bool {
	secret, ok := xsrfSecret()
	if !ok {
		return false
	}
	if cookie, err := r.Cookie("auth_token"); err != nil || cookie.Value == "" {
		return false
	}
	return verifyXSRF(r, scope, secret)
}

func XSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secret, ok := xsrfSecret()
		if !ok {
			http.Error(w, "XSRF configuration error", http.StatusInternalServerError)
			return
		}
		sid := sessionID(r)
		if sid == "" && !isUnsafeMethod(r.Method) {
			var random [32]byte
			if _, err := rand.Read(random[:]); err != nil {
				http.Error(w, "Failed to establish CSRF session", http.StatusInternalServerError)
				return
			}
			id := base64.RawURLEncoding.EncodeToString(random[:])
			http.SetCookie(w, &http.Cookie{
				Name: anonymousCSRFCookie, Value: id, Path: "/",
				HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: CookieSecure(r),
				MaxAge: 24 * 60 * 60,
			})
			sid = "anonymous:" + id
		}
		if isUnsafeMethod(r.Method) && !verifyXSRF(r, r.URL.Path, secret) {
			http.Error(w, "Invalid XSRF token", http.StatusForbidden)
			return
		}
		// For first-time visitors, sid was just generated and the request has
		// no cookie yet; use that same id for the token returned in the form.
		token := xsrftoken.Generate(string(secret), sid, r.URL.Path)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), xsrfTokenKey, token)))
	})
}

func GetXSRFToken(r *http.Request) string {
	if token, ok := r.Context().Value(xsrfTokenKey).(string); ok {
		return token
	}
	return ""
}
