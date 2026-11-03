package middleware

import (
	"auth-proxy/config"
	"auth-proxy/logging"
	"encoding/json"
    "errors"
	"net/http"
	"net/url"
	"strings"
)

// APIAuth selects the permitted authentication plane. Cookie authentication is
// deliberately opt-in; in either mode a supplied Authorization header is
// authoritative and a failed Bearer check never falls back to a cookie.
func APIAuth(mode string, next http.Handler) http.Handler {
	switch mode {
	case "session":
		return SessionAPIAuth(next)
	case "either":
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "" {
				BearerAuth(next).ServeHTTP(w, r)
				return
			}
			SessionAPIAuth(next).ServeHTTP(w, r)
		})
	default:
		return BearerAuth(next)
	}
}

// SessionAPIAuth authenticates API requests using an HttpOnly session cookie.
// It never redirects ordinary API requests to an HTML login page. GET/HEAD
// permit EventSource and other browser subresources without custom headers.
func SessionAPIAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			writeAPIError(w, r, http.StatusUnauthorized, "session mode does not accept Authorization")
			return
		}
		if !sameOriginRequest(r) {
			writeAPIError(w, r, http.StatusForbidden, "cross-origin session request denied")
			return
		}
		// origin mode already requires a browser-verified same-origin
		// Sec-Fetch-Site/Origin/Referer on unsafe requests. xsrf mode adds a
		// session-bound token for deployments that can update the client.
		if isUnsafeMethod(r.Method) &&
			config.Paths.APISessionCSRF == "xsrf" &&
			!ValidateSessionXSRF(r, config.Paths.APIPath) {
			writeAPIError(w, r, http.StatusForbidden, "CSRF token required")
			return
		}
		user, err := resolveSessionUser(r)
		if err != nil {
			switch {
			case errors.Is(err, ErrMissingSession):
				writeAPIError(w, r, http.StatusUnauthorized, "authentication required")
			case errors.Is(err, ErrInvalidSession):
				expireSessionCookie(w, r)
				writeAPIError(w, r, http.StatusUnauthorized, "invalid session")
			default:
				writeAPIError(w, r, http.StatusInternalServerError, "session lookup failed")
			}
			return
		}
		next.ServeHTTP(w, sessionUserRequest(r, user))
	})
}

// SessionXSRFEndpoint provides a session-bound token to same-origin SPAs for
// modifying requests. EventSource, WebSocket and read-only endpoints do not
// need to fetch this token.
func SessionXSRFEndpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeAPIError(w, r, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	SessionAPIAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := GenerateSessionXSRF(r, config.Paths.APIPath)
		if !ok {
			writeAPIError(w, r, http.StatusInternalServerError, "CSRF secret unavailable")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]string{"xsrf_token": token})
	})).ServeHTTP(w, r)
}

// sameOriginRequest is stricter than CrossOriginProtection for cookie-based
// API access. CrossOriginProtection deliberately allows absent browser signals,
// and GET WebSocket upgrades are safe HTTP methods but unsafe WS handshakes.
// Here WS requires an exact Origin; all other requests reject conflicting
// Fetch Metadata, Origin and Referer signals. No source-IP allowlist is used.
func sameOriginRequest(r *http.Request) bool {
	switch strings.ToLower(r.Header.Get("Sec-Fetch-Site")) {
	case "", "same-origin", "none":
	default:
		return false
	}
	origin := r.Header.Get("Origin")
	if isWebSocketUpgrade(r) && origin == "" {
		return false
	}
	if origin != "" && !sameOriginURL(r, origin) {
		return false
	}
	if referer := r.Header.Get("Referer"); referer != "" && !sameOriginURL(r, referer) {
		return false
	}
	if isUnsafeMethod(r.Method) && origin == "" && r.Header.Get("Sec-Fetch-Site") == "" && r.Header.Get("Referer") == "" {
		return false
	}
	return true
}

func sameOriginURL(r *http.Request, raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.User != nil || u.Host == "" || u.Scheme == "" {
		return false
	}
	scheme := logging.GetClientScheme(r)
	if !strings.EqualFold(u.Scheme, scheme) {
		return false
	}
	expected, err := url.Parse(scheme + "://" + r.Host)
	if err != nil || expected.Hostname() == "" {
		return false
	}
	if !strings.EqualFold(strings.TrimSuffix(u.Hostname(), "."), strings.TrimSuffix(expected.Hostname(), ".")) {
		return false
	}
	normalizePort := func(port, scheme string) string {
		if port != "" {
			return port
		}
		if scheme == "https" {
			return "443"
		}
		return "80"
	}
	return normalizePort(u.Port(), scheme) == normalizePort(expected.Port(), scheme)
}

func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(strings.TrimSpace(r.Header.Get("Upgrade")), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

func writeAPIError(w http.ResponseWriter, r *http.Request, status int, message string) {
	w.Header().Set("Cache-Control", "no-store")
	if status == http.StatusUnauthorized {
		w.Header().Set("X-Login-URL", config.Paths.Login)
		if strings.EqualFold(r.Header.Get("Sec-Fetch-Mode"), "navigate") &&
			strings.Contains(r.Header.Get("Accept"), "text/html") {
			http.Redirect(w, r, config.Paths.Login, http.StatusFound)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
