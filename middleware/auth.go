package middleware

import (
	"auth-proxy/config"
	"auth-proxy/logging"
	"auth-proxy/models"
	"auth-proxy/types"
	"auth-proxy/utils"
	"context"
	"database/sql"
    "errors"
	"net/http"
	"strings"
)

// SessionAuth is a middleware that checks for a valid session cookie.
// If the session is valid, it proceeds. If not, it redirects to the login page.
// This is suitable for protecting frontend routes.
func SessionAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := logging.GetClientIP(r)
		// WebSocket handshakes are GET requests but must still validate
		// Origin to prevent cross-site WebSocket hijacking.
		if (isWebSocketUpgrade(r) || isUnsafeMethod(r.Method)) && !sameOriginRequest(r) {
			http.Error(w, "Cross-origin session request denied", http.StatusForbidden)
			return
		}
		user, err := resolveSessionUser(r)
		if err != nil {
			if errors.Is(err, ErrMissingSession) {
				logging.AppLog.Info("Redirecting to login (no session cookie)", "path", r.URL.Path, "ip", ip)
				http.Redirect(w, r, config.Paths.Login, http.StatusFound)
				return
			}
			if errors.Is(err, ErrInvalidSession) {
				expireSessionCookie(w, r)
				logging.SecurityLog.Warn("ACCESS DENIED", "reason", "invalid or expired session", "path", r.URL.Path, "ip", ip)
				http.Redirect(w, r, config.Paths.Login, http.StatusFound)
				return
			}
			logging.AppLog.Error("Session database lookup failed", "error", err, "path", r.URL.Path, "ip", ip)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		next.ServeHTTP(w, sessionUserRequest(r, user))
	})
}

// BearerAuth accepts JWT Bearer authentication only. Browser cookies must
// never silently authorize proxied API calls, including read-only requests.
func BearerAuth(next http.Handler) http.Handler { return bearerAuth(next, false) }

// AdminBearerAuth permits session-cookie authentication for the browser admin
// UI, with a signed CSRF token required on unsafe methods.
func AdminBearerAuth(next http.Handler) http.Handler {
	return bearerAuth(next, true)
}

func bearerAuth(next http.Handler, allowAdminCookie bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := logging.GetClientIP(r)
		authHeader := r.Header.Get("Authorization")

		// Prefer Authorization header if it exists
		if authHeader != "" {
			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
				logging.SecurityLog.Warn("API ACCESS DENIED", "reason", "invalid authorization header format", "path", r.URL.Path, "ip", ip)
				http.Error(w, "Unauthorized: Invalid authorization header format", http.StatusUnauthorized)
				return
			}

			tokenString := parts[1]
			payload, err := utils.ValidateJWT(tokenString)
			if err != nil {
				logging.SecurityLog.Warn("API ACCESS DENIED", "reason", "invalid JWT token", "error", err.Error(), "path", r.URL.Path, "ip", ip)
				http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
				return
			}

			user, err := models.GetUserByID(payload.UserID)
			if err != nil || user == nil {
				if err == sql.ErrNoRows || user == nil {
					logging.SecurityLog.Error("API ACCESS DENIED", "reason", "user from token not found", "user_id", payload.UserID, "path", r.URL.Path, "ip", ip)
					http.Error(w, "Unauthorized: User not found", http.StatusUnauthorized)
				} else {
					logging.AppLog.Error("Error fetching user from DB", "error", err, "user_id", payload.UserID, "path", r.URL.Path, "ip", ip)
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				}
				return
			}

			if !user.IsActive {
				logging.SecurityLog.Warn("API ACCESS DENIED", "reason", "user is inactive", "user_id", user.ID, "path", r.URL.Path, "ip", ip)
				http.Error(w, "Forbidden: User account is inactive", http.StatusForbidden)
				return
			}

			// Add user info to context and proceed
			ctx := context.WithValue(r.Context(), types.SessionDataContextKey, user)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		if !allowAdminCookie {
			logging.SecurityLog.Warn("API ACCESS DENIED", "reason", "Bearer token required", "path", r.URL.Path, "ip", ip)
			http.Error(w, "Unauthorized: Bearer token required", http.StatusUnauthorized)
			return
		}

		// Only the first-party admin UI may authenticate via a browser cookie.
		// CrossOriginProtection and the signed xsrftoken are complementary:
		// the former checks browser origin signals, the latter binds mutations
		// to the authenticated session even when origin headers are absent.
		if isUnsafeMethod(r.Method) && !ValidateSessionXSRF(r, config.Paths.Admin) {
			http.Error(w, "CSRF token required for cookie-authenticated writes", http.StatusForbidden)
			return
		}
		user, err := resolveSessionUser(r)
		if err != nil {
			logging.SecurityLog.Warn("API ACCESS DENIED", "reason", "invalid session cookie", "path", r.URL.Path, "ip", ip)
			if !errors.Is(err, ErrMissingSession) && !errors.Is(err, ErrInvalidSession) {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			} else {
				http.Error(w, "Unauthorized: Invalid session", http.StatusUnauthorized)
			}
			return
		}
		next.ServeHTTP(w, sessionUserRequest(r, user))
	})
}

// AdminMiddleware checks if the user has the 'admin' role.
// This middleware should be used after either SessionAuth or BearerAuth.
func AdminMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := logging.GetClientIP(r)
		// Get user from context
		user, ok := r.Context().Value(types.SessionDataContextKey).(*types.User)
		if !ok || user == nil {
			logging.SecurityLog.Warn("ADMIN ACCESS DENIED", "reason", "no user data in context", "path", r.URL.Path, "ip", ip)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		if user.Role != "admin" {
			logging.SecurityLog.Warn("ADMIN ACCESS DENIED", "reason", "insufficient permissions", "user", user.Username, "role", user.Role, "path", r.URL.Path, "ip", ip)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		logging.SecurityLog.Info("ADMIN ACCESS GRANTED", "user", user.Username, "path", r.URL.Path, "ip", ip)
		next.ServeHTTP(w, r)
	})
}

// HandleOptions is a middleware that handles pre-flight OPTIONS requests.
// This should be placed before the XSRF middleware.
func HandleOptions(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}
