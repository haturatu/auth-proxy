package middleware

import (
	"auth-proxy/config"
	"auth-proxy/logging"
	"auth-proxy/models"
	"auth-proxy/types"
	"auth-proxy/utils"
	"context"
	"database/sql"
	"net/http"
	"strings"
)

// SessionAuth is a middleware that checks for a valid session cookie.
// If the session is valid, it proceeds. If not, it redirects to the login page.
// This is suitable for protecting frontend routes.
func SessionAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := logging.GetClientIP(r)
		cookie, err := r.Cookie("auth_token")

		if err != nil {
			if err == http.ErrNoCookie {
				logging.AppLog.Info("Redirecting to login (no session cookie)", "path", r.URL.Path, "ip", ip)
				http.Redirect(w, r, config.Paths.Login, http.StatusFound)
				return
			}
			logging.AppLog.Error("Error reading auth cookie", "error", err, "path", r.URL.Path, "ip", ip)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		tokenStr := cookie.Value
		user, err := models.GetUserByToken(tokenStr) // This still relies on the session token in the DB
		if err != nil && err != sql.ErrNoRows {
			logging.AppLog.Error("Error validating session token", "error", err, "path", r.URL.Path, "ip", ip)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		if user == nil {
			// Clear the invalid cookie
			http.SetCookie(w, &http.Cookie{
				Name:   "auth_token",
				Value:  "",
				Path:   "/",
				MaxAge: -1,
			})
			logging.SecurityLog.Warn("ACCESS DENIED", "reason", "invalid or expired session token", "path", r.URL.Path, "ip", ip)
			http.Redirect(w, r, config.Paths.Login, http.StatusFound)
			return
		}

		// Add user info to context and headers for downstream handlers
		ctx := context.WithValue(r.Context(), types.SessionDataContextKey, user)
		r.Header.Set("X-Username", user.Username)
		r.Header.Set("X-User-Role", user.Role)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RedirectIfLoggedIn checks if a user is already logged in.
// If a valid session exists, it redirects them to the account page.
// This is used to prevent logged-in users from accessing public pages like login/register.
func RedirectIfLoggedIn(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only apply this logic for GET requests to avoid interfering with form submissions
		if r.Method != http.MethodGet {
			next.ServeHTTP(w, r)
			return
		}

		cookie, err := r.Cookie("auth_token")
		// If no cookie, they are not logged in, so show the page.
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		// If cookie exists, validate it.
		tokenStr := cookie.Value
		user, err := models.GetUserByToken(tokenStr)

		// If there was an error or the user/token is not found in the DB,
		// it's an invalid token. Let them proceed to the login page
		// where they can get a new one. The old invalid cookie will be cleared on successful login.
		if err != nil || user == nil {
			next.ServeHTTP(w, r)
			return
		}

		// If the user and token are valid, redirect them.
		http.Redirect(w, r, config.Paths.Account, http.StatusFound)
	})
}

// BearerAuth is a middleware that checks for a valid JWT Bearer token.
// If the token is valid, it adds the user info to the context and proceeds.
// If not, it returns a 401 Unauthorized error. Suitable for API endpoints.
func BearerAuth(next http.Handler) http.Handler {
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

		// --- Fallback to Cookie-based session for browser clients ---
		cookie, err := r.Cookie("auth_token")
		if err != nil {
			// No Authorization header AND no cookie, deny access
			logging.SecurityLog.Warn("API ACCESS DENIED", "reason", "missing authentication token", "path", r.URL.Path, "ip", ip)
			http.Error(w, "Unauthorized: An authentication token is required", http.StatusUnauthorized)
			return
		}

		tokenStr := cookie.Value
		user, err := models.GetUserByToken(tokenStr)
		if err != nil || user == nil {
			logging.SecurityLog.Warn("API ACCESS DENIED", "reason", "invalid session cookie", "path", r.URL.Path, "ip", ip)
			http.Error(w, "Unauthorized: Invalid session", http.StatusUnauthorized)
			return
		}

		// User is authenticated via cookie, add to context and proceed
		ctx := context.WithValue(r.Context(), types.SessionDataContextKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
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