package handlers

import (
	"auth-proxy/config"
	"auth-proxy/logging"
	"auth-proxy/middleware"
	"auth-proxy/models"
	"auth-proxy/types"
	"errors"
	"html/template"
	"net/http"
	"os"
	"time"
)

// loadTemplates handles both server startup from the repository root and
// package tests running from the handlers/ working directory.
var templates = loadTemplates()

func loadTemplates() *template.Template {
	pattern := "templates/*.html"
	if _, err := os.Stat("templates"); errors.Is(err, os.ErrNotExist) {
		pattern = "../templates/*.html"
	}
	return template.Must(template.ParseGlob(pattern))
}

// authenticateUser handles the core logic for authenticating a user, including brute-force protection.
// It returns the authenticated user or an error if authentication fails.
func authenticateUser(username, password, ip string) (*types.User, error) {
	user, err := models.GetUserByUsername(username)
	if err != nil {
		logging.AppLog.Error("Database error during authentication", "error", err, "username", username, "ip", ip)
		return nil, errors.New("internal server error")
	}

	if user == nil {
		logging.SecurityLog.Warn("AUTH FAIL", "username", username, "ip", ip, "reason", "user not found")
		return nil, errors.New("invalid username or password")
	}

	// An administrator-disabled account must never be re-enabled by a login attempt.
	if !user.IsActive {
		logging.SecurityLog.Warn("AUTH FAIL", "username", username, "ip", ip, "reason", "account disabled")
		return nil, errors.New("account is disabled")
	}

	// Temporary lock is separate from administrative disablement.
	if user.LockedUntil.Valid {
		now := time.Now()
		if now.Before(user.LockedUntil.Time) {
			logging.SecurityLog.Warn("AUTH FAIL", "username", username, "ip", ip, "reason", "temporarily locked")
			return nil, errors.New("account is temporarily locked")
		}
		if err := models.ClearExpiredLoginLock(user.ID, now); err != nil {
			logging.AppLog.Error("Failed to clear expired login lock", "error", err, "user_id", user.ID)
			return nil, errors.New("internal server error")
		}
	}

	// Step 2: If the account is active, validate credentials.
	if !models.CheckPasswordHash(password, user.PasswordHash) {
		// Record the failure
		if err := models.RecordLoginFailure(user.ID); err != nil {
			logging.AppLog.Error("Failed to record login failure", "error", err, "user_id", user.ID, "ip", ip)
		}

		// Re-fetch user to get updated failed_logins count
		updatedUser, _ := models.GetUserByID(user.ID)
		maxAttempts := config.Paths.MaxLoginAttempts

		// Lock the account if max attempts are exceeded
		if maxAttempts > 0 && updatedUser != nil && updatedUser.FailedLogins >= maxAttempts {
			if err := models.SetLoginLock(user.ID, time.Now().Add(time.Duration(config.Paths.LockoutDurationMinutes)*time.Minute)); err != nil {
				logging.AppLog.Error("Failed to lock account", "error", err, "user_id", user.ID, "ip", ip)
			}
			logging.SecurityLog.Warn("ACCOUNT LOCKED", "username", username, "ip", ip)
		}

		logging.SecurityLog.Warn("AUTH FAIL", "username", username, "ip", ip, "reason", "invalid credentials")
		return nil, errors.New("invalid username or password")
	}

	// Step 3: Login successful.
	if err := models.RecordLoginSuccess(user.ID); err != nil {
		logging.AppLog.Error("Failed to record login success", "error", err, "user_id", user.ID, "ip", ip)
	}
	logging.SecurityLog.Info("AUTH SUCCESS", "username", user.Username, "ip", ip)

	return user, nil
}

func renderLoginWithError(w http.ResponseWriter, r *http.Request, message string) {
	data := map[string]interface{}{
		"Paths":           config.Paths,
		"Error":           message,
		"RegisterEnabled": config.Paths.RegisterEnabled,
		"XSRFToken":       middleware.GetXSRFToken(r),
	}
	w.WriteHeader(http.StatusUnauthorized) // Set status to indicate failure
	if err := templates.ExecuteTemplate(w, "login.html", data); err != nil {
		logging.AppLog.Error("Failed to execute login template with error", "error", err)
	}
}

// LoginHandler handles displaying the login form and processing login requests.
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	ip := logging.GetClientIP(r)

	// If user is already logged in, redirect to account page
	cookie, err := r.Cookie("auth_token")
	if err == nil {
		user, _ := models.GetUserByToken(cookie.Value)
		if user != nil && user.IsActive {
			http.Redirect(w, r, config.Paths.Account, http.StatusFound)
			return
		}
	}

	if r.Method == http.MethodGet {
		data := map[string]interface{}{
			"Paths":           config.Paths,
			"RegisterEnabled": config.Paths.RegisterEnabled,
			"XSRFToken":       middleware.GetXSRFToken(r),
		}
		if err := templates.ExecuteTemplate(w, "login.html", data); err != nil {
			logging.AppLog.Error("Failed to execute login template", "error", err, "ip", ip)
		}
		return
	}

	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			logging.AppLog.Error("Failed to parse login form", "error", err, "ip", ip)
			renderLoginWithError(w, r, "An internal error occurred. Please try again.")
			return
		}
		username := r.FormValue("username")
		password := r.FormValue("password")

		user, err := authenticateUser(username, password, ip)
		if err != nil {
			// Map authentication error to user-facing message
			errMsg := "Invalid username or password."
			if err.Error() == "account is disabled" {
                errMsg = "Account is disabled. Contact the administrator."
            } else if err.Error() == "account is temporarily locked" {
				errMsg = "Account is temporarily locked."
			} else if err.Error() == "internal server error" {
				errMsg = "An internal error occurred. Please try again."
			} else if err.Error() == "account has been unlocked, please try again" {
				errMsg = "Account has been unlocked. Please try logging in again."
			}
			renderLoginWithError(w, r, errMsg)
			return
		}

		// --- Create Session Cookie ---
		duration := time.Duration(config.Paths.TokenDurationHours) * time.Hour

		token, err := models.CreateAuthToken(user.ID, duration)
		if err != nil {
			logging.AppLog.Error("Failed to create auth token", "error", err, "username", user.Username, "ip", ip)
			renderLoginWithError(w, r, "Could not create session.")
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "auth_token",
			Value:    token.Token,
			Expires:  token.ExpiresAt,
			Path:     "/",
			HttpOnly: true,
			Secure:   middleware.CookieSecure(r),
			SameSite: http.SameSiteLaxMode,
		})

		// Redirect to the root path, which is the proxied application.
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	w.WriteHeader(http.StatusMethodNotAllowed)
}
