package handlers

import (
	"auth-proxy/config"
	"auth-proxy/logging"
	"auth-proxy/middleware"
	"auth-proxy/models"
	"net/http"
	"time"
)

// LogoutHandler invalidates the user's token by expiring the cookie.
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	ip := logging.GetClientIP(r)
	cookie, err := r.Cookie("auth_token")
	if err != nil {
		// No cookie, nothing to do.
		http.Redirect(w, r, config.Paths.Login, http.StatusFound)
		return
	}

	err = models.DeleteAuthToken(cookie.Value)
	if err != nil {
		// Log the error but still proceed with logging the user out client-side.
		logging.AppLog.Error("Failed to delete token on logout", "error", err, "ip", ip)
	}

	// Expire the cookie by setting its max age to a negative number.
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   middleware.CookieSecure(r),
		SameSite: http.SameSiteLaxMode,
	})

	logging.SecurityLog.Info("LOGOUT SUCCESS", "ip", ip)
	http.Redirect(w, r, config.Paths.Login, http.StatusFound)
}
