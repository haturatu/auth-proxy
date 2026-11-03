package handlers

import (
	"auth-proxy/config"
	"auth-proxy/logging"
	"auth-proxy/middleware"
	"auth-proxy/models"
	"auth-proxy/types"
	"auth-proxy/utils"
	"encoding/json"
	"net/http"
)

// AccountPageHandler serves the account page, passing user data to the template.
func AccountPageHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := r.Context().Value(types.SessionDataContextKey).(*types.User)
	if !ok || user == nil {
		// This should ideally not happen if AuthMiddleware is working correctly.
		http.Error(w, "User not authenticated", http.StatusUnauthorized)
		return
	}

	data := map[string]interface{}{
		"Paths":     config.Paths,
		"User":      user,
		"XSRFToken": middleware.GetXSRFToken(r),
	}
	if err := templates.ExecuteTemplate(w, "account.html", data); err != nil {
		logging.AppLog.Error("Failed to execute account template", "error", err, "user_id", user.ID)
	}
}

// ChangePasswordHandler handles both displaying the page (GET) and processing the update (POST).
func ChangePasswordHandler(w http.ResponseWriter, r *http.Request) {
	// For GET request, just serve the page.
	if r.Method == http.MethodGet {
		data := map[string]interface{}{
			"Paths":     config.Paths,
			"XSRFToken": middleware.GetXSRFToken(r),
		}
		if err := templates.ExecuteTemplate(w, "account_password.html", data); err != nil {
			logging.AppLog.Error("Failed to execute account_password template", "error", err)
		}
		return
	}

	// POST request logic (API call)
	if r.Method == http.MethodPost {
		// This is a protected route, so AuthMiddleware should have put the user in the context.
		user, ok := r.Context().Value(types.SessionDataContextKey).(*types.User)
		if !ok || user == nil {
			http.Error(w, "User not authenticated", http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		if err := r.ParseForm(); err != nil {
			logging.AppLog.Error("Failed to parse change password form", "error", err)
			w.WriteHeader(http.StatusBadRequest)
			if err := json.NewEncoder(w).Encode(map[string]string{"error": "Could not read request."}); err != nil {
				logging.AppLog.Error("Failed to encode json error response", "error", err)
			}
			return
		}
		currentPassword := r.FormValue("current_password")
		newPassword := r.FormValue("new_password")
		confirmNewPassword := r.FormValue("confirm_new_password")

		if ok, message := utils.ValidatePassword(newPassword); !ok {
			w.WriteHeader(http.StatusBadRequest)
			if err := json.NewEncoder(w).Encode(map[string]string{"error": message}); err != nil {
				logging.AppLog.Error("Failed to encode json error response", "error", err)
			}
			return
		}

		if newPassword != confirmNewPassword {
			w.WriteHeader(http.StatusBadRequest)
			if err := json.NewEncoder(w).Encode(map[string]string{"error": "New passwords do not match."}); err != nil {
				logging.AppLog.Error("Failed to encode json error response", "error", err)
			}
			return
		}

		dbUser, err := models.GetUserByID(user.ID)
		if err != nil || dbUser == nil {
			w.WriteHeader(http.StatusInternalServerError)
			if err := json.NewEncoder(w).Encode(map[string]string{"error": "Could not retrieve user data."}); err != nil {
				logging.AppLog.Error("Failed to encode json error response", "error", err)
			}
			return
		}

		if !models.CheckPasswordHash(currentPassword, dbUser.PasswordHash) {
			w.WriteHeader(http.StatusUnauthorized)
			if err := json.NewEncoder(w).Encode(map[string]string{"error": "Current password is incorrect."}); err != nil {
				logging.AppLog.Error("Failed to encode json error response", "error", err)
			}
			return
		}

		newPasswordHash, err := models.HashPassword(newPassword)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			if err := json.NewEncoder(w).Encode(map[string]string{"error": "Failed to process new password."}); err != nil {
				logging.AppLog.Error("Failed to encode json error response", "error", err)
			}
			return
		}

		if err := models.UpdateUserPassword(dbUser.ID, newPasswordHash); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			if err := json.NewEncoder(w).Encode(map[string]string{"error": "Failed to update password."}); err != nil {
				logging.AppLog.Error("Failed to encode json error response", "error", err)
			}
			return
		}

		// Expire this caller's browser session after the DB transaction revokes
		// all stored browser/refresh credentials for the user.
		http.SetCookie(w, &http.Cookie{
			Name: "auth_token", Path: "/", MaxAge: -1, HttpOnly: true,
			Secure: middleware.CookieSecure(r), SameSite: http.SameSiteLaxMode,
		})
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(map[string]string{"message": "Password updated successfully."}); err != nil {
			logging.AppLog.Error("Failed to encode json error response", "error", err)
		}
		return
	}

	// Handle other methods
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}
