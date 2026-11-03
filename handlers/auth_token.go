package handlers

import (
	"auth-proxy/config"
	"auth-proxy/logging"
	"auth-proxy/models"
	"auth-proxy/utils"
	"encoding/json"
    "errors"
	"net/http"
	"time"
)

// RefreshTokenHandler handles exchanging a valid refresh token for a new access token.
func RefreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	ip := logging.GetClientIP(r)

	// 1. Parse request body
	var reqBody struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if reqBody.RefreshToken == "" {
		http.Error(w, "Missing refresh_token", http.StatusBadRequest)
		return
	}

	// 2. Validate the refresh token in DB
	refreshToken, err := models.GetRefreshTokenByToken(reqBody.RefreshToken)
	if err != nil {
		logging.AppLog.Error("Error getting refresh token from DB", "error", err, "ip", ip)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if refreshToken == nil || refreshToken.IsRevoked || time.Now().After(refreshToken.ExpiresAt) {
		logging.SecurityLog.Warn("REFRESH TOKEN FAIL", "reason", "token not found, revoked, or expired", "ip", ip)
		http.Error(w, "Unauthorized: Invalid refresh token", http.StatusUnauthorized)
		return
	}

	// 3. Get user info
	user, err := models.GetUserByID(refreshToken.UserID)
	if err != nil || user == nil {
		logging.AppLog.Error("Failed to get user from refresh token", "error", err, "user_id", refreshToken.UserID, "ip", ip)
		http.Error(w, "Unauthorized: User not found", http.StatusUnauthorized)
		return
	}

	if !user.IsActive {
		logging.SecurityLog.Warn("REFRESH TOKEN FAIL", "reason", "inactive account", "user_id", user.ID, "ip", ip)
		http.Error(w, "Unauthorized: account inactive", http.StatusUnauthorized)
		return
	}

	// 4. Issue a new access token
	newAccessToken, err := utils.GenerateJWT(user, time.Duration(config.Paths.AccessTokenDurationMinutes)*time.Minute)
	if err != nil {
		logging.AppLog.Error("Failed to generate new access token", "error", err, "username", user.Username, "ip", ip)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Consume the supplied refresh credential exactly once and replace it in
	// the same database transaction. Concurrent replays must not issue tokens.
	newRefreshToken, err := models.RotateRefreshToken(reqBody.RefreshToken, user.ID, time.Duration(config.Paths.RefreshTokenDurationDays)*24*time.Hour)
	if err != nil {
		if errors.Is(err, models.ErrRefreshTokenSpent) {
			http.Error(w, "Unauthorized: invalid refresh token", http.StatusUnauthorized)
		} else {
			logging.AppLog.Error("Failed to rotate refresh token", "error", err, "ip", ip)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		return
	}

	// 7. Respond with new tokens
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]string{
		"access_token":  newAccessToken,
		"refresh_token": newRefreshToken.Token,
	}); err != nil {
		logging.AppLog.Error("Failed to encode token response", "error", err, "ip", ip)
	}
}

// TokenHandler handles issuing JWT tokens for API clients.
func TokenHandler(w http.ResponseWriter, r *http.Request) {
	ip := logging.GetClientIP(r)

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Use the shared authentication logic
	user, err := authenticateUser(creds.Username, creds.Password, ip)
	if err != nil {
		// Return a generic error to the API client
		http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

	// --- Issue Tokens ---
	// Access Token
	accessToken, err := utils.GenerateJWT(user, time.Duration(config.Paths.AccessTokenDurationMinutes)*time.Minute)
	if err != nil {
		logging.AppLog.Error("Failed to generate access token", "error", err, "username", user.Username, "ip", ip)
		http.Error(w, "Failed to generate access token", http.StatusInternalServerError)
		return
	}

	// Refresh Token
	refreshToken, err := models.CreateRefreshToken(user.ID, time.Duration(config.Paths.RefreshTokenDurationDays)*24*time.Hour)
	if err != nil {
		logging.AppLog.Error("Failed to create refresh token", "error", err, "username", user.Username, "ip", ip)
		http.Error(w, "Failed to create refresh token", http.StatusInternalServerError)
		return
	}
	// --- End Issue Tokens ---

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken.Token,
	}); err != nil {
		logging.AppLog.Error("Failed to encode token response", "error", err, "ip", ip)
	}
}
