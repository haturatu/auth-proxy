package models

import (
	"auth-proxy/database"
	"auth-proxy/types"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"time"
)

// GenerateSecureToken creates a random, secure token.
func GenerateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// CreateAuthToken creates a new token for a user, deleting any existing ones.
func CreateAuthToken(userID int64, duration time.Duration) (*types.AuthToken, error) {
	tokenString, err := GenerateSecureToken(32)
	if err != nil {
		return nil, err
	}

	expiresAt := time.Now().Add(duration)

	tx, err := database.DB.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	// Insert the new token
	insertQuery := database.Rebind("INSERT INTO auth_tokens (user_id, token, expires_at) VALUES (?, ?, ?)")
	if _, err := tx.Exec(insertQuery, userID, tokenString, expiresAt); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return &types.AuthToken{
		UserID:    userID,
		Token:     tokenString,
		ExpiresAt: expiresAt,
	}, nil
}

// GetUserByToken retrieves a user associated with a given token.
// It returns the user if the token is valid and not expired.
func GetUserByToken(tokenString string) (*types.User, error) {
	query := database.Rebind("SELECT u.id, u.username, u.password_hash, u.role, u.is_active, u.failed_logins, u.last_login_at, u.created_at, u.updated_at FROM users u JOIN auth_tokens t ON u.id = t.user_id WHERE t.token = ? AND t.expires_at > ?")

	row := database.DB.QueryRow(query, tokenString, time.Now())

	user := &types.User{}
	err := row.Scan(&user.ID, &user.Username, &user.PasswordHash, &user.Role, &user.IsActive, &user.FailedLogins, &user.LastLoginAt, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // Token not found or expired, not a server error
		}
		return nil, err
	}

	return user, nil
}

// DeleteAuthToken deletes a token from the database.
func DeleteAuthToken(tokenString string) error {
	query := database.Rebind("DELETE FROM auth_tokens WHERE token = ?")
	_, err := database.DB.Exec(query, tokenString)
	return err
}

// DeleteExpiredTokens cleans up expired tokens from the database.
func DeleteExpiredTokens() (int64, error) {
	query := database.Rebind("DELETE FROM auth_tokens WHERE expires_at < ?")
	res, err := database.DB.Exec(query, time.Now())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// CreateRefreshToken creates a new refresh token for a user.
func CreateRefreshToken(userID int64, duration time.Duration) (*types.RefreshToken, error) {
	tokenString, err := GenerateSecureToken(32)
	if err != nil {
		return nil, err
	}

	expiresAt := time.Now().Add(duration)

	tx, err := database.DB.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	// Insert the new refresh token
	insertQuery := database.Rebind("INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES (?, ?, ?)")
	if _, err := tx.Exec(insertQuery, userID, tokenString, expiresAt); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return &types.RefreshToken{
		UserID:    userID,
		Token:     tokenString,
		ExpiresAt: expiresAt,
	}, nil
}

// GetRefreshTokenByToken retrieves a refresh token by its token string.
func GetRefreshTokenByToken(tokenString string) (*types.RefreshToken, error) {
	query := database.Rebind("SELECT id, user_id, token, expires_at, is_revoked FROM refresh_tokens WHERE token = ?")
	row := database.DB.QueryRow(query, tokenString)

	token := &types.RefreshToken{}
	err := row.Scan(&token.ID, &token.UserID, &token.Token, &token.ExpiresAt, &token.IsRevoked)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // Not found
		}
		return nil, err
	}
	return token, nil
}

// DeleteRefreshTokenByToken deletes a refresh token from the database by its token string.
func DeleteRefreshTokenByToken(tokenString string) error {
	query := database.Rebind("DELETE FROM refresh_tokens WHERE token = ?")
	_, err := database.DB.Exec(query, tokenString)
	return err
}
