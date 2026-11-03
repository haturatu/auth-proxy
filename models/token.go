package models

import (
	"auth-proxy/database"
	"auth-proxy/types"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
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

	// Delete existing tokens for the user
	deleteQuery := database.Rebind("DELETE FROM auth_tokens WHERE user_id = ?")
	if _, err := tx.Exec(deleteQuery, userID); err != nil {
		return nil, err
	}

	// Insert the new token
	insertQuery := database.Rebind("INSERT INTO auth_tokens (user_id, token, expires_at) VALUES (?, ?, ?)")
	if _, err := tx.Exec(insertQuery, userID, database.TokenHash(tokenString), expiresAt); err != nil {
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

	row := database.DB.QueryRow(query, database.TokenHash(tokenString), time.Now())

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
	_, err := database.DB.Exec(query, database.TokenHash(tokenString))
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

	// Delete existing, non-revoked refresh tokens for the user
	deleteQuery := database.Rebind("DELETE FROM refresh_tokens WHERE user_id = ?")
	if _, err := tx.Exec(deleteQuery, userID); err != nil {
		return nil, err
	}

	// Insert the new refresh token
	insertQuery := database.Rebind("INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES (?, ?, ?)")
	if _, err := tx.Exec(insertQuery, userID, database.TokenHash(tokenString), expiresAt); err != nil {
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

// ErrRefreshTokenSpent reports replay or an expired/revoked refresh token.
var ErrRefreshTokenSpent = errors.New("refresh token already consumed or expired")

// RotateRefreshToken atomically consumes the presented credential and replaces it.
// The conditional UPDATE is the concurrency gate: at most one transaction may
// successfully consume the old token across multiple proxy instances.
func RotateRefreshToken(oldToken string, userID int64, duration time.Duration) (*types.RefreshToken, error) {
	raw, err := GenerateSecureToken(32)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	expiresAt := now.Add(duration)
	tx, err := database.DB.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck
	consume := database.Rebind("UPDATE refresh_tokens SET is_revoked = TRUE WHERE token = ? AND user_id = ? AND is_revoked = FALSE AND expires_at > ?")
	res, err := tx.Exec(consume, database.TokenHash(oldToken), userID, now)
	if err != nil {
		return nil, err
	}
	count, err := res.RowsAffected()
	if err != nil {
		return nil, err
	}
	if count != 1 {
		return nil, ErrRefreshTokenSpent
	}
	// The current schema permits one refresh token per user. The consumed
	// row is deleted in the same transaction; replay cannot win the CAS.
	remove := database.Rebind("DELETE FROM refresh_tokens WHERE user_id = ?")
	if _, err := tx.Exec(remove, userID); err != nil {
		return nil, err
	}
	insert := database.Rebind("INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES (?, ?, ?)")
	if _, err := tx.Exec(insert, userID, database.TokenHash(raw), expiresAt); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &types.RefreshToken{UserID: userID, Token: raw, ExpiresAt: expiresAt}, nil
}

// GetRefreshTokenByToken retrieves a refresh token by its token string.
func GetRefreshTokenByToken(tokenString string) (*types.RefreshToken, error) {
	query := database.Rebind("SELECT id, user_id, token, expires_at, is_revoked FROM refresh_tokens WHERE token = ?")
	row := database.DB.QueryRow(query, database.TokenHash(tokenString))

	token := &types.RefreshToken{}
	err := row.Scan(&token.ID, &token.UserID, &token.Token, &token.ExpiresAt, &token.IsRevoked)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // Not found
		}
		return nil, err
	}
	// Never expose the persisted digest to callers. Keep the presented raw token
	// for downstream revocation/rotation operations.
	token.Token = tokenString
	return token, nil
}

// DeleteRefreshTokenByToken deletes a refresh token from the database by its token string.
func DeleteRefreshTokenByToken(tokenString string) error {
	query := database.Rebind("DELETE FROM refresh_tokens WHERE token = ?")
	_, err := database.DB.Exec(query, database.TokenHash(tokenString))
	return err
}
