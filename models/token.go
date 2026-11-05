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
	query := database.Rebind("SELECT u.id, u.username, COALESCE((SELECT password_hash FROM password_credentials WHERE user_id = u.id), ''), u.role, u.is_active, u.failed_logins, u.last_login_at, u.created_at, u.updated_at, u.credentials_version FROM users u JOIN auth_tokens t ON u.id = t.user_id WHERE t.token = ? AND t.expires_at > ?")

	row := database.DB.QueryRow(query, database.TokenHash(tokenString), time.Now())

	user := &types.User{}
	err := row.Scan(&user.ID, &user.Username, &user.PasswordHash, &user.Role, &user.IsActive, &user.FailedLogins, &user.LastLoginAt, &user.CreatedAt, &user.UpdatedAt, &user.CredentialsVersion)
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
	tx, err := database.DB.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck
	var deleted int64
	for _, table := range []string{"auth_tokens", "refresh_tokens", "consumed_refresh_tokens"} {
		query := database.Rebind("DELETE FROM " + table + " WHERE expires_at < ?")
		res, err := tx.Exec(query, time.Now())
		if err != nil {
			return 0, err
		}
		count, err := res.RowsAffected()
		if err != nil {
			return 0, err
		}
		deleted += count
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return deleted, nil
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

// RotateRefreshToken atomically consumes the presented credential, records its
// hash as a spent token, and replaces it. A concurrent call can consume it only
// once; the old token cannot authorize a second refresh.
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

	consume := database.Rebind("DELETE FROM refresh_tokens WHERE token = ? AND user_id = ? AND expires_at > ?")
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
	record := database.Rebind("INSERT INTO consumed_refresh_tokens (token_hash, user_id, expires_at, consumed_at) VALUES (?, ?, ?, ?)")
	if _, err := tx.Exec(record, database.TokenHash(oldToken), userID, now.Add(duration), now); err != nil {
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

// RevokeOnRefreshReplay revokes the current refresh credential if a previously
// spent token is submitted. Unknown values do not affect any account.
func RevokeOnRefreshReplay(raw string) (bool, error) {
	tx, err := database.DB.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback() //nolint:errcheck
	find := database.Rebind("SELECT user_id FROM consumed_refresh_tokens WHERE token_hash = ? AND expires_at > ?")
	var userID int64
	err = tx.QueryRow(find, database.TokenHash(raw), time.Now()).Scan(&userID)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	revoke := database.Rebind("DELETE FROM refresh_tokens WHERE user_id = ?")
	if _, err := tx.Exec(revoke, userID); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

// GetRefreshTokenByToken retrieves a refresh token by its token string.
func GetRefreshTokenByToken(tokenString string) (*types.RefreshToken, error) {
	query := database.Rebind("SELECT id, user_id, token, expires_at FROM refresh_tokens WHERE token = ?")
	row := database.DB.QueryRow(query, database.TokenHash(tokenString))

	token := &types.RefreshToken{}
	err := row.Scan(&token.ID, &token.UserID, &token.Token, &token.ExpiresAt)
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
