package models

import (
	"auth-proxy/database"
	"auth-proxy/types"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// HashPassword defaults to the existing bcrypt format for compatibility.
// PBKDF2 is an explicitly opt-in standard-library alternative, not a forced migration.
const pbkdf2Iterations = 600000

func HashPassword(password string) (string, error) {
	if os.Getenv("PASSWORD_HASH_ALGORITHM") != "pbkdf2-sha256" {
		bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
		return string(bytes), err
	}
	var salt [16]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return "", err
	}
	key, err := pbkdf2.Key(sha256.New, password, salt[:], pbkdf2Iterations, 32)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("$pbkdf2-sha256$%d$%s$%s", pbkdf2Iterations,
		base64.RawStdEncoding.EncodeToString(salt[:]), base64.RawStdEncoding.EncodeToString(key)), nil
}

// CheckPasswordHash handles both the old bcrypt hashes and optional PBKDF2 hashes.
func CheckPasswordHash(password, hash string) bool {
	if !strings.HasPrefix(hash, "$pbkdf2-sha256$") {
		return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
	}
	parts := strings.Split(hash, "$")
	if len(parts) != 5 || parts[1] != "pbkdf2-sha256" {
		return false
	}
	iterations, err := strconv.Atoi(parts[2])
	if err != nil || iterations < 100000 || iterations > 2000000 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil || len(salt) != 16 {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(want) != 32 {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, iterations, 32)
	return err == nil && subtle.ConstantTimeCompare(got, want) == 1
}

// CreateUser creates a new user in the database
func CreateUser(username, password, role string) (*types.User, error) {
	passwordHash, err := HashPassword(password)
	if err != nil {
		return nil, err
	}

	query := database.Rebind("INSERT INTO users(username, password_hash, role) VALUES(?, ?, ?)")
	stmt, err := database.DB.Prepare(query)
	if err != nil {
		return nil, err
	}
	defer stmt.Close() //nolint:errcheck

	_, err = stmt.Exec(username, passwordHash, role)
	if err != nil {
		return nil, err
	}

	return GetUserByUsername(username) // Return the full user object
}

// baseSelectQuery is the common set of columns for user queries
const baseSelectQuery = "SELECT id, username, password_hash, role, is_active, failed_logins, last_login_at, created_at, updated_at FROM users"

// scanUser scans a row into a User struct
func scanUser(row *sql.Row) (*types.User, error) {
	user := &types.User{}
	err := row.Scan(&user.ID, &user.Username, &user.PasswordHash, &user.Role, &user.IsActive, &user.FailedLogins, &user.LastLoginAt, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // User not found
		}
		return nil, err
	}
	return user, nil
}

// GetUserByUsername retrieves a user by their username
func GetUserByUsername(username string) (*types.User, error) {
	query := database.Rebind(baseSelectQuery + " WHERE username = ?")
	row := database.DB.QueryRow(query, username)
	return scanUser(row)
}

// GetUserByID retrieves a user by their ID
func GetUserByID(id int64) (*types.User, error) {
	query := database.Rebind(baseSelectQuery + " WHERE id = ?")
	row := database.DB.QueryRow(query, id)
	return scanUser(row)
}

// GetAllUsers retrieves all users from the database
func GetAllUsers() ([]types.User, error) {
	rows, err := database.DB.Query(baseSelectQuery)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	var users []types.User
	for rows.Next() {
		var user types.User
		if err := rows.Scan(&user.ID, &user.Username, &user.PasswordHash, &user.Role, &user.IsActive, &user.FailedLogins, &user.LastLoginAt, &user.CreatedAt, &user.UpdatedAt); err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, nil
}

// UpdateUserRole updates a user's role
func UpdateUserRole(id int64, role string) error {
	query := database.Rebind("UPDATE users SET role = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?")
	_, err := database.DB.Exec(query, role, id)
	return err
}

// DeleteUser deletes a user from the database
func DeleteUser(id int64) error {
	query := database.Rebind("DELETE FROM users WHERE id = ?")
	_, err := database.DB.Exec(query, id)
	return err
}

// UpdateUserPassword updates a user's password hash
func UpdateUserPassword(id int64, passwordHash string) error {
	query := database.Rebind("UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?")
	_, err := database.DB.Exec(query, passwordHash, id)
	return err
}

// RecordLoginSuccess resets failed login attempts and updates last login time
func RecordLoginSuccess(id int64) error {
	query := database.Rebind("UPDATE users SET failed_logins = 0, last_login_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ?")
	_, err := database.DB.Exec(query, id)
	return err
}

// RecordLoginFailure increments the failed login counter
func RecordLoginFailure(id int64) error {
	query := database.Rebind("UPDATE users SET failed_logins = failed_logins + 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?")
	_, err := database.DB.Exec(query, id)
	return err
}

// SetUserActiveStatus updates the is_active flag for a user
func SetUserActiveStatus(id int64, isActive bool) error {
	query := database.Rebind("UPDATE users SET is_active = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?")
	_, err := database.DB.Exec(query, isActive, id)
	return err
}
