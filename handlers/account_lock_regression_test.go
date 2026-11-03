package handlers

import (
	"auth-proxy/config"
	"auth-proxy/database"
	"auth-proxy/logging"
	"auth-proxy/models"
	"database/sql"
	"testing"
	"time"
)

func TestDisabledAccountNeverUnlocksByLogin(t *testing.T) {
	logging.InitLoggers()
	oldDB := database.DB
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	database.DB = db
	t.Cleanup(func() {
		_ = db.Close()
		database.DB = oldDB
	})
	_, err = db.Exec(`CREATE TABLE users (
		id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT,
		role TEXT, is_active BOOLEAN, failed_logins INTEGER,
		locked_until DATETIME, last_login_at DATETIME,
		created_at DATETIME, updated_at DATETIME)`)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := models.HashPassword("valid-password-123")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	_, err = db.Exec(`INSERT INTO users (id, username, password_hash, role,
		is_active, failed_logins, locked_until, created_at, updated_at)
		VALUES (42, 'blocked', ?, 'user', FALSE, 0, ?, ?, ?)`,
		hash, now.Add(-time.Hour), now, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authenticateUser("blocked", "valid-password-123", "192.0.2.10"); err == nil {
		t.Fatal("administrator-disabled account accepted a login")
	}
	user, err := models.GetUserByUsername("blocked")
	if err != nil {
		t.Fatal(err)
	}
	if user == nil || user.IsActive {
		t.Fatal("administrator-disabled account was automatically re-enabled")
	}
}

func TestExpiredTemporaryLockDoesNotDisableAccount(t *testing.T) {
	logging.InitLoggers()
	oldDB := database.DB
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	database.DB = db
	t.Cleanup(func() {
		_ = db.Close()
		database.DB = oldDB
	})
	_, err = db.Exec(`CREATE TABLE users (
		id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT,
		role TEXT, is_active BOOLEAN, failed_logins INTEGER,
		locked_until DATETIME, last_login_at DATETIME,
		created_at DATETIME, updated_at DATETIME)`)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := models.HashPassword("valid-password-123")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	_, err = db.Exec(`INSERT INTO users (id, username, password_hash, role,
		is_active, failed_logins, locked_until, created_at, updated_at)
		VALUES (43, 'active', ?, 'user', TRUE, 5, ?, ?, ?)`,
		hash, now.Add(-time.Hour), now, now)
	if err != nil {
		t.Fatal(err)
	}
	oldPaths := config.Paths
	t.Cleanup(func() { config.Paths = oldPaths })
	config.Paths.MaxLoginAttempts = 5
	config.Paths.LockoutDurationMinutes = 10
	if _, err := authenticateUser("active", "valid-password-123", "192.0.2.10"); err != nil {
		t.Fatalf("expired temporary lock was not cleared: %v", err)
	}
	user, err := models.GetUserByUsername("active")
	if err != nil {
		t.Fatal(err)
	}
	if user == nil || !user.IsActive || user.LockedUntil.Valid || user.FailedLogins != 0 {
		t.Fatalf("temporary lock state not cleared on login: %+v", user)
	}
}
