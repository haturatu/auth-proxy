package database

import (
	"fmt"
)

// MigrateIdentity is additive and idempotent on SQLite, PostgreSQL and MySQL.
// The legacy NOT NULL password_hash column remains as an empty compatibility
// column; credentials are moved into password_credentials. Passwordless users
// have no row in that table.
func MigrateIdentity() error {
	rows, err := DB.Query("SELECT credentials_version FROM users LIMIT 0")
	if err == nil {
		_ = rows.Close()
	} else {
		if _, err = DB.Exec("ALTER TABLE users ADD COLUMN credentials_version BIGINT NOT NULL DEFAULT 1"); err != nil {
			return err
		}
	}
	statements := []string{
		`CREATE TABLE IF NOT EXISTS password_credentials (user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, password_hash VARCHAR(255) NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS webauthn_credentials (id VARCHAR(128) PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, credential TEXT NOT NULL, created_at BIGINT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS sso_sessions (token_hash VARCHAR(128) PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, credentials_version BIGINT NOT NULL, auth_time BIGINT NOT NULL, expires_at BIGINT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS app_sessions (token_hash VARCHAR(128) PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, app_id VARCHAR(64) NOT NULL, sso_session_id VARCHAR(128) NOT NULL REFERENCES sso_sessions(token_hash) ON DELETE CASCADE, expires_at BIGINT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS oauth_clients (id VARCHAR(64) PRIMARY KEY, origin VARCHAR(512) NOT NULL, redirect_uri VARCHAR(512) NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS oauth_transactions (token_hash VARCHAR(128) PRIMARY KEY, kind VARCHAR(32) NOT NULL, payload TEXT NOT NULL, expires_at BIGINT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS authorization_codes (token_hash VARCHAR(128) PRIMARY KEY, payload TEXT NOT NULL, expires_at BIGINT NOT NULL)`,
	}
	statements = append(statements, `CREATE TABLE IF NOT EXISTS webauthn_users (user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, handle VARCHAR(128) NOT NULL UNIQUE)`)
	// MySQL ignores inline REFERENCES. Explicit constraints are required there.
	if dbType == "mysql" {
		statements[0] = `CREATE TABLE IF NOT EXISTS password_credentials (user_id INT PRIMARY KEY, password_hash VARCHAR(255) NOT NULL, FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)`
		statements[1] = `CREATE TABLE IF NOT EXISTS webauthn_credentials (id VARCHAR(128) PRIMARY KEY, user_id INT NOT NULL, credential TEXT NOT NULL, created_at BIGINT NOT NULL, FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)`
		statements[2] = `CREATE TABLE IF NOT EXISTS sso_sessions (token_hash VARCHAR(128) PRIMARY KEY, user_id INT NOT NULL, credentials_version BIGINT NOT NULL, auth_time BIGINT NOT NULL, expires_at BIGINT NOT NULL, FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)`
		statements[3] = `CREATE TABLE IF NOT EXISTS app_sessions (token_hash VARCHAR(128) PRIMARY KEY, user_id INT NOT NULL, app_id VARCHAR(64) NOT NULL, sso_session_id VARCHAR(128) NOT NULL, expires_at BIGINT NOT NULL, FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE, FOREIGN KEY (sso_session_id) REFERENCES sso_sessions(token_hash) ON DELETE CASCADE)`
		statements[len(statements)-1] = `CREATE TABLE IF NOT EXISTS webauthn_users (user_id INT PRIMARY KEY, handle VARCHAR(128) NOT NULL UNIQUE, FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)`
	}
	for _, stmt := range statements {
		if _, err = DB.Exec(stmt); err != nil {
			return fmt.Errorf("identity schema: %w", err)
		}
	}
	tx, err := DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err = tx.Exec(`INSERT INTO password_credentials (user_id, password_hash) SELECT id, password_hash FROM users WHERE password_hash <> '' AND NOT EXISTS (SELECT 1 FROM password_credentials p WHERE p.user_id = users.id)`); err != nil {
		return err
	}
	if _, err = tx.Exec(`UPDATE users SET password_hash = '' WHERE password_hash <> ''`); err != nil {
		return err
	}
	return tx.Commit()
}
