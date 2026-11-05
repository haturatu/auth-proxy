package database

import (
	"auth-proxy/logging"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"net/url"
	"os"
	"strconv"
	"strings"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
)

var (
	DB     *sql.DB
	dbType string
)

// InitDB determines the database type from environment variables and initializes the connection.
func InitDB() {
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL != "" {
		initFromURL(databaseURL)
	} else {
		dbType = "sqlite3"
		initSQLite()
	}
	createTables()
}

// initFromURL initializes the database based on the DATABASE_URL.
func initFromURL(databaseURL string) {
	u, err := url.Parse(databaseURL)
	if err != nil {
		logging.AppLog.Error("Invalid DATABASE_URL", "error", err)
		os.Exit(1)
	}

	driver := u.Scheme
	logging.AppLog.Info("Attempting to connect to database", "driver", driver)

	switch driver {
	case "postgres", "postgresql":
		dbType = "postgres"
		initPostgreSQL(databaseURL)
	case "mysql":
		dbType = "mysql"

		dsn, err := mysqlDSN(databaseURL)
		if err != nil {
			logging.AppLog.Error("Invalid MySQL DATABASE_URL", "error", err)
			os.Exit(1)
		}
		initMySQL(dsn)
	default:
		logging.AppLog.Error("Unsupported database driver in DATABASE_URL", "driver", driver)
		os.Exit(1)
	}
}

// initSQLite initializes a SQLite database connection.
func initSQLite() {
	databasePath := os.Getenv("DATABASE_PATH")
	if databasePath == "" {
		databasePath = "./auth.db"
	}

	var err error
	DB, err = sql.Open("sqlite3", "file:"+databasePath+"?_busy_timeout=5000&_foreign_keys=on&_journal_mode=WAL")
	if err != nil {
		logging.AppLog.Error("Failed to open sqlite database", "error", err)
		os.Exit(1)
	}
	DB.SetMaxOpenConns(1)
	if err = retryPing(DB); err != nil {
		logging.AppLog.Error("Failed to connect to sqlite database", "error", err)
		os.Exit(1)
	}
	logging.AppLog.Info("Database connection established", "type", "sqlite", "path", databasePath)
}

// initPostgreSQL initializes a PostgreSQL database connection.
func initPostgreSQL(dataSourceName string) {
	var err error
	DB, err = sql.Open("postgres", dataSourceName)
	if err != nil {
		logging.AppLog.Error("Failed to open postgres database", "error", err)
		os.Exit(1)
	}
	if err = retryPing(DB); err != nil {
		logging.AppLog.Error("Failed to connect to postgres database", "error", err)
		os.Exit(1)
	}
	logging.AppLog.Info("Database connection established", "type", "postgres")
}

// initMySQL initializes a MySQL database connection.
func initMySQL(dataSourceName string) {
	var err error
	DB, err = sql.Open("mysql", dataSourceName)
	if err != nil {
		logging.AppLog.Error("Failed to open mysql database", "error", err)
		os.Exit(1)
	}
	if err = retryPing(DB); err != nil {
		logging.AppLog.Error("Failed to connect to mysql database", "error", err)
		os.Exit(1)
	}
	logging.AppLog.Info("Database connection established", "type", "mysql")
}

// createTables creates the necessary tables if they don't exist, using syntax appropriate for the current dbType.
func createTables() {
	var createTableSQL string
	switch dbType {
	case "sqlite3":
		createTableSQL = `CREATE TABLE IF NOT EXISTS users (
			"id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
			"username" TEXT NOT NULL UNIQUE,
			"password_hash" TEXT NOT NULL,
			"role" TEXT NOT NULL,
			"is_active" BOOLEAN NOT NULL DEFAULT TRUE,
			"failed_logins" INTEGER NOT NULL DEFAULT 0,
			"last_login_at" DATETIME,
			"created_at" DATETIME DEFAULT CURRENT_TIMESTAMP,
			"updated_at" DATETIME DEFAULT CURRENT_TIMESTAMP
		);`
	case "postgres":
		createTableSQL = `CREATE TABLE IF NOT EXISTS users (
			id SERIAL PRIMARY KEY,
			username VARCHAR(255) NOT NULL UNIQUE,
			password_hash VARCHAR(255) NOT NULL,
			role VARCHAR(50) NOT NULL,
			is_active BOOLEAN NOT NULL DEFAULT TRUE,
			failed_logins INT NOT NULL DEFAULT 0,
			last_login_at TIMESTAMP WITH TIME ZONE,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
		);`
	case "mysql":
		createTableSQL = `CREATE TABLE IF NOT EXISTS users (
			id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
			username VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL UNIQUE,
			password_hash VARCHAR(255) NOT NULL,
			role VARCHAR(50) NOT NULL,
			is_active BOOLEAN NOT NULL DEFAULT TRUE,
			failed_logins INT NOT NULL DEFAULT 0,
			last_login_at DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
		);`
	}

	if _, err := DB.Exec(createTableSQL); err != nil {
		logging.AppLog.Error("Failed to create users table", "error", err, "db_type", dbType)
		os.Exit(1)
	}
	if err := MigrateIdentity(); err != nil {
		logging.AppLog.Error("Failed to migrate identity schema", "error", err)
		os.Exit(1)
	}
	logging.AppLog.Info("Users table verified successfully")
	// MySQL/MariaDB frequently default to a case-insensitive collation.
	// Match the case-sensitive user lookup semantics of SQLite/PostgreSQL,
	// including on existing installations, without rewriting account names.
	if dbType == "mysql" {
		var collation string
		err := DB.QueryRow(`SELECT COLLATION_NAME FROM information_schema.COLUMNS
			WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users'
			  AND COLUMN_NAME = 'username'`).Scan(&collation)
		if err != nil {
			logging.AppLog.Error("Failed to inspect username collation", "error", err)
			os.Exit(1)
		}
		if !strings.EqualFold(collation, "utf8mb4_bin") {
			_, err := DB.Exec(`ALTER TABLE users
				MODIFY username VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL`)
			if err != nil {
				logging.AppLog.Error("Failed to migrate username collation", "error", err)
				os.Exit(1)
			}
		}
	}

	// Add a separate temporary login lock. Keep is_active exclusively for
	// administrator disablement. This is safe for existing databases on all drivers.
	lockColumn := map[string]string{
		"sqlite3":  "DATETIME",
		"postgres": "TIMESTAMP WITH TIME ZONE",
		"mysql":    "DATETIME",
	}[dbType]
	rows, err := DB.Query("SELECT locked_until FROM users LIMIT 0")
	if err == nil {
		_ = rows.Close()
	} else if _, alterErr := DB.Exec("ALTER TABLE users ADD COLUMN locked_until " + lockColumn); alterErr != nil {
		logging.AppLog.Error("Failed to migrate users.locked_until", "error", alterErr, "previous_query_error", err)
		os.Exit(1)
	}

	// Now, create the auth_tokens table
	var createTokenTableSQL string
	switch dbType {
	case "sqlite3":
		createTokenTableSQL = `CREATE TABLE IF NOT EXISTS auth_tokens (
			"id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
			"user_id" INTEGER NOT NULL UNIQUE,
			"token" TEXT NOT NULL UNIQUE,
			"expires_at" DATETIME NOT NULL,
			FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
		);`
	case "postgres":
		createTokenTableSQL = `CREATE TABLE IF NOT EXISTS auth_tokens (
			id SERIAL PRIMARY KEY,
			user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
			token VARCHAR(255) NOT NULL UNIQUE,
			expires_at TIMESTAMP WITH TIME ZONE NOT NULL
		);`
	case "mysql":
		createTokenTableSQL = `CREATE TABLE IF NOT EXISTS auth_tokens (
			id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
			user_id INT NOT NULL UNIQUE,
			token VARCHAR(255) NOT NULL UNIQUE,
			expires_at DATETIME NOT NULL,
			FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
		);`
	}

	if _, err := DB.Exec(createTokenTableSQL); err != nil {
		logging.AppLog.Error("Failed to create auth_tokens table", "error", err, "db_type", dbType)
		os.Exit(1)
	}
	logging.AppLog.Info("Auth_tokens table verified successfully")

	// Now, create the refresh_tokens table
	var createRefreshTokenTableSQL string
	switch dbType {
	case "sqlite3":
		createRefreshTokenTableSQL = `CREATE TABLE IF NOT EXISTS refresh_tokens (
			"id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
			"user_id" INTEGER NOT NULL UNIQUE,
			"token" TEXT NOT NULL UNIQUE,
			"expires_at" DATETIME NOT NULL,
			FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
		);`
	case "postgres":
		createRefreshTokenTableSQL = `CREATE TABLE IF NOT EXISTS refresh_tokens (
			id SERIAL PRIMARY KEY,
			user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
			token VARCHAR(255) NOT NULL UNIQUE,
			expires_at TIMESTAMP WITH TIME ZONE NOT NULL
		);`
	case "mysql":
		createRefreshTokenTableSQL = `CREATE TABLE IF NOT EXISTS refresh_tokens (
			id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
			user_id INT NOT NULL UNIQUE,
			token VARCHAR(255) NOT NULL UNIQUE,
			expires_at DATETIME NOT NULL,
			FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
		);`
	}

	if _, err := DB.Exec(createRefreshTokenTableSQL); err != nil {
		logging.AppLog.Error("Failed to create refresh_tokens table", "error", err, "db_type", dbType)
		os.Exit(1)
	}
	logging.AppLog.Info("Refresh_tokens table verified successfully")
	// Existing databases may still have a legacy is_revoked column.
	// Drop already-revoked rows before runtime stops consulting that column.
	if rows, err := DB.Query("SELECT is_revoked FROM refresh_tokens LIMIT 0"); err == nil {
		_ = rows.Close()
		if _, err := DB.Exec("DELETE FROM refresh_tokens WHERE is_revoked = TRUE"); err != nil {
			logging.AppLog.Error("Failed to retire revoked refresh tokens", "error", err)
			os.Exit(1)
		}
	}

	// Spent refresh-token hashes are retained until expiry so replay can revoke
	// the newest token in the same credential family.
	var spentSQL string
	switch dbType {
	case "sqlite3":
		spentSQL = `CREATE TABLE IF NOT EXISTS consumed_refresh_tokens (
			token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL,
			expires_at DATETIME NOT NULL, consumed_at DATETIME NOT NULL,
			FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)`
	case "postgres":
		spentSQL = `CREATE TABLE IF NOT EXISTS consumed_refresh_tokens (
			token_hash VARCHAR(255) PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			expires_at TIMESTAMP WITH TIME ZONE NOT NULL, consumed_at TIMESTAMP WITH TIME ZONE NOT NULL)`
	case "mysql":
		spentSQL = `CREATE TABLE IF NOT EXISTS consumed_refresh_tokens (
			token_hash VARCHAR(255) PRIMARY KEY, user_id INT NOT NULL,
			expires_at DATETIME NOT NULL, consumed_at DATETIME NOT NULL,
			FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)`
	}
	if _, err := DB.Exec(spentSQL); err != nil {
		logging.AppLog.Error("Failed to create consumed_refresh_tokens", "error", err, "db_type", dbType)
		os.Exit(1)
	}

	for _, table := range []string{"auth_tokens", "refresh_tokens"} {
		if err := migrateTokenHashes(table); err != nil {
			logging.AppLog.Error("Failed to migrate bearer token hashes", "table", table, "error", err)
			os.Exit(1)
		}
	}

}

// TokenHash derives the identifier stored for a bearer credential.
// The raw token must only be returned to the client, never persisted.
func TokenHash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// migrateTokenHashes converts previously stored plaintext tokens in place.
// Existing clients keep their tokens and need not sign in again after upgrade.
func migrateTokenHashes(table string) error {
	rows, err := DB.Query("SELECT id, token FROM " + table)
	if err != nil {
		return err
	}
	type row struct {
		id    int64
		token string
	}
	var legacy []row
	for rows.Next() {
		var x row
		if err := rows.Scan(&x.id, &x.token); err != nil {
			_ = rows.Close()
			return err
		}
		if !strings.HasPrefix(x.token, "sha256:") {
			legacy = append(legacy, x)
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if len(legacy) == 0 {
		return nil
	}
	tx, err := DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	query := Rebind("UPDATE " + table + " SET token = ? WHERE id = ?")
	for _, x := range legacy {
		if _, err := tx.Exec(query, TokenHash(x.token), x.id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Rebind converts a query with '_?_' placeholders to the database-specific format.
func Rebind(query string) string {
	if dbType == "postgres" {
		parts := strings.Split(query, "?")
		var result strings.Builder
		for i, part := range parts {
			if i > 0 {
				result.WriteString("$" + strconv.Itoa(i))
			}
			result.WriteString(part)
		}
		return result.String()
	}
	// sqlite3 and mysql both use '?'
	return query
}

// CloseDB closes the database connection.
func CloseDB() {
	if DB != nil {
		if err := DB.Close(); err != nil {
			logging.AppLog.Error("Failed to close database connection", "error", err)
		}
		logging.AppLog.Info("Database connection closed")
	}
}
