package database

import (
	"auth-proxy/logging"
	"database/sql"
	"fmt"
	"net/url"
	"os"
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

		// The mysql driver requires parseTime=true to scan DATE/DATETIME into time.Time
		q := u.Query()
		if q.Get("parseTime") == "" {
			q.Set("parseTime", "true")
		}
		u.RawQuery = q.Encode()

		// The mysql driver DSN format is user:password@tcp(host:port)/dbname
		var dsn string
		if u.User != nil {
			dsn = fmt.Sprintf("%s@tcp(%s)%s", u.User.String(), u.Host, u.Path)
		} else {
			dsn = fmt.Sprintf("tcp(%s)%s", u.Host, u.Path)
		}
		if u.RawQuery != "" {
			dsn = fmt.Sprintf("%s?%s", dsn, u.RawQuery)
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
	DB, err = sql.Open("sqlite3", databasePath)
	if err != nil {
		logging.AppLog.Error("Failed to open sqlite database", "error", err)
		os.Exit(1)
	}
	if err = DB.Ping(); err != nil {
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
	if err = DB.Ping(); err != nil {
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
	if err = DB.Ping(); err != nil {
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
			username VARCHAR(255) NOT NULL UNIQUE,
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
	logging.AppLog.Info("Users table verified successfully")

	// Now, create the auth_tokens table
	var createTokenTableSQL string
	switch dbType {
	case "sqlite3":
		createTokenTableSQL = `CREATE TABLE IF NOT EXISTS auth_tokens (
			"id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
			"user_id" INTEGER NOT NULL,
			"token" TEXT NOT NULL UNIQUE,
			"expires_at" DATETIME NOT NULL,
			FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
		);`
	case "postgres":
		createTokenTableSQL = `CREATE TABLE IF NOT EXISTS auth_tokens (
			id SERIAL PRIMARY KEY,
			user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			token VARCHAR(255) NOT NULL UNIQUE,
			expires_at TIMESTAMP WITH TIME ZONE NOT NULL
		);`
	case "mysql":
		createTokenTableSQL = `CREATE TABLE IF NOT EXISTS auth_tokens (
			id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
			user_id INT NOT NULL,
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
			"user_id" INTEGER NOT NULL,
			"token" TEXT NOT NULL UNIQUE,
			"expires_at" DATETIME NOT NULL,
			"is_revoked" BOOLEAN NOT NULL DEFAULT FALSE,
			FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
		);`
	case "postgres":
		createRefreshTokenTableSQL = `CREATE TABLE IF NOT EXISTS refresh_tokens (
			id SERIAL PRIMARY KEY,
			user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			token VARCHAR(255) NOT NULL UNIQUE,
			expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
			is_revoked BOOLEAN NOT NULL DEFAULT FALSE
		);`
	case "mysql":
		createRefreshTokenTableSQL = `CREATE TABLE IF NOT EXISTS refresh_tokens (
			id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
			user_id INT NOT NULL,
			token VARCHAR(255) NOT NULL UNIQUE,
			expires_at DATETIME NOT NULL,
			is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
			FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
		);`
	}

	if _, err := DB.Exec(createRefreshTokenTableSQL); err != nil {
		logging.AppLog.Error("Failed to create refresh_tokens table", "error", err, "db_type", dbType)
		os.Exit(1)
	}
	logging.AppLog.Info("Refresh_tokens table verified successfully")

}

// Rebind converts a query with '_?_' placeholders to the database-specific format.
func Rebind(query string) string {
	if dbType == "postgres" {
		parts := strings.Split(query, "?")
		var result strings.Builder
		for i, part := range parts {
			if i > 0 {
				result.WriteString(fmt.Sprintf("$%d", i))
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
