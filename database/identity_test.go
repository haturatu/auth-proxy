package database

import (
	"database/sql"
	"testing"
)

func TestIdentityMigrationPreservesPasswordsAndAllowsPasswordlessUsers(t *testing.T) {
	oldDB, oldType := DB, dbType
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	DB, dbType = db, "sqlite3"
	t.Cleanup(func() { _ = db.Close(); DB, dbType = oldDB, oldType })
	if _, err = db.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT NOT NULL); INSERT INTO users VALUES (1, 'legacy', 'existing-bcrypt-hash')`); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err = MigrateIdentity(); err != nil {
			t.Fatal(err)
		}
	}
	var legacy, password string
	var version int64
	if err = db.QueryRow("SELECT u.password_hash, p.password_hash, u.credentials_version FROM users u JOIN password_credentials p ON u.id = p.user_id").Scan(&legacy, &password, &version); err != nil {
		t.Fatal(err)
	}
	if legacy != "" || password != "existing-bcrypt-hash" || version != 1 {
		t.Fatalf("migration lost credential or failed to separate it")
	}
	if _, err = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (2, 'passkey-only', '')"); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = db.QueryRow("SELECT COUNT(*) FROM password_credentials WHERE user_id = 2").Scan(&count); err != nil || count != 0 {
		t.Fatalf("passwordless account has a password: %d %v", count, err)
	}
}
