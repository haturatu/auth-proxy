package database

import (
	"database/sql"
	"testing"
	"time"
)

func TestLegacyBearerTokenMigrationPreservesValidClientTokens(t *testing.T) {
	old := DB
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	DB = db
	t.Cleanup(func() {
		DB = old
		_ = db.Close()
	})
	for _, table := range []string{"auth_tokens", "refresh_tokens"} {
		if _, err := db.Exec("CREATE TABLE " + table + " (id INTEGER PRIMARY KEY, user_id INTEGER, token TEXT UNIQUE, expires_at DATETIME)"); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec("INSERT INTO "+table+" (id, user_id, token, expires_at) VALUES (?, ?, ?, ?)", 1, 10, "legacy-raw-token", time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		if err := migrateTokenHashes(table); err != nil {
			t.Fatalf("%s: migration: %v", table, err)
		}
		var persisted string
		if err := db.QueryRow("SELECT token FROM " + table + " WHERE id = 1").Scan(&persisted); err != nil {
			t.Fatal(err)
		}
		if persisted != TokenHash("legacy-raw-token") {
			t.Fatalf("%s: persisted token does not match expected hash", table)
		}
		if err := migrateTokenHashes(table); err != nil {
			t.Fatalf("%s: idempotent migration: %v", table, err)
		}
		var after string
		if err := db.QueryRow("SELECT token FROM " + table + " WHERE id = 1").Scan(&after); err != nil {
			t.Fatal(err)
		}
		if after != persisted {
			t.Fatalf("%s: migration hashed an already-hashed token", table)
		}
	}
}
