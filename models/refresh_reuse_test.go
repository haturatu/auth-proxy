package models

import (
	"auth-proxy/database"
	"database/sql"
	"testing"
	"time"
)

func TestSpentRefreshReplayRevokesCurrentCredentials(t *testing.T) {
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
	for _, stmt := range []string{
		"CREATE TABLE refresh_tokens (id INTEGER PRIMARY KEY, user_id INTEGER UNIQUE, token TEXT UNIQUE, expires_at DATETIME)",
		"CREATE TABLE consumed_refresh_tokens (token_hash TEXT PRIMARY KEY, user_id INTEGER, expires_at DATETIME, consumed_at DATETIME)",
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	oldToken, err := CreateRefreshToken(1, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	current, err := RotateRefreshToken(oldToken.Token, 1, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var stored string
	if err := db.QueryRow("SELECT token_hash FROM consumed_refresh_tokens WHERE user_id=1").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != database.TokenHash(oldToken.Token) || stored == oldToken.Token {
		t.Fatal("spent credential must be stored only as hash")
	}
	if reused, err := RevokeOnRefreshReplay(oldToken.Token); err != nil || !reused {
		t.Fatalf("replayed refresh credential not detected: %v %v", reused, err)
	}
	if found, err := GetRefreshTokenByToken(current.Token); err != nil || found != nil {
		t.Fatalf("latest refresh token must be revoked after replay: %v", err)
	}
	if reused, err := RevokeOnRefreshReplay("not-a-token"); err != nil || reused {
		t.Fatalf("unknown credential must not revoke a user: %v %v", reused, err)
	}
}
