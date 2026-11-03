package models

import (
	"auth-proxy/database"
	"database/sql"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestRotateRefreshTokenConsumesExactlyOnce(t *testing.T) {
	old := database.DB
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	database.DB = db
	defer func() { database.DB = old; _ = db.Close() }()
	if _, err := db.Exec("CREATE TABLE refresh_tokens (id INTEGER PRIMARY KEY, user_id INTEGER UNIQUE, token TEXT UNIQUE, expires_at DATETIME, is_revoked BOOLEAN DEFAULT FALSE)"); err != nil {
		t.Fatal(err)
	}
	oldToken, err := CreateRefreshToken(1, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	successes := 0
	wg.Add(2)
	for i := 0; i < 2; i++ {
		go func() {
			defer wg.Done()
			_, err := RotateRefreshToken(oldToken.Token, 1, time.Hour)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				successes++
			} else if !errors.Is(err, ErrRefreshTokenSpent) {
				t.Errorf("rotate: %v", err)
			}
		}()
	}
	wg.Wait()
	if successes != 1 {
		t.Fatalf("expected exactly one success, got %d", successes)
	}
	if token, _ := GetRefreshTokenByToken(oldToken.Token); token != nil {
		t.Fatal("spent credential still valid")
	}
}
