package models

import (
    "auth-proxy/database"
    "database/sql"
    "testing"
    "time"
)

func TestBearerTokensStoredOnlyAsHashes(t *testing.T) {
    oldDB := database.DB
    db, err := sql.Open("sqlite3", ":memory:")
    if err != nil { t.Fatal(err) }
    database.DB = db
    t.Cleanup(func() { _ = db.Close(); database.DB = oldDB })
    db.SetMaxOpenConns(1)
    for _, stmt := range []string{
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT, role TEXT, is_active BOOLEAN, failed_logins INTEGER, last_login_at DATETIME, created_at DATETIME, updated_at DATETIME)",
        "CREATE TABLE auth_tokens (user_id INTEGER UNIQUE, token TEXT, expires_at DATETIME)",
        "CREATE TABLE refresh_tokens (id INTEGER PRIMARY KEY, user_id INTEGER UNIQUE, token TEXT, expires_at DATETIME, is_revoked BOOLEAN DEFAULT FALSE)",
    } { if _, err := db.Exec(stmt); err != nil { t.Fatal(err) } }
    now := time.Now()
    if _, err := db.Exec("INSERT INTO users VALUES (1, 'alice', 'hash', 'user', 1, 0, NULL, ?, ?)", now, now); err != nil { t.Fatal(err) }
    session, err := CreateAuthToken(1, time.Hour)
    if err != nil { t.Fatal(err) }
    refresh, err := CreateRefreshToken(1, time.Hour)
    if err != nil { t.Fatal(err) }
    for _, tc := range []struct { table, raw string }{{"auth_tokens", session.Token}, {"refresh_tokens", refresh.Token}} {
        var saved string
        if err := db.QueryRow("SELECT token FROM " + tc.table + " WHERE user_id=1").Scan(&saved); err != nil { t.Fatal(err) }
        if saved == tc.raw || saved != database.TokenHash(tc.raw) { t.Fatalf("%s contains wrong token storage", tc.table) }
    }
    if user, err := GetUserByToken(session.Token); err != nil || user == nil { t.Fatalf("cookie lookup: %v", err) }
    if found, err := GetRefreshTokenByToken(refresh.Token); err != nil || found == nil { t.Fatalf("refresh lookup: %v", err) }
    if err := DeleteAuthToken(session.Token); err != nil { t.Fatal(err) }
    if found, _ := GetUserByToken(session.Token); found != nil { t.Fatal("deleted session still valid") }
}
