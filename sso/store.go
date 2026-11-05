package sso

import (
	"auth-proxy/database"
	"auth-proxy/models"
	"auth-proxy/types"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

type session struct {
	Hash     string
	UserID   int64
	Version  int64
	AuthTime int64
	Expires  int64
}

func (s *Service) seal(value any, aad string) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, s.box.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(s.box.Seal(nonce, nonce, data, []byte(aad))), nil
}

func (s *Service) open(encoded string, value any, aad string) error {
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(data) < s.box.NonceSize() {
		return errInvalid
	}
	plain, err := s.box.Open(nil, data[:s.box.NonceSize()], data[s.box.NonceSize():], []byte(aad))
	if err != nil {
		return errInvalid
	}
	return json.Unmarshal(plain, value)
}

func (s *Service) syncClients() error {
	tx, err := database.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err = tx.Exec("DELETE FROM oauth_clients"); err != nil {
		return err
	}
	for _, a := range s.config.Applications {
		if _, err = tx.Exec(database.Rebind("INSERT INTO oauth_clients (id, origin, redirect_uri) VALUES (?, ?, ?)"), a.ID, a.Origin, a.RedirectURI); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Service) putFlow(kind, raw string, value any) error {
	hash := database.TokenHash(raw)
	data, err := s.seal(value, kind+":"+hash)
	if err != nil {
		return err
	}
	_, err = database.DB.Exec(database.Rebind("INSERT INTO oauth_transactions (token_hash, kind, payload, expires_at) VALUES (?, ?, ?, ?)"), hash, kind, data, time.Now().Add(flowLifetime).Unix())
	return err
}

// takeRecord uses conditional DELETE inside the transaction to arbitrate
// concurrent consumers on every supported database. Only one can commit a use.
func (s *Service) takeRecord(table, kind, raw string, value any) error {
	if raw == "" || len(raw) > 128 {
		return errInvalid
	}
	tx, err := database.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	hash := database.TokenHash(raw)
	where := "token_hash = ? AND expires_at > ?"
	args := []any{hash, time.Now().Unix()}
	if table == "oauth_transactions" {
		where += " AND kind = ?"
		args = append(args, kind)
	}
	var data string
	err = tx.QueryRow(database.Rebind("SELECT payload FROM "+table+" WHERE "+where), args...).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return errInvalid
	}
	if err != nil {
		return err
	}
	res, err := tx.Exec(database.Rebind("DELETE FROM "+table+" WHERE "+where), args...)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return errInvalid
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	return s.open(data, value, kind+":"+hash)
}

func (s *Service) createSSO(user *types.User) (string, error) {
	return s.replaceSSO(user, "")
}

func (s *Service) replaceSSO(user *types.User, previous string) (string, error) {
	raw := randomToken()
	now := time.Now()
	tx, err := database.DB.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback() //nolint:errcheck
	// Reauthentication rotates the SSO session and revokes its old app
	// sessions, so a later logout cannot leave orphaned sessions on a device.
	if previous != "" {
		if _, err = tx.Exec(database.Rebind("DELETE FROM sso_sessions WHERE token_hash = ?"), database.TokenHash(previous)); err != nil {
			return "", err
		}
	}
	res, err := tx.Exec(database.Rebind("INSERT INTO sso_sessions (token_hash, user_id, credentials_version, auth_time, expires_at) SELECT ?, id, credentials_version, ?, ? FROM users WHERE id = ? AND credentials_version = ? AND is_active = TRUE"), database.TokenHash(raw), now.Unix(), now.Add(ssoLifetime).Unix(), user.ID, user.CredentialsVersion)
	if err != nil {
		return "", err
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return "", errInvalid
	}
	return raw, tx.Commit()
}

func (s *Service) lookupSSO(raw string) (*session, *types.User, error) {
	return s.lookupSSOHash(database.TokenHash(raw))
}

func (s *Service) lookupSSOHash(hash string) (*session, *types.User, error) {
	var v session
	err := database.DB.QueryRow(database.Rebind("SELECT token_hash, user_id, credentials_version, auth_time, expires_at FROM sso_sessions WHERE token_hash = ? AND expires_at > ?"), hash, time.Now().Unix()).Scan(&v.Hash, &v.UserID, &v.Version, &v.AuthTime, &v.Expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, errInvalid
	}
	if err != nil {
		return nil, nil, err
	}
	u, err := models.GetUserByID(v.UserID)
	if err != nil {
		return nil, nil, err
	}
	if u == nil || !u.IsActive || u.CredentialsVersion != v.Version {
		return nil, nil, errInvalid
	}
	return &v, u, nil
}

// Cleanup deletes expired protocol records and sessions. SQL cascades remove
// dependent app sessions; authorization always checks expiry before this job.
func Cleanup() error {
	now := time.Now().Unix()
	for _, table := range []string{"app_sessions", "sso_sessions", "oauth_transactions", "authorization_codes"} {
		if _, err := database.DB.Exec(database.Rebind("DELETE FROM "+table+" WHERE expires_at <= ?"), now); err != nil {
			return err
		}
	}
	return nil
}
