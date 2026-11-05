package sso

import (
	"auth-proxy/config"
	"auth-proxy/database"
	"auth-proxy/logging"
	"auth-proxy/models"
	"auth-proxy/types"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

type passkeyUser struct {
	ID          int64
	Name        string
	Handle      []byte
	Credentials []webauthn.Credential
	Records     map[string]string `json:"-"`
}

func (u *passkeyUser) WebAuthnID() []byte                         { return u.Handle }
func (u *passkeyUser) WebAuthnName() string                       { return u.Name }
func (u *passkeyUser) WebAuthnDisplayName() string                { return u.Name }
func (u *passkeyUser) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }

type ceremony struct {
	Session  webauthn.SessionData
	User     passkeyUser
	SSOHash  string
	Version  int64
	Continue string
}

func decodeJSON(r *http.Request, value any) error {
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); !errors.Is(err, io.EOF) {
		return errInvalid
	}
	return nil
}

func (s *Service) loadPasskeyUser(user *types.User) (*passkeyUser, error) {
	u := &passkeyUser{ID: user.ID, Name: user.Username, Records: make(map[string]string)}
	var handle string
	err := database.DB.QueryRow(database.Rebind("SELECT handle FROM webauthn_users WHERE user_id = ?"), user.ID).Scan(&handle)
	if errors.Is(err, sql.ErrNoRows) {
		handle = randomToken()
		_, err = database.DB.Exec(database.Rebind("INSERT INTO webauthn_users (user_id, handle) VALUES (?, ?)"), user.ID, handle)
	}
	if err != nil {
		return nil, err
	}
	u.Handle, err = base64.RawURLEncoding.DecodeString(handle)
	if err != nil {
		return nil, err
	}
	rows, err := database.DB.Query(database.Rebind("SELECT id, credential FROM webauthn_credentials WHERE user_id = ?"), user.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	for rows.Next() {
		var id, encoded string
		if err = rows.Scan(&id, &encoded); err != nil {
			return nil, err
		}
		var credential webauthn.Credential
		if err = s.open(encoded, &credential, "credential:"+id); err != nil {
			return nil, err
		}
		u.Credentials = append(u.Credentials, credential)
		u.Records[id] = encoded
	}
	return u, rows.Err()
}

func (s *Service) registerBegin(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Username string `json:"username"`
	}
	if err := decodeJSON(r, &input); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	parent, user, err := s.currentSSO(r)
	var flow ceremony
	if err == nil {
		if time.Now().Unix()-parent.AuthTime > int64(flowLifetime.Seconds()) {
			http.Error(w, "Sign in again before adding a passkey", http.StatusUnauthorized)
			return
		}
		u, err := s.loadPasskeyUser(user)
		if err != nil {
			unavailable(w, err)
			return
		}
		flow.User, flow.SSOHash, flow.Version = *u, parent.Hash, user.CredentialsVersion
	} else if errors.Is(err, errInvalid) {
		if !config.Paths.RegisterEnabled {
			http.Error(w, "Registration disabled", http.StatusForbidden)
			return
		}
		name := strings.TrimSpace(input.Username)
		count := utf8.RuneCountInString(name)
		if count < 3 || count > 128 || strings.IndexFunc(name, unicode.IsControl) >= 0 {
			http.Error(w, "Username must contain 3–128 characters", http.StatusBadRequest)
			return
		}
		existing, err := models.GetUserByUsername(name)
		if err != nil {
			unavailable(w, err)
			return
		}
		if existing != nil {
			http.Error(w, "Username unavailable", http.StatusConflict)
			return
		}
		handle, _ := base64.RawURLEncoding.DecodeString(randomToken())
		flow.User = passkeyUser{Name: name, Handle: handle}
	} else {
		unavailable(w, err)
		return
	}
	opts := []webauthn.RegistrationOption{webauthn.WithExclusions(credentialDescriptors(flow.User.Credentials))}
	options, session, err := s.wa.BeginRegistration(&flow.User, opts...)
	if err != nil {
		http.Error(w, "Could not begin registration", http.StatusBadRequest)
		return
	}
	flow.Session = *session
	raw := randomToken()
	if err = s.putFlow("registration", raw, &flow); err != nil {
		unavailable(w, err)
		return
	}
	setCookie(w, "__Host-sso_registration", raw, flowLifetime)
	reply(w, options)
}

func credentialDescriptors(credentials []webauthn.Credential) []protocol.CredentialDescriptor {
	result := make([]protocol.CredentialDescriptor, 0, len(credentials))
	for _, c := range credentials {
		result = append(result, c.Descriptor())
	}
	return result
}

func (s *Service) registerFinish(w http.ResponseWriter, r *http.Request) {
	raw, err := readCookie(r, "__Host-sso_registration")
	if err != nil {
		http.Error(w, "Registration expired", http.StatusBadRequest)
		return
	}
	var flow ceremony
	if err = s.takeRecord("oauth_transactions", "registration", raw, &flow); err != nil {
		if errors.Is(err, errInvalid) {
			http.Error(w, "Registration expired", http.StatusBadRequest)
		} else {
			unavailable(w, err)
		}
		return
	}
	setCookie(w, "__Host-sso_registration", "", -time.Second)
	if flow.User.ID != 0 {
		parent, user, err := s.currentSSO(r)
		if err != nil {
			if errors.Is(err, errInvalid) {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
			} else {
				unavailable(w, err)
			}
			return
		}
		if parent.Hash != flow.SSOHash || user.ID != flow.User.ID || user.CredentialsVersion != flow.Version {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	} else if !config.Paths.RegisterEnabled {
		http.Error(w, "Registration disabled", http.StatusForbidden)
		return
	}
	credential, err := s.wa.FinishRegistration(&flow.User, flow.Session, r)
	if err != nil {
		logging.SecurityLog.Warn("Passkey registration rejected")
		http.Error(w, "Passkey verification failed", http.StatusBadRequest)
		return
	}
	user, err := s.persistRegistration(&flow, credential)
	if err != nil {
		unavailable(w, err)
		return
	}
	if err = s.issueSSO(w, r, user); err != nil {
		unavailable(w, err)
		return
	}
	reply(w, map[string]string{"redirect": "/sso/account"})
}

func revokeCredentials(tx *sql.Tx, id int64) error {
	if _, err := tx.Exec(database.Rebind("UPDATE users SET credentials_version = credentials_version + 1 WHERE id = ?"), id); err != nil {
		return err
	}
	return deleteUserSessions(tx, id)
}

func deleteUserSessions(tx *sql.Tx, id int64) error {
	for _, table := range []string{"auth_tokens", "refresh_tokens", "app_sessions", "sso_sessions"} {
		if _, err := tx.Exec(database.Rebind("DELETE FROM "+table+" WHERE user_id = ?"), id); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) persistRegistration(flow *ceremony, credential *webauthn.Credential) (*types.User, error) {
	id := database.TokenHash(string(credential.ID))
	encoded, err := s.seal(credential, "credential:"+id)
	if err != nil {
		return nil, err
	}
	tx, err := database.DB.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck
	userID := flow.User.ID
	if userID == 0 {
		if _, err = tx.Exec(database.Rebind("INSERT INTO users (username, password_hash, role) VALUES (?, '', 'user')"), flow.User.Name); err != nil {
			return nil, err
		}
		if err = tx.QueryRow(database.Rebind("SELECT id FROM users WHERE username = ?"), flow.User.Name).Scan(&userID); err != nil {
			return nil, err
		}
		if _, err = tx.Exec(database.Rebind("INSERT INTO webauthn_users (user_id, handle) VALUES (?, ?)"), userID, base64.RawURLEncoding.EncodeToString(flow.User.Handle)); err != nil {
			return nil, err
		}
	} else {
		// Conditional update serializes changes and rejects a ceremony captured
		// before another credential mutation or account disablement.
		res, err := tx.Exec(database.Rebind("UPDATE users SET credentials_version = credentials_version + 1 WHERE id = ? AND credentials_version = ? AND is_active = TRUE"), userID, flow.Version)
		if err != nil {
			return nil, err
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			return nil, errInvalid
		}
		if err = deleteUserSessions(tx, userID); err != nil {
			return nil, err
		}
	}
	if _, err = tx.Exec(database.Rebind("INSERT INTO webauthn_credentials (id, user_id, credential, created_at) VALUES (?, ?, ?, ?)"), id, userID, encoded, time.Now().Unix()); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return models.GetUserByID(userID)
}

func (s *Service) loginBegin(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Flow string `json:"flow"`
	}
	if err := decodeJSON(r, &input); err != nil || len(input.Flow) > 128 {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	options, session, err := s.wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		http.Error(w, "Could not begin login", http.StatusBadRequest)
		return
	}
	raw := randomToken()
	if err = s.putFlow("login", raw, ceremony{Session: *session, Continue: input.Flow}); err != nil {
		unavailable(w, err)
		return
	}
	setCookie(w, "__Host-sso_login", raw, flowLifetime)
	reply(w, options)
}

func (s *Service) discoverUser(rawID, handle []byte) (webauthn.User, error) {
	var id int64
	err := database.DB.QueryRow(database.Rebind("SELECT user_id FROM webauthn_credentials WHERE id = ?"), database.TokenHash(string(rawID))).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errInvalid
	}
	if err != nil {
		return nil, err
	}
	user, err := models.GetUserByID(id)
	if err != nil {
		return nil, err
	}
	if user == nil || !user.IsActive {
		return nil, errInvalid
	}
	u, err := s.loadPasskeyUser(user)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(handle, u.Handle) != 1 {
		return nil, errInvalid
	}
	return u, nil
}

func (s *Service) continuation(flow string) (string, error) {
	if flow == "" {
		return "/sso/account", nil
	}
	var q url.Values
	if err := s.takeRecord("oauth_transactions", "authorize", flow, &q); err != nil {
		return "", err
	}
	if _, err := s.validateAuthorization(q); err != nil {
		return "", err
	}
	return "/oauth2/authorize?" + q.Encode(), nil
}

func (s *Service) loginFinish(w http.ResponseWriter, r *http.Request) {
	raw, err := readCookie(r, "__Host-sso_login")
	if err != nil {
		http.Error(w, "Login expired", http.StatusBadRequest)
		return
	}
	var flow ceremony
	if err = s.takeRecord("oauth_transactions", "login", raw, &flow); err != nil {
		if errors.Is(err, errInvalid) {
			http.Error(w, "Login expired", http.StatusBadRequest)
		} else {
			unavailable(w, err)
		}
		return
	}
	setCookie(w, "__Host-sso_login", "", -time.Second)
	u, credential, err := s.wa.FinishPasskeyLogin(s.discoverUser, flow.Session, r)
	if err != nil || credential.Authenticator.CloneWarning {
		logging.SecurityLog.Warn("Passkey login rejected")
		http.Error(w, "Passkey verification failed", http.StatusUnauthorized)
		return
	}
	user, err := models.GetUserByID(u.(*passkeyUser).ID)
	if err != nil {
		unavailable(w, err)
		return
	}
	if user == nil || !user.IsActive {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	redirect, err := s.continuation(flow.Continue)
	if err != nil {
		http.Error(w, "Login request expired; open the application again", http.StatusBadRequest)
		return
	}
	id := database.TokenHash(string(credential.ID))
	encoded, err := s.seal(credential, "credential:"+id)
	if err != nil {
		unavailable(w, err)
		return
	}
	res, err := database.DB.Exec(database.Rebind("UPDATE webauthn_credentials SET credential = ? WHERE id = ? AND user_id = ? AND credential = ?"), encoded, id, user.ID, u.(*passkeyUser).Records[id])
	if err != nil {
		unavailable(w, err)
		return
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if err = models.RecordLoginSuccess(user.ID); err != nil {
		unavailable(w, err)
		return
	}
	if err = s.issueSSO(w, r, user); err != nil {
		unavailable(w, err)
		return
	}
	reply(w, map[string]string{"redirect": redirect})
}

func (s *Service) passwordLogin(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Flow     string `json:"flow"`
	}
	if err := decodeJSON(r, &input); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	user, err := s.password(input.Username, input.Password, logging.GetClientIP(r))
	if err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}
	redirect, err := s.continuation(input.Flow)
	if err != nil {
		http.Error(w, "Login request expired; open the application again", http.StatusBadRequest)
		return
	}
	if err = s.issueSSO(w, r, user); err != nil {
		unavailable(w, err)
		return
	}
	reply(w, map[string]string{"redirect": redirect})
}

func (s *Service) listCredentials(w http.ResponseWriter, r *http.Request) {
	_, user, err := s.currentSSO(r)
	if err != nil {
		if errors.Is(err, errInvalid) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		} else {
			unavailable(w, err)
		}
		return
	}
	rows, err := database.DB.Query(database.Rebind("SELECT id, created_at FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at"), user.ID)
	if err != nil {
		unavailable(w, err)
		return
	}
	defer rows.Close() //nolint:errcheck
	type item struct {
		ID        string `json:"id"`
		CreatedAt int64  `json:"created_at"`
	}
	items := []item{}
	for rows.Next() {
		var it item
		if err = rows.Scan(&it.ID, &it.CreatedAt); err != nil {
			unavailable(w, err)
			return
		}
		items = append(items, it)
	}
	if err = rows.Err(); err != nil {
		unavailable(w, err)
		return
	}
	reply(w, items)
}

func (s *Service) deleteCredential(w http.ResponseWriter, r *http.Request) {
	parent, user, err := s.currentSSO(r)
	if err != nil {
		if errors.Is(err, errInvalid) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		} else {
			unavailable(w, err)
		}
		return
	}
	if time.Now().Unix()-parent.AuthTime > int64(flowLifetime.Seconds()) {
		http.Error(w, "Sign in again before removing a passkey", http.StatusUnauthorized)
		return
	}
	tx, err := database.DB.Begin()
	if err != nil {
		unavailable(w, err)
		return
	}
	defer tx.Rollback() //nolint:errcheck
	if err = revokeCredentials(tx, user.ID); err != nil {
		unavailable(w, err)
		return
	}
	var count int
	if err = tx.QueryRow(database.Rebind("SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = ?"), user.ID).Scan(&count); err != nil {
		unavailable(w, err)
		return
	}
	if count <= 1 && user.PasswordHash == "" {
		http.Error(w, "Add another passkey before removing your last sign-in method", http.StatusConflict)
		return
	}
	res, err := tx.Exec(database.Rebind("DELETE FROM webauthn_credentials WHERE id = ? AND user_id = ?"), r.PathValue("id"), user.ID)
	if err != nil {
		unavailable(w, err)
		return
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		http.Error(w, "Passkey not found", http.StatusNotFound)
		return
	}
	if err = tx.Commit(); err != nil {
		unavailable(w, err)
		return
	}
	setCookie(w, ssoCookie, "", -time.Second)
	w.WriteHeader(http.StatusNoContent)
}
