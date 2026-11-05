package sso

import (
	"auth-proxy/config"
	"auth-proxy/database"
	"auth-proxy/middleware"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type gatewayFlow struct {
	AppID       string
	BindingHash string
	Verifier    string
	Nonce       string
	ReturnPath  string
}

func pkce(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func flowCookie(state string) string {
	// Per-transaction cookies allow concurrent login tabs without overwriting
	// each other's browser binding.
	return "__Host-sso_flow_" + pkce(state)[:20]
}

func safeRequest(r *http.Request, a *config.Application) bool {
	method := r.Header.Get("X-Original-Method")
	origin := r.Header.Get("X-Original-Origin")
	mode := r.Header.Get("X-Original-Fetch-Mode")
	site := r.Header.Get("X-Original-Fetch-Site")
	upgrade := r.Header.Get("X-Original-Upgrade")
	if method == "" {
		return false
	}
	if strings.EqualFold(upgrade, "websocket") {
		return method == "GET" && origin == a.Origin
	}
	if method != "GET" && method != "HEAD" && method != "OPTIONS" {
		return origin == a.Origin
	}
	if origin != "" && origin != a.Origin {
		return false
	}
	if site == "cross-site" || site == "same-site" {
		return (method == "GET" || method == "HEAD") && mode == "navigate"
	}
	return true
}

func browserNavigation(r *http.Request) bool {
	if r.Header.Get("X-Original-Method") != "GET" || r.Header.Get("X-Original-Fetch-Mode") != "navigate" || r.Header.Get("X-Original-Fetch-Dest") != "document" || r.Header.Get("X-Original-Upgrade") != "" {
		return false
	}
	for _, part := range strings.Split(r.Header.Get("X-Original-Accept"), ",") {
		kind, params, err := mime.ParseMediaType(strings.TrimSpace(part))
		if err == nil && kind == "text/html" && params["q"] != "0" {
			return true
		}
	}
	return false
}

func (s *Service) authz(w http.ResponseWriter, r *http.Request) {
	a, err := s.application(r)
	if err != nil || !safeRequest(r, a) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	raw, err := readCookie(r, appCookie)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	var ssoHash string
	var userID int64
	err = database.DB.QueryRow(database.Rebind("SELECT sso_session_id, user_id FROM app_sessions WHERE token_hash = ? AND app_id = ? AND expires_at > ?"), database.TokenHash(raw), a.ID, time.Now().Unix()).Scan(&ssoHash, &userID)
	if errors.Is(err, sql.ErrNoRows) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if err != nil {
		unavailable(w, err)
		return
	}
	_, user, err := s.lookupSSOHash(ssoHash)
	if errors.Is(err, errInvalid) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if err != nil {
		unavailable(w, err)
		return
	}
	if user.ID != userID || !allowed(a, user) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	w.Header().Set("X-Auth-Request-User", user.Username)
	w.Header().Set("X-Auth-Request-User-ID", strconv.FormatInt(user.ID, 10))
	w.Header().Set("X-Auth-Request-Role", user.Role)
	// Let Nginx forward application cookies while withholding every credential
	// owned by this service. This also supports applications with many cookies.
	var cookies []string
	for _, c := range r.Cookies() {
		if middleware.IsAuthCookie(c.Name) {
			continue
		}
		cookies = append(cookies, c.String())
	}
	w.Header().Set("X-Auth-Request-Cookie", strings.Join(cookies, "; "))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) start(w http.ResponseWriter, r *http.Request) {
	a, err := s.application(r)
	if err != nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if !browserNavigation(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	path, err := localPath(r.Header.Get("X-Original-URI"))
	if err != nil {
		http.Error(w, "Invalid return path", http.StatusBadRequest)
		return
	}
	parsed, _ := url.ParseRequestURI(path)
	apiPrefix := strings.TrimRight(config.Paths.APIPath, "/")
	if apiPrefix == "" {
		apiPrefix = "/api"
	}
	if parsed.Path == apiPrefix || strings.HasPrefix(parsed.Path, apiPrefix+"/") {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	state, binding, nonce, verifier := randomToken(), randomToken(), randomToken(), randomToken()
	f := gatewayFlow{AppID: a.ID, BindingHash: database.TokenHash(binding), Verifier: verifier, Nonce: nonce, ReturnPath: path}
	if err = s.putFlow("gateway", state, &f); err != nil {
		unavailable(w, err)
		return
	}
	setCookie(w, flowCookie(state), binding, flowLifetime)
	query := url.Values{"response_type": {"code"}, "client_id": {a.ID}, "redirect_uri": {a.RedirectURI}, "scope": {"openid profile"}, "state": {state}, "nonce": {nonce}, "code_challenge": {pkce(verifier)}, "code_challenge_method": {"S256"}}
	http.Redirect(w, r, s.config.Issuer+"/oauth2/authorize?"+query.Encode(), http.StatusFound)
}

func (s *Service) callback(w http.ResponseWriter, r *http.Request) {
	a, err := s.application(r)
	if err != nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	q := r.URL.Query()
	if len(q["state"]) != 1 || len(q["code"]) != 1 || len(q["iss"]) != 1 || q.Get("iss") != s.config.Issuer {
		http.Error(w, "Invalid callback", http.StatusBadRequest)
		return
	}
	state := q.Get("state")
	if len(state) != 43 {
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}
	binding, err := readCookie(r, flowCookie(state))
	if err != nil {
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}
	var f gatewayFlow
	if err = s.takeRecord("oauth_transactions", "gateway", state, &f); err != nil {
		if errors.Is(err, errInvalid) {
			http.Error(w, "Invalid state", http.StatusBadRequest)
		} else {
			unavailable(w, err)
		}
		return
	}
	setCookie(w, flowCookie(state), "", -time.Second)
	if f.AppID != a.ID || subtle.ConstantTimeCompare([]byte(f.BindingHash), []byte(database.TokenHash(binding))) != 1 {
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}
	// The RP and OP are in the same process. Exchange through the same core
	// validation used by /oauth2/token; no loopback HTTP or internal headers.
	tokens, code, err := s.exchange(a, q.Get("code"), a.RedirectURI, f.Verifier)
	if err != nil {
		if errors.Is(err, errInvalid) {
			http.Error(w, "Invalid code", http.StatusBadRequest)
		} else {
			unavailable(w, err)
		}
		return
	}
	claims, err := s.validateIDToken(tokens.IDToken, a.ID, f.Nonce)
	if err != nil || claims.Subject != strconv.FormatInt(code.UserID, 10) {
		http.Error(w, "Invalid ID token", http.StatusBadRequest)
		return
	}
	parent, user, err := s.lookupSSOHash(code.SSOHash)
	if errors.Is(err, errInvalid) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if err != nil {
		unavailable(w, err)
		return
	}
	if !allowed(a, user) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	raw := randomToken()
	expires := min(time.Now().Add(appLifetime).Unix(), parent.Expires)
	_, err = database.DB.Exec(database.Rebind("INSERT INTO app_sessions (token_hash, user_id, app_id, sso_session_id, expires_at) VALUES (?, ?, ?, ?, ?)"), database.TokenHash(raw), user.ID, a.ID, parent.Hash, expires)
	if err != nil {
		unavailable(w, err)
		return
	}
	setCookie(w, appCookie, raw, time.Until(time.Unix(expires, 0)))
	http.Redirect(w, r, a.Origin+f.ReturnPath, http.StatusFound)
}

func (s *Service) appLogout(w http.ResponseWriter, r *http.Request) {
	a, err := s.application(r)
	if err != nil || r.Header.Get("X-Original-Origin") != a.Origin || r.Header.Get("X-Original-Method") != "POST" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	raw, err := readCookie(r, appCookie)
	if err == nil {
		_, err = database.DB.Exec(database.Rebind("DELETE FROM app_sessions WHERE token_hash = ? AND app_id = ?"), database.TokenHash(raw), a.ID)
		if err != nil {
			unavailable(w, err)
			return
		}
	}
	setCookie(w, appCookie, "", -time.Second)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) logout(w http.ResponseWriter, r *http.Request) {
	raw, err := readCookie(r, ssoCookie)
	if err == nil {
		_, err = database.DB.Exec(database.Rebind("DELETE FROM sso_sessions WHERE token_hash = ?"), database.TokenHash(raw))
		if err != nil {
			unavailable(w, err)
			return
		}
	}
	setCookie(w, ssoCookie, "", -time.Second)
	w.WriteHeader(http.StatusNoContent)
}
