package handlers

import (
	"auth-proxy/types"
	"auth-proxy/utils"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAuthenticatedProxyRebuildsIdentityAndStripsCredentials(t *testing.T) {
	t.Setenv("UPSTREAM_ASSERTION_ED25519_SEED", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("UPSTREAM_ASSERTION_AS_BEARER", "false")
	old := workerPool
	workerPool = &types.WorkerPool{TaskQueue: make(chan func(), 8)}
	t.Cleanup(func() { workerPool = old })
	var backendError string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for name, want := range map[string]string{
			"X-Username":             "alice",
			"X-User-Role":            "user",
			"X-Auth-Request-User":    "alice",
			"X-Auth-Request-Role":    "user",
			"X-Auth-Request-User-Id": "42",
			"Cookie":                 "theme=dark",
		} {
			if got := r.Header.Get(name); got != want {
				backendError += name + "=" + got + " expected " + want + "; "
			}
		}
		if got := r.Header.Get("Authorization"); got != "" {
			backendError += "Authorization leaked; "
		}
		if got := r.Header.Get("X-Forwarded-User"); got != "" {
			backendError += "X-Forwarded-User spoofed; "
		}
		token := r.Header.Get("X-Auth-Request-JWT")
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			backendError += "missing assertion; "
		} else {
			key, err := utils.UpstreamAssertionPublicKey()
			if err != nil {
				backendError += "invalid assertion key; "
			}
			signature, err := base64.RawURLEncoding.DecodeString(parts[2])
			if err != nil || !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), signature) {
				backendError += "assertion signature invalid; "
			}
		}
		w.Header().Set("Vary", "Accept-Encoding")
		w.WriteHeader(204)
	}))
	defer upstream.Close()
	req := httptest.NewRequest("GET", "http://192.168.10.5:8080/api/events", nil)
	req.RemoteAddr = "192.168.20.14:5678"
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: "private-session"})
	req.AddCookie(&http.Cookie{Name: "anon_xsrf", Value: "private-csrf"})
	for _, name := range []string{"__Host-sso_session", "__Host-app_session", "__Host-sso_login", "__Host-sso_flow_test"} {
		req.AddCookie(&http.Cookie{Name: name, Value: "private-credential"})
	}
	req.AddCookie(&http.Cookie{Name: "theme", Value: "dark"})
	req.Header.Set("Authorization", "Bearer client-jwt")
	req.Header.Set("X-Auth-Request-User", "evil")
	req.Header.Set("X-Auth-Request-JWT", "forged")
	req.Header.Set("X-Forwarded-User", "evil")
	user := &types.User{ID: 42, Username: "alice", Role: "user", IsActive: true}
	req = req.WithContext(context.WithValue(req.Context(), types.SessionDataContextKey, user))
	rr := httptest.NewRecorder()
	NewProxy(upstream.URL).ServeHTTP(rr, req)
	if rr.Code != 204 {
		t.Fatalf("proxy returned %d %s", rr.Code, rr.Body.String())
	}
	if backendError != "" {
		t.Fatal(backendError)
	}
	if got := rr.Header().Get("Cache-Control"); got != "private, no-store" {
		t.Fatalf("Cache-Control = %q", got)
	}
	if !strings.Contains(rr.Header().Get("Vary"), "Cookie") {
		t.Fatal("Vary missing Cookie")
	}
}
