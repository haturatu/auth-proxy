package middleware

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestLogoutCSRFTokenIsScopedToLogoutPath(t *testing.T) {
	t.Setenv("XSRF_SECRET_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)))
	session := "user-session"
	get := httptest.NewRequest(http.MethodGet, "http://app.local/account", nil)
	get.AddCookie(&http.Cookie{Name: "auth_token", Value: session})
	logoutToken, ok := GenerateSessionXSRF(get, "/logout")
	if !ok || logoutToken == "" {
		t.Fatal("failed to generate logout-scoped token")
	}
	accountToken, ok := GenerateSessionXSRF(get, "/account")
	if !ok || accountToken == "" {
		t.Fatal("failed to generate account-scoped token")
	}

	h := XSRF(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	for _, tc := range []struct {
		name  string
		token string
		want  int
	}{
		{"correct scope", logoutToken, http.StatusNoContent},
		{"wrong scope", accountToken, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := url.Values{"xsrf_token": {tc.token}}.Encode()
			req := httptest.NewRequest(http.MethodPost, "http://app.local/logout", bytes.NewBufferString(body))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.AddCookie(&http.Cookie{Name: "auth_token", Value: session})
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != tc.want {
				t.Fatalf("got %d want %d: %s", rr.Code, tc.want, rr.Body.String())
			}
		})
	}
}
