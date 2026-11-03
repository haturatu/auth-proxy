package middleware

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAnonymousCSRFAcrossDirectLAN(t *testing.T) {
	t.Setenv("XSRF_SECRET_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)))
	t.Setenv("COOKIE_SECURE", "auto")
	var generated string
	h := XSRF(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		generated = GetXSRFToken(r)
		w.WriteHeader(http.StatusNoContent)
	}))
	get := httptest.NewRequest("GET", "http://192.168.10.5:8080/login", nil)
	page := httptest.NewRecorder()
	h.ServeHTTP(page, get)
	if generated == "" {
		t.Fatal("missing initial anonymous CSRF token")
	}
	cookies := page.Result().Cookies()
	if len(cookies) == 0 || cookies[0].Secure {
		t.Fatal("direct HTTP LAN must have usable anon cookie")
	}
	post := httptest.NewRequest("POST", "http://192.168.10.5:8080/login", strings.NewReader(""))
	post.AddCookie(cookies[0])
	post.Header.Set("X-XSRF-Token", generated)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, post)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("valid VLAN form status=%d", rr.Code)
	}
	noCookie := httptest.NewRequest("POST", "http://192.168.10.5:8080/login", nil)
	noCookie.Header.Set("X-XSRF-Token", generated)
	denied := httptest.NewRecorder()
	h.ServeHTTP(denied, noCookie)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("no-cookie status=%d", denied.Code)
	}
}
