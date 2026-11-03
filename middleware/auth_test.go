package middleware

import (
	"auth-proxy/logging"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBearerAuthRejectsSessionCookieForRead(t *testing.T) {
	logging.InitLoggers()
	handler := BearerAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("request must not reach protected handler")
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "http://192.168.10.5:8080/api/private", nil)
	req.RemoteAddr = "192.168.20.10:12345"
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: "existing-session"})
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("cookie-only proxied API GET: got status %d, want %d", resp.Code, http.StatusUnauthorized)
	}
}

func TestAdminBearerAuthRequiresXSRFForCookieWrite(t *testing.T) {
	logging.InitLoggers()
	handler := AdminBearerAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("request must not reach admin handler")
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodPost, "http://192.168.10.5:8080/api/admin/users", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: "existing-session"})
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("cookie-only admin POST without XSRF: got status %d, want %d", resp.Code, http.StatusForbidden)
	}
}
