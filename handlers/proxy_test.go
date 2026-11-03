package handlers

import (
	"auth-proxy/types"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestReverseProxyRejectsForgedIdentityHeaders(t *testing.T) {
	old := workerPool
	workerPool = &types.WorkerPool{TaskQueue: make(chan func(), 8)}
	t.Cleanup(func() { workerPool = old })
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Username") != "" || r.Header.Get("X-User-Role") != "" {
			t.Error("forged identity forwarded")
		}
		if r.Header.Get("X-Forwarded-For") != "192.168.20.10" {
			t.Errorf("IP=%q", r.Header.Get("X-Forwarded-For"))
		}
		w.WriteHeader(204)
	}))
	defer upstream.Close()
	req := httptest.NewRequest("GET", "http://192.168.10.5:8080/data", nil)
	req.RemoteAddr = "192.168.20.10:4321"
	req.Header.Set("X-Username", "admin")
	req.Header.Set("X-User-Role", "admin")
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	rr := httptest.NewRecorder()
	NewProxy(upstream.URL).ServeHTTP(rr, req)
	if rr.Code != 204 {
		t.Fatalf("status=%d", rr.Code)
	}
}
