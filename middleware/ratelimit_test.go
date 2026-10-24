package middleware

import (
	"auth-proxy/types"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRateLimiterRetentionAndUnlockedHandler(t *testing.T) {
	l := &types.RateLimiter{Requests: map[string][]int64{}, Max: 2, Window: time.Minute}
	h := RateLimitMiddleware(l)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !l.Mutex.TryLock() {
			t.Fatal("handler holds global limiter lock")
		}
		l.Mutex.Unlock()
	}))
	for i := 0; i < 1000; i++ {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = fmt.Sprintf("192.0.%d.%d:1234", i/256, i%256)
		h.ServeHTTP(httptest.NewRecorder(), r)
	}
	if len(l.Requests) != 0 {
		t.Fatal("GETs retained client keys")
	}
	for i := 0; i < maxRateLimitClients; i++ {
		l.Requests[fmt.Sprint(i)] = []int64{time.Now().Add(-time.Hour).Unix()}
	}
	Cleanup(l)
	if len(l.Requests) != 0 {
		t.Fatal("expired POST clients retained")
	}
	for i := 0; i < maxRateLimitClients; i++ {
		l.Requests[fmt.Sprint(i)] = []int64{time.Now().Unix()}
	}
	r := httptest.NewRequest("POST", "/", nil)
	r.RemoteAddr = "192.0.2.1:1234"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusTooManyRequests || len(l.Requests) != maxRateLimitClients {
		t.Fatal("client budget exceeded")
	}
}
func TestRateLimitBudgetStillRejectsThirdPOST(t *testing.T) {
	l := &types.RateLimiter{Requests: map[string][]int64{}, Max: 2, Window: time.Minute}
	h := RateLimitMiddleware(l)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	for i := 0; i < 3; i++ {
		r := httptest.NewRequest("POST", "/", nil)
		r.RemoteAddr = "192.0.2.1:1234"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if (w.Code == 429) != (i == 2) {
			t.Fatal(i, w.Code)
		}
	}
}
