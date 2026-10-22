package handlers

import (
	"auth-proxy/types"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestProxyRewritePreservesTargetAndRequest(t *testing.T) {
	oldPool := workerPool
	workerPool = &types.WorkerPool{TaskQueue: make(chan func(), 1)}
	t.Cleanup(func() { workerPool = oldPool })

	received := make(chan *http.Request, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Clone(r.Context())
		w.WriteHeader(http.StatusAccepted)
	}))
	defer upstream.Close()
	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://public.example/files/report?client=ok", nil)
	req.RemoteAddr = "192.0.2.1:1234"
	req.Header.Set("Authorization", "Bearer example")
	req.Header.Set("Cookie", "session=example")
	req.Header.Set("X-Forwarded-For", "spoofed-client")
	req.Header.Set("X-Forwarded-Host", "spoofed-host")
	req.Header.Set("X-Forwarded-Proto", "spoofed-proto")
	recorder := httptest.NewRecorder()
	NewProxy(upstream.URL+"/base?fixed=1").ServeHTTP(recorder, req)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d", recorder.Code)
	}
	got := <-received
	if got.Host != target.Host {
		t.Errorf("Host = %q, want %q", got.Host, target.Host)
	}
	if got.URL.Path != "/base/files/report" {
		t.Errorf("path = %q", got.URL.Path)
	}
	if got.URL.Query().Get("fixed") != "1" || got.URL.Query().Get("client") != "ok" {
		t.Errorf("query = %q", got.URL.RawQuery)
	}
	for key, want := range map[string]string{
		"Authorization": "Bearer example", "Cookie": "session=example",
		"X-Forwarded-For": "192.0.2.1", "X-Forwarded-Host": "public.example", "X-Forwarded-Proto": "http",
	} {
		if got.Header.Get(key) != want {
			t.Errorf("%s = %q, want %q", key, got.Header.Get(key), want)
		}
	}
}
