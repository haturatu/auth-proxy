package middleware

import (
    "net/http"
    "net/http/httptest"
    "strings"
    "testing"
)

func TestCookieSecureDirectVLAN(t *testing.T) {
    t.Setenv("COOKIE_SECURE","auto")
    req:=httptest.NewRequest("GET","http://192.168.10.5:8080/login",nil)
    req.Header.Set("X-Forwarded-Proto","https")
    if CookieSecure(req) { t.Fatal("untrusted forwarding header must not force Secure") }
    t.Setenv("COOKIE_SECURE","true")
    if !CookieSecure(req) { t.Fatal("TLS terminator should force secure cookies when configured") }
}

func TestAuthBodyLimit(t *testing.T) {
    handler:=LimitAuthBody(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
        if err:=r.ParseForm();err!=nil { http.Error(w,"parse failed",400);return }
        w.WriteHeader(204)
    }))
    req:=httptest.NewRequest("POST","http://192.168.10.5:8080/login",strings.NewReader(strings.Repeat("a",MaxAuthBodyBytes+1)))
    rr:=httptest.NewRecorder()
    handler.ServeHTTP(rr,req)
    if rr.Code!=http.StatusRequestEntityTooLarge {t.Fatalf("status=%d",rr.Code)}
}

func TestCrossOriginDirectVLAN(t *testing.T) {
    cop:=http.NewCrossOriginProtection()
    h:=cop.Handler(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){w.WriteHeader(204)}))
    for _,tc:=range []struct{ origin, fetchSite string; want int }{
        {"http://192.168.10.5:8080","same-origin",204},
        {"http://evil.example","cross-site",403},
    } {
        req:=httptest.NewRequest("POST","http://192.168.10.5:8080/login",nil)
        req.Header.Set("Origin",tc.origin)
        req.Header.Set("Sec-Fetch-Site",tc.fetchSite)
        rr:=httptest.NewRecorder()
        h.ServeHTTP(rr,req)
        if rr.Code!=tc.want {t.Fatalf("origin=%s status=%d want=%d",tc.origin,rr.Code,tc.want)}
    }
}
