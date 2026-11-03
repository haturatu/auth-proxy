package middleware

import (
    "net/http"
    "os"
    "strings"
)

const MaxAuthBodyBytes = 64 << 10

// LimitAuthBody caps bodies on authentication and administration endpoints, not
// arbitrary proxied application requests (which may stream large files).
func LimitAuthBody(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.ContentLength > MaxAuthBodyBytes {
            http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
            return
        }
        if r.Body != nil {
            r.Body = http.MaxBytesReader(w, r.Body, MaxAuthBodyBytes)
        }
        next.ServeHTTP(w, r)
    })
}

// CookieSecure supports raw HTTP LAN access by default. For production behind
// a TLS-terminating proxy, set COOKIE_SECURE=true (never trust client XFP here).
func CookieSecure(r *http.Request) bool {
    switch strings.ToLower(strings.TrimSpace(os.Getenv("COOKIE_SECURE"))) {
    case "true", "always":
        return true
    case "false", "never":
        return false
    default:
        return r.TLS != nil
    }
}
