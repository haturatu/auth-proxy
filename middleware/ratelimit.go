package middleware

import (
	"auth-proxy/config"
	"auth-proxy/types"
	"net"
	"net/http"
	"time"
)

const maxRateLimitClients = 10000

func NewRateLimiter() *types.RateLimiter {
	return &types.RateLimiter{Requests: make(map[string][]int64), Max: config.Paths.RateLimitMaxRequests, Window: time.Duration(config.Paths.RateLimitWindowSeconds) * time.Second}
}
func RateLimitMiddleware(l *types.RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				http.Error(w, "Invalid client address", http.StatusBadRequest)
				return
			}
			now := time.Now().Unix()
			l.Mutex.Lock()
			recent := l.Requests[ip][:0]
			for _, ts := range l.Requests[ip] {
				if now-ts < int64(l.Window.Seconds()) {
					recent = append(recent, ts)
				}
			}
			if len(recent) == 0 {
				delete(l.Requests, ip)
			} else {
				l.Requests[ip] = recent
			}
			if len(recent) >= l.Max {
				l.Mutex.Unlock()
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}
			if r.Method == http.MethodPost {
				if len(recent) == 0 && len(l.Requests) >= maxRateLimitClients {
					cleanupRateLimitLocked(l, now)
				}
				if len(recent) == 0 && len(l.Requests) >= maxRateLimitClients {
					l.Mutex.Unlock()
					http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
					return
				}
				l.Requests[ip] = append(recent, now)
			}
			l.Mutex.Unlock()
			next.ServeHTTP(w, r)
		})
	}
}
func cleanupRateLimitLocked(l *types.RateLimiter, now int64) {
	for ip, requests := range l.Requests {
		if len(requests) == 0 || now-requests[len(requests)-1] >= int64(l.Window.Seconds()) {
			delete(l.Requests, ip)
		}
	}
}
func Cleanup(l *types.RateLimiter) {
	l.Mutex.Lock()
	defer l.Mutex.Unlock()
	cleanupRateLimitLocked(l, time.Now().Unix())
}
