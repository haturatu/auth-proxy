package handlers

import (
	"auth-proxy/logging"
	"auth-proxy/types"
	"auth-proxy/utils"
	"auth-proxy/worker"
	"context"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
)

type assertionContextKey struct{}

// NewProxy forwards requests to a fixed backend and derives identity ONLY from
// authenticated context. Client-supplied identity headers are never trusted.
func NewProxy(targetURL string) http.Handler {
	target, err := url.Parse(targetURL)
	if err != nil {
		panic("Invalid target URL: " + err.Error())
	}
	audience := os.Getenv("UPSTREAM_ASSERTION_AUDIENCE")
	if audience == "" {
		audience = target.Host
	}

	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.SetXForwarded()
			pr.Out.Header.Set("X-Forwarded-For", logging.GetClientIP(pr.In))
			pr.Out.Header.Set("X-Forwarded-Proto", logging.GetClientScheme(pr.In))

			// Prevent injection of identity claims, even on unprotected paths.
			for name := range pr.Out.Header {
				lower := strings.ToLower(name)
				if strings.HasPrefix(lower, "x-auth-request-") ||
					strings.HasPrefix(lower, "x-goog-authenticated-user-") ||
					strings.HasPrefix(lower, "x-amzn-oidc-") ||
					lower == "x-username" || lower == "x-user-role" ||
					lower == "x-forwarded-user" || lower == "remote-user" ||
					lower == "cf-access-jwt-assertion" || lower == "x-goog-iap-jwt-assertion" {
					pr.Out.Header.Del(name)
				}
			}

			// The browser's session/CSRF cookies and incoming JWT are for the
			// edge, not upstream applications. Other application cookies remain.
			pr.Out.Header.Del("Authorization")
			pr.Out.Header.Del("Cookie")
			var appCookies []string
			for _, cookie := range pr.In.Cookies() {
				if cookie.Name == "auth_token" || cookie.Name == "anon_xsrf" {
					continue
				}
				appCookies = append(appCookies, cookie.String())
			}
			if len(appCookies) != 0 {
				pr.Out.Header.Set("Cookie", strings.Join(appCookies, "; "))
			}

			if user, ok := pr.In.Context().Value(types.SessionDataContextKey).(*types.User); ok && user != nil {
				pr.Out.Header.Set("X-Username", user.Username)
				pr.Out.Header.Set("X-User-Role", user.Role)
				pr.Out.Header.Set("X-Auth-Request-User", user.Username)
				pr.Out.Header.Set("X-Auth-Request-Role", user.Role)
				pr.Out.Header.Set("X-Auth-Request-User-ID", strconv.FormatInt(user.ID, 10))
				if signed, ok := pr.In.Context().Value(assertionContextKey{}).(string); ok && signed != "" {
					pr.Out.Header.Set("X-Auth-Request-JWT", signed)
					if os.Getenv("UPSTREAM_ASSERTION_AS_BEARER") == "true" {
						pr.Out.Header.Set("Authorization", "Bearer "+signed)
					}
				}
			}

			// Never log the query string, which may contain sensitive parameters.
			path := pr.Out.URL.Path
			ip := logging.GetClientIP(pr.In)
			worker.Submit(workerPool, func() {
				logging.AppLog.Info("Proxying request", "path", path, "ip", ip)
			})
		},
		ModifyResponse: func(resp *http.Response) error {
			if resp.Request != nil {
				if user, ok := resp.Request.Context().Value(types.SessionDataContextKey).(*types.User); ok && user != nil {
					resp.Header.Set("Cache-Control", "private, no-store")
					vary := strings.Join(resp.Header.Values("Vary"), ", ")
					if !strings.Contains(strings.ToLower(vary), "cookie") {
						if vary != "" {
							resp.Header.Set("Vary", vary+", Cookie")
						} else {
							resp.Header.Set("Vary", "Cookie")
						}
					}
				}
			}
			return nil
		},
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		ip := logging.GetClientIP(r)
		worker.Submit(workerPool, func() {
			logging.AppLog.Error("Proxy error", "error", err, "ip", ip)
		})
		http.Error(w, "Proxy Error", http.StatusBadGateway)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Sign before starting the upstream request so a key/RNG failure
		// cannot degrade an authenticated request into unsigned identity.
		if user, ok := r.Context().Value(types.SessionDataContextKey).(*types.User); ok && user != nil &&
			os.Getenv("UPSTREAM_ASSERTION_ED25519_SEED") != "" {
			signed, err := utils.GenerateUpstreamAssertion(user, audience)
			if err != nil {
				http.Error(w, "Identity assertion unavailable", http.StatusInternalServerError)
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), assertionContextKey{}, signed))
		}
		proxy.ServeHTTP(w, r)
	})
}
