package handlers

import (
	"auth-proxy/logging"
	"auth-proxy/types"
	"auth-proxy/worker"
	"net/http"
	"net/http/httputil"
	"net/url"
)

// NewProxy creates a new reverse proxy handler using httputil.ReverseProxy.
func NewProxy(targetURL string) http.Handler {
	target, err := url.Parse(targetURL)
	if err != nil {
		panic("Invalid target URL: " + err.Error())
	}

	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.SetXForwarded()
			pr.Out.Header.Set("X-Forwarded-For", logging.GetClientIP(pr.In))
			pr.Out.Header.Set("X-Forwarded-Proto", logging.GetClientScheme(pr.In))

			// Never trust identity headers supplied by the client.
			pr.Out.Header.Del("X-Username")
			pr.Out.Header.Del("X-User-Role")
			if user, ok := pr.In.Context().Value(types.SessionDataContextKey).(*types.User); ok && user != nil {
				pr.Out.Header.Set("X-Username", user.Username)
				pr.Out.Header.Set("X-User-Role", user.Role)
			}

			urlStr := pr.Out.URL.String()
			ip := logging.GetClientIP(pr.In)
			worker.Submit(workerPool, func() {
				logging.AppLog.Info("Proxying request", "url", urlStr, "ip", ip)
			})
		},
	}

	// Custom error handler for logging
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		ip := logging.GetClientIP(r)
		// Asynchronously log the proxy error to avoid blocking the response.
		worker.Submit(workerPool, func() {
			logging.AppLog.Error("Proxy error", "error", err, "ip", ip)
		})
		http.Error(w, "Proxy Error", http.StatusBadGateway)
	}

	return proxy
}
