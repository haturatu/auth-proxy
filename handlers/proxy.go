package handlers

import (
	"auth-proxy/logging"
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

	proxy := httputil.NewSingleHostReverseProxy(target)

	// The default director is mostly fine, but we want to log.
	director := proxy.Director
	proxy.Director = func(req *http.Request) {
		director(req) // Run the default director

		// Asynchronously log the proxying action to avoid blocking the request.
		urlStr := req.URL.String()
		ip := logging.GetClientIP(req)
		worker.Submit(workerPool, func() {
			logging.AppLog.Info("Proxying request", "url", urlStr, "ip", ip)
		})
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
