package handlers

import (
	"auth-proxy/config"
	"auth-proxy/logging"
	"auth-proxy/middleware"
	"auth-proxy/worker"
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	fcgiclient "github.com/tomasen/fcgi_client"
)

// NewPhpProxyHandler creates a handler that proxies requests to a specific PHP script.
func NewPhpProxyHandler(scriptName string) http.Handler {
	phpFpmSocket := os.Getenv("PHP_FPM_SOCKET")
	if phpFpmSocket == "" {
		phpFpmSocket = "/run/php-fpm/php-fpm.sock" // Default value
	}

	// Get doc root from env for container support.
	docRoot := os.Getenv("PHP_DOC_ROOT")

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fcgi, err := fcgiclient.Dial("unix", phpFpmSocket)
		if err != nil {
			errStr := err.Error()
			ip := logging.GetClientIP(r)
			worker.Submit(workerPool, func() {
				logging.AppLog.Error("Failed to connect to php-fpm", "error", errStr, "ip", ip)
			})
			http.Error(w, "Failed to connect to php-fpm: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer fcgi.Close()

		env := make(map[string]string)

		var scriptFilename string
		var finalDocRoot string

		if docRoot != "" {
			// PHP_DOC_ROOT is set, for containerized environments.
			finalDocRoot = docRoot
			scriptFilename = filepath.Join(finalDocRoot, scriptName)
		} else {
			// Fallback to local development logic.
			localDocRoot, err := filepath.Abs("templates/php")
			if err != nil {
				http.Error(w, "Could not resolve templates/php path", http.StatusInternalServerError)
				return
			}
			finalDocRoot = localDocRoot
			scriptFilename = filepath.Join(finalDocRoot, scriptName)

			// Verify file exists for local dev.
			if _, err := os.Stat(scriptFilename); os.IsNotExist(err) {
				http.NotFound(w, r)
				return
			}
		}

		env["SCRIPT_FILENAME"] = scriptFilename
		env["DOCUMENT_ROOT"] = finalDocRoot

		// Pass path config to PHP
		env["AUTH_PATH_LOGIN"] = config.Paths.Login
		env["AUTH_PATH_REGISTER"] = config.Paths.Register
		env["AUTH_PATH_LOGOUT"] = config.Paths.Logout
		env["AUTH_PATH_ACCOUNT"] = config.Paths.Account
		env["AUTH_PATH_ACCOUNT_PASSWORD"] = config.Paths.AccountPassword
		env["AUTH_PATH_ADMIN"] = config.Paths.Admin
		env["AUTH_PATH_ADMIN_USERS_API"] = config.Paths.AdminUsersAPI
		env["AUTH_ASSETS_PATH"] = config.Paths.Assets

		// Pass XSRF token to PHP
		env["HTTP_X_XSRF_TOKEN"] = middleware.GetXSRFToken(r)

		// Asynchronously log the proxying action to avoid blocking the request.
		worker.Submit(workerPool, func() {
			logging.AppLog.Debug("Proxying to PHP-FPM", "script_filename", scriptFilename, "doc_root", finalDocRoot)
		})

		env["REQUEST_METHOD"] = r.Method
		env["SERVER_SOFTWARE"] = "go / auth-proxy"
		env["REMOTE_ADDR"] = r.RemoteAddr
		env["SERVER_PROTOCOL"] = r.Proto
		env["QUERY_STRING"] = r.URL.RawQuery
		env["REQUEST_URI"] = r.RequestURI
		env["SCRIPT_NAME"] = r.URL.Path
		for name, headers := range r.Header {
			name = "HTTP_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
			env[name] = strings.Join(headers, ", ")
		}

		var body io.Reader
		if r.Body != nil {
			bodyBytes, _ := io.ReadAll(r.Body)
			env["CONTENT_LENGTH"] = strconv.Itoa(len(bodyBytes))
			body = bytes.NewReader(bodyBytes)
		} else {
			env["CONTENT_LENGTH"] = "0"
		}
		env["CONTENT_TYPE"] = r.Header.Get("Content-Type")

		resp, err := fcgi.Request(env, body)
		if err != nil {
			ip := logging.GetClientIP(r)
			errStr := err.Error()
			worker.Submit(workerPool, func() {
				logging.AppLog.Error("FastCGI request failed", "error", errStr, "ip", ip)
			})
			http.Error(w, "FastCGI request failed: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Copy headers
		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}

		// Check for PHP errors communicated via status header (a common pattern)
		if status := resp.Header.Get("Status"); strings.HasPrefix(status, "404") {
			http.NotFound(w, r)
			return
		}

		statusCode := resp.StatusCode
		if statusCode == 0 {
			statusCode = http.StatusOK // Default to 200 OK if not specified
		}
		w.WriteHeader(statusCode)

		// Copy body
		if _, err := io.Copy(w, resp.Body); err != nil {
			logging.AppLog.Error("Failed to copy response body from PHP-FPM", "error", err)
		}
	})
}
