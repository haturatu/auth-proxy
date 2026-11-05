package router

import (
	"auth-proxy/config"
	"auth-proxy/handlers"
	"auth-proxy/logging"
	"auth-proxy/middleware"
	"auth-proxy/models"
	"auth-proxy/sso"
	"auth-proxy/types"
	"auth-proxy/worker"
	"net/http"
	"os"
	"strings"
	"time"
)

// isAPIPath checks the path prefix at a URL segment boundary, including the
// prefix root itself (for example /api and /api/...).
func isAPIPath(path, prefix string) bool {
	root := strings.TrimSuffix(prefix, "/")
	return path == root || strings.HasPrefix(path, root+"/")
}

// isAuthUIAlias detects ambiguous spellings of service-owned UI routes.
// Without this check, /admin/ or /ADMIN could reach a case/slash-insensitive
// upstream when the proxied frontend is intentionally public.
func isAuthUIAlias(path string) bool {
	reserved := []string{
		config.Paths.Login, config.Paths.Register, config.Paths.Logout,
		config.Paths.Account, config.Paths.AccountPassword, config.Paths.Admin,
	}
	for _, route := range reserved {
		if route != "" && path != route &&
			strings.EqualFold(strings.TrimRight(path, "/"), strings.TrimRight(route, "/")) {
			return true
		}
	}
	return false
}

// allowedRequestHost validates the external Host only when an explicit list
// is configured. Public deployments should set ALLOWED_HOSTS to all front-door
// host:port combinations; default remains open for local development.
func allowedRequestHost(host string) bool {
	allowed := strings.TrimSpace(os.Getenv("ALLOWED_HOSTS"))
	if allowed == "" {
		return true
	}
	for _, entry := range strings.Split(allowed, ",") {
		if strings.EqualFold(strings.TrimSpace(entry), host) {
			return true
		}
	}
	return false
}

// NewRouter creates and configures the main application router.
func NewRouter(rateLimiter, loginLimiter *types.RateLimiter) http.Handler {
	h, err := NewRouterChecked(rateLimiter, loginLimiter)
	if err != nil {
		panic(err)
	}
	return h
}

// NewRouterChecked reports initialization failures to the server so fatal
// configuration/database errors are logged to stderr and exit with status 1.
func NewRouterChecked(rateLimiter, loginLimiter *types.RateLimiter) (http.Handler, error) {
	targetURL := os.Getenv("TARGET_URL")
	var identity *sso.Service
	if c, err := config.LoadSSO(); err != nil {
		return nil, err
	} else if c != nil {
		identity, err = sso.New(c, handlers.AuthenticatePassword, loginLimiter, rateLimiter)
		if err != nil {
			return nil, err
		}
	}

	// Browser CSRF defense is scoped to our own UI/admin endpoints, not to
	// arbitrary proxied traffic (WebDAV, APIs, streaming, etc.).
	crossOrigin := http.NewCrossOriginProtection()
	for _, entry := range strings.Split(os.Getenv("CSRF_TRUSTED_ORIGINS"), ",") {
		origin := strings.TrimSpace(entry)
		if origin == "" {
			continue
		}
		if err := crossOrigin.AddTrustedOrigin(origin); err != nil {
			panic("invalid CSRF_TRUSTED_ORIGINS: " + err.Error())
		}
	}

	// --- Create routers for Web and API ---
	webMux := http.NewServeMux()
	apiMux := http.NewServeMux()

	// --- Static file serving (Web) ---
	assetsPath := strings.TrimRight(config.Paths.Assets, "/") + "/"
	assetsFS := http.FileServer(http.Dir("templates"))
	webMux.Handle(assetsPath, http.StripPrefix(assetsPath, assetsFS))

	// --- Rate Limiter ---

	// Helper to switch handler based on HTTP method
	methodSwitch := func(get, post http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				post.ServeHTTP(w, r)
			} else {
				get.ServeHTTP(w, r)
			}
		})
	}

	// --- Web UI Routes (XSRF-protected) ---
	if os.Getenv("FRONTEND_TYPE") == "php" {
		// PHP frontend routes
		loginPageHandler := handlers.NewPhpProxyHandler("login.php")
		registerPageHandler := handlers.NewPhpProxyHandler("register.php")
		accountPageHandler := handlers.NewPhpProxyHandler("account.php")
		accountPasswordPageHandler := handlers.NewPhpProxyHandler("account_password.php")

		loginHandler := methodSwitch(loginPageHandler, middleware.RateLimitMiddleware(loginLimiter)(middleware.LimitAuthBody(http.HandlerFunc(handlers.LoginHandler))))
		webMux.Handle(config.Paths.Login, loginHandler)

		if config.Paths.RegisterEnabled {
			registerPostHandler := middleware.RateLimitMiddleware(rateLimiter)(middleware.LimitAuthBody(http.HandlerFunc(handlers.RegisterHandler)))
			registerHandler := methodSwitch(registerPageHandler, registerPostHandler)
			webMux.Handle(config.Paths.Register, registerHandler)
		}

		accountPasswordPostHandler := middleware.LimitAuthBody(http.HandlerFunc(handlers.ChangePasswordHandler))
		accountPasswordHandler := methodSwitch(accountPasswordPageHandler, accountPasswordPostHandler)
		webMux.Handle(config.Paths.AccountPassword, middleware.SessionAuth(accountPasswordHandler))
		webMux.Handle(config.Paths.Account, middleware.SessionAuth(accountPageHandler))
		webMux.Handle(config.Paths.Admin, middleware.SessionAuth(middleware.AdminMiddleware(http.HandlerFunc(handlers.AdminPageHandler))))
	} else {
		// Go template frontend routes
		webMux.Handle(config.Paths.Login, middleware.RateLimitMiddleware(loginLimiter)(middleware.LimitAuthBody(http.HandlerFunc(handlers.LoginHandler))))
		if config.Paths.RegisterEnabled {
			webMux.Handle(config.Paths.Register, middleware.RateLimitMiddleware(rateLimiter)(middleware.LimitAuthBody(http.HandlerFunc(handlers.RegisterHandler))))
		}
		webMux.Handle(config.Paths.Account, middleware.SessionAuth(http.HandlerFunc(handlers.AccountPageHandler)))
		webMux.Handle(config.Paths.Admin, middleware.SessionAuth(middleware.AdminMiddleware(http.HandlerFunc(handlers.AdminPageHandler))))
		webMux.Handle(config.Paths.AccountPassword, middleware.SessionAuth(middleware.LimitAuthBody(http.HandlerFunc(handlers.ChangePasswordHandler))))
	}
	webMux.HandleFunc(config.Paths.Logout, handlers.LogoutHandler)

	// --- API Routes (No XSRF) ---
	apiMux.Handle("/api/auth/token", middleware.RateLimitMiddleware(loginLimiter)(middleware.LimitAuthBody(http.HandlerFunc(handlers.TokenHandler))))
	if config.Paths.APIAuthMode != "bearer" {
		// A signed token for same-origin browser API mutations. No JS token
		// is needed for GET EventSource streams or WebSocket handshakes.
		apiMux.Handle(config.Paths.APIPath+"auth/csrf", http.HandlerFunc(middleware.SessionXSRFEndpoint))
	}
	apiMux.Handle("/auth/refresh", middleware.LimitAuthBody(http.HandlerFunc(handlers.RefreshTokenHandler)))

	// Admin API endpoints
	adminCreateUserAPI := http.HandlerFunc(handlers.CreateUserHandler)
	getUsersHandler := http.HandlerFunc(handlers.GetUsersHandler)
	adminUsersAPI := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			adminCreateUserAPI.ServeHTTP(w, r)
		} else {
			getUsersHandler.ServeHTTP(w, r)
		}
	})
	adminUpdateRoleAPI := http.HandlerFunc(handlers.UpdateUserRoleHandler)
	adminDeleteUserAPI := http.HandlerFunc(handlers.DeleteUserHandler)
	adminSetStatusAPI := http.HandlerFunc(handlers.SetUserActiveStatusHandler)

	apiMux.Handle(config.Paths.AdminUsersAPI, crossOrigin.Handler(middleware.AdminBearerAuth(middleware.AdminMiddleware(middleware.LimitAuthBody(adminUsersAPI)))))
	apiMux.Handle(config.Paths.AdminUsersAPI+"/", crossOrigin.Handler(middleware.AdminBearerAuth(middleware.AdminMiddleware(middleware.LimitAuthBody(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case strings.HasSuffix(path, "/role") && r.Method == http.MethodPost:
			adminUpdateRoleAPI.ServeHTTP(w, r)
		case strings.HasSuffix(path, "/status") && r.Method == http.MethodPost:
			adminSetStatusAPI.ServeHTTP(w, r)
		case r.Method == http.MethodDelete:
			adminDeleteUserAPI.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	}))))))

	// --- Main Application Proxy ---
	proxyHandler := handlers.NewProxy(targetURL)

	// --- XSRF Protection (for Web UI) ---
	xsrfProtectedWebMux := crossOrigin.Handler(middleware.HandleOptions(middleware.XSRF(webMux)))

	// --- Final Handler ---
	finalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowedRequestHost(r.Host) {
			http.Error(w, "Misdirected Request", http.StatusMisdirectedRequest)
			return
		}

		// Always dispatch the service-owned API routes before any proxy fallback.
		// In particular, a custom admin API path must never bypass the
		// AdminBearerAuth/AdminMiddleware chain when it is outside API_PATH.
		if _, pattern := apiMux.Handler(r); pattern != "" {
			apiMux.ServeHTTP(w, r)
			return
		}
		if sso.Owns(r.URL.Path) {
			if identity == nil {
				http.NotFound(w, r)
			} else {
				identity.ServeHTTP(w, r)
			}
			return
		}
		if targetURL == "" {
			if r.URL.Path == "/" {
				http.Redirect(w, r, "/sso/account", http.StatusFound)
				return
			}
			// Existing local user/admin routes remain available in IdP-only mode.
			if _, pattern := webMux.Handler(r); pattern == "" {
				if _, pattern := apiMux.Handler(r); pattern == "" {
					http.NotFound(w, r)
					return
				}
			}
		}
		// Handle proxied API paths. Service-owned routes were dispatched above.
		if isAPIPath(r.URL.Path, config.Paths.APIPath) {
			// If no specific handler is found, it's a request to be proxied.
			// Select explicit authentication mode for protected API paths.
			// PROTECT_API=false would expose all upstream API traffic.
			if config.Paths.ProtectAPI {
				middleware.APIAuth(config.Paths.APIAuthMode, proxyHandler).ServeHTTP(w, r)
			} else {
				proxyHandler.ServeHTTP(w, r)
			}
			return
		}

		// Check if the path is a web UI path and apply XSRF protection
		_, webPattern := webMux.Handler(r)
		if webPattern != "" {
			xsrfProtectedWebMux.ServeHTTP(w, r)
			return
		}

		// Never forward path aliases of local authentication pages upstream.
		if isAuthUIAlias(r.URL.Path) {
			http.NotFound(w, r)
			return
		}

		// Fallback to proxy for all other paths
		if config.Paths.ProtectFrontend {
			middleware.SessionAuth(proxyHandler).ServeHTTP(w, r)
		} else {
			proxyHandler.ServeHTTP(w, r)
		}
	})

	return finalHandler, nil
}

// StartBackgroundTasks launches periodic jobs for cleanup.
func StartBackgroundTasks(pool *types.WorkerPool, limiter, loginLimiter *types.RateLimiter) {
	// Ticker for expired token cleanup (every hour)
	tokenTicker := time.NewTicker(1 * time.Hour)
	defer tokenTicker.Stop()

	// Ticker for rate limiter cleanup (every minute)
	rateLimiterTicker := time.NewTicker(time.Minute)
	defer rateLimiterTicker.Stop()

	logging.AppLog.Info("Background task scheduler started")

	// Run initial cleanup tasks at startup
	submitTokenCleanup(pool)
	submitRateLimiterCleanup(pool, limiter)
	submitRateLimiterCleanup(pool, loginLimiter)

	// Run tasks on their respective tickers
	for {
		select {
		case <-tokenTicker.C:
			submitTokenCleanup(pool)
		case <-rateLimiterTicker.C:
			submitRateLimiterCleanup(pool, limiter)
			submitRateLimiterCleanup(pool, loginLimiter)
		}
	}
}

// submitTokenCleanup submits the expired token deletion task to the worker pool.
func submitTokenCleanup(pool *types.WorkerPool) {
	worker.Submit(pool, func() {
		if err := sso.Cleanup(); err != nil {
			logging.AppLog.Error("Failed to clean up SSO records", "error", err)
		}
		logging.AppLog.Info("Running background task: deleting expired tokens")
		rowsAffected, err := models.DeleteExpiredTokens()
		if err != nil {
			logging.AppLog.Error("Failed to delete expired tokens", "error", err)
		} else {
			if rowsAffected > 0 {
				logging.AppLog.Info("Finished deleting expired tokens", "deleted_count", rowsAffected)
			}
		}
	})
}

// submitRateLimiterCleanup submits the rate limiter cleanup task to the worker pool.
func submitRateLimiterCleanup(pool *types.WorkerPool, limiter *types.RateLimiter) {
	worker.Submit(pool, func() {
		logging.AppLog.Info("Running background task: cleaning up rate limiter")
		middleware.Cleanup(limiter)
	})
}
