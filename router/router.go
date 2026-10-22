package router

import (
	"auth-proxy/config"
	"auth-proxy/handlers"
	"auth-proxy/logging"
	"auth-proxy/middleware"
	"auth-proxy/models"
	"auth-proxy/types"
	"auth-proxy/worker"
	"net/http"
	"os"
	"strings"
	"time"
)

// NewRouter creates and configures the main application router.
func NewRouter() http.Handler {
	targetURL := os.Getenv("TARGET_URL")

	// --- Create routers for Web and API ---
	webMux := http.NewServeMux()
	apiMux := http.NewServeMux()

	// --- Static file serving (Web) ---
	assetsPath := strings.TrimRight(config.Paths.Assets, "/") + "/"
	assetsFS := http.FileServer(http.Dir("templates"))
	webMux.Handle(assetsPath, http.StripPrefix(assetsPath, assetsFS))

	// --- Rate Limiter ---
	rateLimiter := middleware.NewRateLimiter()

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

		loginHandler := methodSwitch(loginPageHandler, http.HandlerFunc(handlers.LoginHandler))
		webMux.Handle(config.Paths.Login, loginHandler)

		if config.Paths.RegisterEnabled {
			registerPostHandler := middleware.RateLimitMiddleware(rateLimiter)(http.HandlerFunc(handlers.RegisterHandler))
			registerHandler := methodSwitch(registerPageHandler, registerPostHandler)
			webMux.Handle(config.Paths.Register, registerHandler)
		}

		accountPasswordPostHandler := http.HandlerFunc(handlers.ChangePasswordHandler)
		accountPasswordHandler := methodSwitch(accountPasswordPageHandler, accountPasswordPostHandler)
		webMux.Handle(config.Paths.AccountPassword, middleware.SessionAuth(accountPasswordHandler))
		webMux.Handle(config.Paths.Account, middleware.SessionAuth(accountPageHandler))
		webMux.Handle(config.Paths.Admin, middleware.SessionAuth(middleware.AdminMiddleware(http.HandlerFunc(handlers.AdminPageHandler))))
	} else {
		// Go template frontend routes
		webMux.HandleFunc(config.Paths.Login, handlers.LoginHandler)
		if config.Paths.RegisterEnabled {
			webMux.Handle(config.Paths.Register, middleware.RateLimitMiddleware(rateLimiter)(http.HandlerFunc(handlers.RegisterHandler)))
		}
		webMux.Handle(config.Paths.Account, middleware.SessionAuth(http.HandlerFunc(handlers.AccountPageHandler)))
		webMux.Handle(config.Paths.Admin, middleware.SessionAuth(middleware.AdminMiddleware(http.HandlerFunc(handlers.AdminPageHandler))))
		webMux.Handle(config.Paths.AccountPassword, middleware.SessionAuth(http.HandlerFunc(handlers.ChangePasswordHandler)))
	}
	webMux.HandleFunc(config.Paths.Logout, handlers.LogoutHandler)

	// --- API Routes (No XSRF) ---
	apiMux.HandleFunc("/api/auth/token", handlers.TokenHandler)
	apiMux.HandleFunc("/auth/refresh", handlers.RefreshTokenHandler)

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

	apiMux.Handle(config.Paths.AdminUsersAPI, middleware.BearerAuth(middleware.AdminMiddleware(adminUsersAPI)))
	apiMux.Handle(config.Paths.AdminUsersAPI+"/", middleware.BearerAuth(middleware.AdminMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	}))))

	// --- Main Application Proxy ---
	proxyHandler := handlers.NewProxy(targetURL)

	// --- XSRF Protection (for Web UI) ---
	xsrfProtectedWebMux := middleware.HandleOptions(middleware.XSRF(webMux))

	// --- Final Handler ---
	finalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle API paths
		if strings.HasPrefix(r.URL.Path, config.Paths.APIPath) {
			// Check if a specific handler exists in the API mux
			_, pattern := apiMux.Handler(r)

			// If a specific pattern is found, let the API mux handle it internally.
			if pattern != "" {
				apiMux.ServeHTTP(w, r)
				return
			}

			// If no specific handler is found, it's a request to be proxied.
			// Protect it with Bearer/Cookie auth if PROTECT_API is enabled.
			if config.Paths.ProtectAPI {
				middleware.BearerAuth(proxyHandler).ServeHTTP(w, r)
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

		// Fallback to proxy for all other paths
		if config.Paths.ProtectFrontend {
			middleware.SessionAuth(proxyHandler).ServeHTTP(w, r)
		} else {
			proxyHandler.ServeHTTP(w, r)
		}
	})

	return finalHandler
}

// StartBackgroundTasks launches periodic jobs for cleanup.
func StartBackgroundTasks(pool *types.WorkerPool, limiter *types.RateLimiter) {
	// Ticker for expired token cleanup (every hour)
	tokenTicker := time.NewTicker(1 * time.Hour)
	defer tokenTicker.Stop()

	// Ticker for rate limiter cleanup (every 24 hours)
	rateLimiterTicker := time.NewTicker(24 * time.Hour)
	defer rateLimiterTicker.Stop()

	logging.AppLog.Info("Background task scheduler started")

	// Run initial cleanup tasks at startup
	submitTokenCleanup(pool)
	submitRateLimiterCleanup(pool, limiter)

	// Run tasks on their respective tickers
	for {
		select {
		case <-tokenTicker.C:
			submitTokenCleanup(pool)
		case <-rateLimiterTicker.C:
			submitRateLimiterCleanup(pool, limiter)
		}
	}
}

// submitTokenCleanup submits the expired token deletion task to the worker pool.
func submitTokenCleanup(pool *types.WorkerPool) {
	worker.Submit(pool, func() {
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
