package main

import (
	"auth-proxy/config"
	"auth-proxy/database"
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

	"github.com/joho/godotenv"
)

func main() {
	// Initialize loggers
	logging.InitLoggers()

	// Load .env file
	if err := godotenv.Load(); err != nil {
		logging.AppLog.Info("No .env file found, using environment variables")
	}

	// Initialize path configurations
	config.Init()

	// Initialize database
	database.InitDB()
	defer database.CloseDB()

	// Initialize and start the worker pool
	pool := worker.NewWorkerPool()
	defer worker.Close(pool)
	handlers.SetWorkerPool(pool)

	// Get target URL for proxy
	targetURL := os.Getenv("TARGET_URL")
	if targetURL == "" {
		logging.AppLog.Error("TARGET_URL environment variable not set")
		os.Exit(1)
	}

	// --- Create router and define routes ---
	mux := http.NewServeMux()

	// --- Static file serving ---
	assetsPath := strings.TrimRight(config.Paths.Assets, "/") + "/"
	assetsFS := http.FileServer(http.Dir("templates"))
	mux.Handle(assetsPath, http.StripPrefix(assetsPath, assetsFS))

	// --- Frontend selection and routing ---
	frontendType := os.Getenv("FRONTEND_TYPE")
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

	if frontendType == "php" {
		// Create specific handlers for each PHP page
		loginPageHandler := handlers.NewPhpProxyHandler("login.php")
		registerPageHandler := handlers.NewPhpProxyHandler("register.php")
		accountPageHandler := handlers.NewPhpProxyHandler("account.php")
		accountPasswordPageHandler := handlers.NewPhpProxyHandler("account_password.php")

		// For /login, GET goes to PHP, POST goes to Go's login logic
		loginHandler := methodSwitch(loginPageHandler, http.HandlerFunc(handlers.LoginHandler))
		mux.Handle(config.Paths.Login, middleware.RedirectIfLoggedIn(loginHandler))

		if config.Paths.RegisterEnabled {
			// For /register, GET goes to PHP, POST goes to Go's register logic
			registerPostHandler := middleware.RateLimitMiddleware(rateLimiter)(http.HandlerFunc(handlers.RegisterHandler))
			registerHandler := methodSwitch(registerPageHandler, registerPostHandler)
			mux.Handle(config.Paths.Register, middleware.RedirectIfLoggedIn(registerHandler))
		}

		// For account pages, GET goes to PHP, POST (for password change) goes to Go
		accountPasswordPostHandler := http.HandlerFunc(handlers.ChangePasswordHandler)
		accountPasswordHandler := methodSwitch(accountPasswordPageHandler, accountPasswordPostHandler)
		mux.Handle(config.Paths.AccountPassword, middleware.SessionAuth(accountPasswordHandler))
		mux.Handle(config.Paths.Account, middleware.SessionAuth(accountPageHandler)) // This page is GET only

		// Admin page still uses Go templates
		mux.Handle(config.Paths.Admin, middleware.SessionAuth(middleware.AdminMiddleware(http.HandlerFunc(handlers.AdminPageHandler))))
	} else {
		// --- Public Auth Routes (Go templates) ---
		mux.Handle(config.Paths.Login, middleware.RedirectIfLoggedIn(http.HandlerFunc(handlers.LoginHandler)))
		if config.Paths.RegisterEnabled {
			registerHandler := middleware.RateLimitMiddleware(rateLimiter)(http.HandlerFunc(handlers.RegisterHandler))
			mux.Handle(config.Paths.Register, middleware.RedirectIfLoggedIn(registerHandler))
		}
		// --- Auth HTML pages (Protected by SessionAuth, Go templates) ---
		mux.Handle(config.Paths.Account, middleware.SessionAuth(http.HandlerFunc(handlers.AccountPageHandler)))
		mux.Handle(config.Paths.Admin, middleware.SessionAuth(middleware.AdminMiddleware(http.HandlerFunc(handlers.AdminPageHandler))))
		mux.Handle(config.Paths.AccountPassword, middleware.SessionAuth(http.HandlerFunc(handlers.ChangePasswordHandler)))
	}

	// --- Common Routes ---
	mux.HandleFunc(config.Paths.Logout, handlers.LogoutHandler)
	mux.HandleFunc("/auth/refresh", handlers.RefreshTokenHandler)
	mux.HandleFunc("/api/auth/token", handlers.TokenHandler)

	// --- Protected API Endpoints (for Admin UI, protected by SessionAuth) ---
	adminUsersAPI := http.HandlerFunc(handlers.GetUsersHandler)
	adminUpdateRoleAPI := http.HandlerFunc(handlers.UpdateUserRoleHandler)
	adminDeleteUserAPI := http.HandlerFunc(handlers.DeleteUserHandler)
	adminSetStatusAPI := http.HandlerFunc(handlers.SetUserActiveStatusHandler)

	mux.Handle(config.Paths.AdminUsersAPI, middleware.SessionAuth(middleware.AdminMiddleware(adminUsersAPI)))
	mux.Handle(config.Paths.AdminUsersAPI+"/", middleware.SessionAuth(middleware.AdminMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	finalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, pattern := mux.Handler(r)
		if pattern != "" {
			mux.ServeHTTP(w, r)
			return
		}

		path := r.URL.Path

		// API Protection with Bearer Token
		if config.Paths.ProtectAPI && strings.HasPrefix(path, config.Paths.APIPath) {
			middleware.BearerAuth(proxyHandler).ServeHTTP(w, r)
			return
		}

		// Frontend Protection with Session Cookie
		if config.Paths.ProtectFrontend {
			middleware.SessionAuth(proxyHandler).ServeHTTP(w, r)
			return
		}

		// No protection
		proxyHandler.ServeHTTP(w, r)
	})

	// Get server port
	port := os.Getenv("LISTEN_PORT")
	if port == "" {
		port = "8080"
	}
	listenAddr := ":" + port

	// --- Start Server ---
	logging.AppLog.Info("Server starting on " + listenAddr)

		// Start periodic background tasks

		go startBackgroundTasks(pool, rateLimiter)

	

		if err := http.ListenAndServe(listenAddr, finalHandler); err != nil {

			logging.AppLog.Error("Server failed to start", "error", err)

			os.Exit(1)

		}

	}

	

	// startBackgroundTasks launches periodic jobs in the background.

	func startBackgroundTasks(pool *types.WorkerPool, limiter *types.RateLimiter) {

		// Ticker for expired token cleanup (every hour)

		tokenTicker := time.NewTicker(1 * time.Hour)

		defer tokenTicker.Stop()

	

		// Ticker for rate limiter cleanup (every 10 minutes)

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

	
