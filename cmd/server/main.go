package main

import (
	"auth-proxy/config"
	"auth-proxy/database"
	"auth-proxy/handlers"
	"auth-proxy/logging"
	"auth-proxy/middleware"
	"auth-proxy/router"
	"auth-proxy/worker"
	"net/http"
	"os"
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

	// --- Secret Key Validation ---
	sessionSecret := os.Getenv("SESSION_SECRET")
	if len(sessionSecret) < 32 {
		logging.AppLog.Error("SESSION_SECRET must contain at least 32 bytes of random data")
		os.Exit(1)
	}
	if err := logging.ConfigureTrustedProxies(os.Getenv("TRUSTED_PROXY_CIDRS")); err != nil {
		logging.AppLog.Error("Invalid TRUSTED_PROXY_CIDRS", "error", err)
		os.Exit(1)
	}
	xsrfSecret := os.Getenv("XSRF_SECRET_KEY")
	if xsrfSecret == "" {
		logging.AppLog.Error("XSRF_SECRET_KEY environment variable not set")
		os.Exit(1)
	}

	// Get target URL for proxy
	targetURL := os.Getenv("TARGET_URL")
	if targetURL == "" {
		logging.AppLog.Error("TARGET_URL environment variable not set")
		os.Exit(1)
	}

	// Create the main handler
	rateLimiter := middleware.NewRateLimiter()
	mainRouter := router.NewRouter(rateLimiter)

	// Start periodic background tasks
	go router.StartBackgroundTasks(pool, rateLimiter)

	// Get server port
	port := os.Getenv("LISTEN_PORT")
	if port == "" {
		port = "8080"
	}
	listenAddr := ":" + port

	// --- Start Server ---
	logging.AppLog.Info("Server starting on " + listenAddr)

	srv := &http.Server{
		Addr:                listenAddr,
		Handler:             mainRouter,
		ReadHeaderTimeout:   5 * time.Second,
		IdleTimeout:         60 * time.Second,
		MaxHeaderBytes:      32 << 10,
		MaxHeaderValueCount: 128,
	}
	if err := srv.ListenAndServe(); err != nil {
		logging.AppLog.Error("Server failed to start", "error", err)
		os.Exit(1)
	}
}
