package main

import (
	"auth-proxy/config"
	"auth-proxy/database"
	"auth-proxy/handlers"
	"auth-proxy/logging"
	"auth-proxy/middleware"
	"auth-proxy/router"
	"auth-proxy/worker"
	"context"
	"net/http"
	"os"
	"time"

	"github.com/joho/godotenv"
)

func main() {
	logging.InitLoggers()

	if err := godotenv.Load(); err != nil {
		logging.AppLog.Info("No .env file found, using environment variables")
	}
	config.Init()
	if err := config.Validate(); err != nil {
		logging.AppLog.Error("Invalid configuration", "error", err)
		os.Exit(1)
	}
	logging.AppLog.Info("Authentication plane configured",
		"protect_frontend", config.Paths.ProtectFrontend,
		"protect_api", config.Paths.ProtectAPI,
		"api_auth_mode", config.Paths.APIAuthMode,
	)

	// Only honor forwarded headers from explicitly configured proxy peers.
	// Direct clients on another VLAN require no trusted CIDR.
	if err := logging.ConfigureTrustedProxies(os.Getenv("TRUSTED_PROXY_CIDRS")); err != nil {
		logging.AppLog.Error("Invalid TRUSTED_PROXY_CIDRS", "error", err)
		os.Exit(1)
	}

	database.InitDB()
	defer database.CloseDB()

	pool := worker.NewWorkerPool()
	defer worker.Close(pool)
	handlers.SetWorkerPool(pool)

	rateLimiter := middleware.NewRateLimiter()
	loginLimiter := middleware.NewLoginRateLimiter()
	mainRouter := router.NewRouter(rateLimiter, loginLimiter)
	go router.StartBackgroundTasks(pool, rateLimiter, loginLimiter)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := database.DB.PingContext(ctx); err != nil {
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.Handle("/", mainRouter)

	port := os.Getenv("LISTEN_PORT")
	if port == "" {
		port = "8080"
	}
	listenAddr := ":" + port
	logging.AppLog.Info("Server starting on " + listenAddr)
	srv := &http.Server{
		Addr:                listenAddr,
		Handler:             mux,
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
