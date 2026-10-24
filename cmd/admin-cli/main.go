package main

import (
	"auth-proxy/config"
	"auth-proxy/database"
	"auth-proxy/logging"
	"auth-proxy/models"
	"auth-proxy/utils"
	"flag"
	"fmt"
	"os"

	"github.com/joho/godotenv"
)

func main() {
	// Initialize logging
	logging.InitLoggers()

	// Load .env file and initialize config
	if err := godotenv.Load(); err != nil {
		logging.AppLog.Info("No .env file found, using environment variables")
	}
	config.Init()

	username := flag.String("username", "", "Username for the new admin user")
	password := flag.String("password", "", "Password for the new admin user")
	flag.Parse()

	if *username == "" || *password == "" {
		logging.AppLog.Error("Both --username and --password flags are required")
		os.Exit(1)
	}

	// Validate password policy
	if ok, message := utils.ValidatePassword(*password); !ok {
		logging.AppLog.Error("Password does not meet the policy", "reason", message)
		os.Exit(1)
	}

	// Initialize DB connection
	database.InitDB()
	defer database.CloseDB()

	// Check if user already exists
	existingUser, err := models.GetUserByUsername(*username)
	if err != nil {
		logging.AppLog.Error("Error checking for existing user", "error", err)
		os.Exit(1)
	}
	if existingUser != nil {
		logging.AppLog.Error(fmt.Sprintf("User '%s' already exists.", *username))
		os.Exit(1)
	}

	// Create admin user
	_, err = models.CreateUser(*username, *password, "admin")
	if err != nil {
		logging.AppLog.Error("Failed to create admin user", "error", err)
		os.Exit(1)
	}

	fmt.Printf("Admin user '%s' created successfully.\n", *username)
}
