<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**  *generated with [DocToc](https://github.com/thlorenz/doctoc)*

- [Auth Proxy](#auth-proxy)
  - [Try the Demo](#try-the-demo)
  - [Why I Built This](#why-i-built-this)
  - [Features](#features)
  - [Security and Authentication Details](#security-and-authentication-details)
    - [XSRF Protection](#xsrf-protection)
    - [Password Encryption](#password-encryption)
    - [Authentication Flow](#authentication-flow)
      - [1. Web UI (Session-Based)](#1-web-ui-session-based)
      - [2. API (JWT-Based)](#2-api-jwt-based)
    - [Session Management](#session-management)
      - [Web UI Sessions](#web-ui-sessions)
      - [API Sessions (Stateless with JWT)](#api-sessions-stateless-with-jwt)
    - [Transport Layer Security (HTTPS)](#transport-layer-security-https)
  - [Getting Started](#getting-started)
    - [Prerequisites](#prerequisites)
    - [Installation](#installation)
    - [Configuration](#configuration)
- [Example `.env` file:](#example-env-file)
    - [Frontend Selection](#frontend-selection)
      - [PHP Frontend Setup](#php-frontend-setup)
    - [Database Setup Examples](#database-setup-examples)
      - [PostgreSQL](#postgresql)
      - [MySQL / MariaDB](#mysql--mariadb)
  - [Usage](#usage)
  - [Issuing API Tokens (Bearer Tokens)](#issuing-api-tokens-bearer-tokens)
    - [Proxying to Protected Backend APIs](#proxying-to-protected-backend-apis)
  - [Admin API Endpoints](#admin-api-endpoints)
    - [List Users](#list-users)
    - [Create User](#create-user)
    - [Update User Role](#update-user-role)
    - [Update User Status](#update-user-status)
    - [Delete User](#delete-user)
  - [Configuration Details](#configuration-details)
  - [demo](#demo)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->
  
  <img width="1366" height="526" alt="image" src="https://github.com/user-attachments/assets/eab0085e-00d9-434a-b8eb-6c174fa59f5d" />
  
  
  # Auth Proxy
  
  This is a simple authenticating reverse proxy written in Go. It provides a flexible authentication layer that can be placed in front of any backend web service.
  
  It handles user registration, login, and session management, and proxies authenticated requests to the configured backend. It also includes an administration dashboard for user management.
  
  ## Try the Demo
  ```bash
  git clone https://github.com/haturatu/auth-proxy.git
  cd auth-proxy
  chmod +x run-demo.sh
  bash run-demo.sh
  ```
  
  ## Why I Built This
  
  I'm also the developer of [puremania](https://github.com/haturatu/puremania), and I wanted to avoid adding complex authentication logic to that project.
  While integrating authentication into every application is good for security, it's a hassle to manage separate IDs and passwords for each one. This is a common problem for self-hosting enthusiasts who need a centralized way to control access.
  This project aims to solve that by acting as a central authentication service. By referencing the same database, user information can be shared across different applications.
  
  ## Features
  
  - **Authentication**: Provides login, logout, and registration pages.
  - **Reverse Proxy**: Proxies authenticated users to a backend service.
  - **Admin Dashboard**: A simple UI to manage users (update roles, activate/deactivate, delete).
  - **Flexible Database Support**: Works with PostgreSQL, MySQL, and SQLite.
  - **Pluggable Frontend**: Supports multiple frontend modes (JS-driven or PHP).
  - **Security Hardening**:
      - **Brute-force Protection**: Locks user accounts after a configurable number of failed login attempts. This protection applies to both the web UI login and the `/api/auth/token` endpoint.
      - **User Creation Rate Limiting**: Prevents the same IP from creating too many users in a short period.
      - **Configurable Password Policies**: Enforce password strength requirements. See details below.
      - **Secure Session Cookies**: Uses `HttpOnly` secure cookies for session management.
  - **Highly Configurable**: Nearly all aspects, including database connections, security policies, and internal URL paths, can be configured via an `.env` file.
  - **Structured Logging**: Detailed application and security logs using `slog`.
  - **CLI for Admin Creation**: A command-line tool to easily create initial admin users.
  
  ## Security and Authentication Details
  
  ### XSRF Protection
  
  The proxy includes XSRF (Cross-Site Request Forgery) protection to prevent malicious attacks. This is implemented using the `golang.org/x/net/xsrftoken` library.
  
  When a user visits a page that performs state-changing requests (like a form submission), a unique, per-session XSRF token is generated. This token is embedded in the page, typically in a hidden form field or a meta tag. When the user submits the form or makes an API call, the token is sent back to the server in a header (`X-XSRF-Token`) or as part of the form data.
  
  The server validates that the token is correct for the user's session and the specific action being performed. If the token is missing or invalid, the request is rejected. This ensures that the request is legitimate and originates from your application, not a malicious third-party site.
  
  This protection is enabled by default. You only need to configure the secret key used to generate the tokens:
  
  - `XSRF_SECRET_KEY`: A 32-byte, base64-encoded random key for XSRF protection.
  
  ### Password Encryption
  
  User passwords are never stored in plaintext. They are securely hashed using the **bcrypt** algorithm, a strong, adaptive hashing function designed specifically for passwords. When a user logs in, the provided password is
  hashed and then compared to the stored hash, preventing plaintext password exposure even if the database is compromised.
  
  ### Authentication Flow
  
  The proxy supports two distinct authentication flows for different use cases:
  
  #### 1. Web UI (Session-Based)
  
  This flow is designed for users interacting with the application through a web browser.
  
  1.  A user submits their username and password via the login page.
  2.  The server validates the credentials against the database.
  3.  On success, a cryptographically secure, random token is generated and stored in the database, associated with the user.
  4.  This token is sent to the user's browser in a secure, `HttpOnly` cookie named `auth_token`, establishing a session.
  
  #### 2. API (JWT-Based)
  
  This flow is designed for programmatic clients and services.
  
  1.  A client sends a `POST` request with the user's username and password to the `/api/auth/token` endpoint.
  2.  The server validates the credentials.
  3.  On success, it generates and returns two tokens:
      *   A short-lived **JWT Access Token** containing user claims (ID, role) and an expiration time. This token is signed to prevent tampering.
      *   A long-lived **Refresh Token** that is stored in the database and can be used to obtain a new access token.
  
  ### Session Management
  
  #### Web UI Sessions
  
  For subsequent requests from a browser, the `auth_token` cookie is automatically sent to the server. A middleware validates this token by looking it up in the database. If the token is valid and has not expired, the request is authenticated and allowed to proceed. When a user logs out, the session token is deleted from the database, effectively invalidating the session.
  
  #### API Sessions (Stateless with JWT)
  
  For API requests, the client must include the JWT Access Token in the `Authorization: Bearer <token>` header. A middleware on the server validates the token's signature and expiration time. This process is stateless, meaning it does not require a database lookup for every request, making it highly efficient. If the access token has expired, the client can use the refresh token to request a new access token without re-authenticating.
  
  **Note on Authentication Precedence:** When an API endpoint is protected (i.e., `PROTECT_API=true`), the middleware first looks for an `Authorization: Bearer` header. If this header is not present, it will fall back to validating the `auth_token` session cookie. This allows users who are logged into the web UI to also authenticate to the API using their browser session, but it means that API endpoints are accessible via either a valid JWT or a valid session cookie.
  
  ### Transport Layer Security (HTTPS)
  
  For production environments, it is **critical** to run this proxy behind a TLS-terminating reverse proxy (like Nginx, Caddy, or a cloud load balancer).
  
  This application does not handle HTTPS termination itself. By default, it communicates over HTTP. If you deploy it without a secure proxy in front, sensitive data like user passwords sent during login could be intercepted in a Man-in-the-Middle (MITM) attack. However, MITM attacks are realistically difficult and usually require the attacker to be on the same network. An easy way to prevent this is to place the backend application and this authentication proxy behind an HTTP server like Nginx. This effectively wraps the communication in TLS, though it is not a complete solution.  
  ## Getting Started
  
  ### Prerequisites
  
  - Go 1.27.3 or later
  - (Optional) A running PHP-FPM service if you intend to use the PHP frontend.
  - (Optional) PostgreSQL or MySQL database server.
  
  ### Installation
  
  1.  **Clone the repository:**
      ```sh
      git clone https://github.com/haturatu/auth-proxy
      cd auth-proxy
      ```
  
  2.  **Install dependencies:**
      ```sh
      go mod tidy
      ```
  
  3.  **Build the binaries:**
      ```sh
      go build -o auth-proxy-server ./cmd/server && go build -o admin-cli ./cmd/admin-cli
      ```
  
  ### Configuration
  
  Configuration is managed via a `.env` file in the root of the project. Create a file named `.env` and add the necessary variables.
  
  # Example `.env` file:
  
  ```dotenv
  # --- Server Settings ---
  # The port for the proxy server to listen on
  LISTEN_PORT=8080
  
  # --- Required ---
  # The URL of the backend service you want to protect
  TARGET_URL=http://localhost:8081
  
  # A long, random string for securing session cookies and JWTs
  # For production, generate a new key using: openssl rand -base64 45
  SESSION_SECRET=my-super-secret-key
  
  # (Required) A 32-byte random key for XSRF protection.
  # Generate with: openssl rand -base64 32
  XSRF_SECRET_KEY=
  
  # --- Database ---
  # Use ONE of the following options:
  
  # Option 1: PostgreSQL or MySQL (Recommended)
  # Example: postgres://user:password@host:port/dbname?sslmode=disable
  # Example: mysql://user:password@tcp(host:port)/dbname?charset=utf8mb4&parseTime=true
  DATABASE_URL=mysql://test:test@127.0.0.1:3306/auth
  
  # Option 2: SQLite (Default if DATABASE_URL is not set)
  # DATABASE_PATH=./auth.db
  
  # --- Frontend & Proxy ---
  # Frontend mode: "js" (default) or "php"
  FRONTEND_TYPE=js
  # If true, protects the frontend path with session authentication
  PROTECT_FRONTEND=false
  # If true, protects the API path with bearer token authentication
  PROTECT_API=false
  # Base path for frontend routes to be protected
  FRONT_PATH=/
  # Base path for API routes to be protected
  API_PATH=/api/
  
  # --- Security Policies ---
  
  # Brute-force protection settings
  MAX_LOGIN_ATTEMPTS=5
  LOCKOUT_DURATION_MINUTES=10
  
  # User creation rate limit settings
  USER_CREATION_RATE_LIMIT_MAX_REQUESTS=5
  USER_CREATION_RATE_LIMIT_WINDOW_SECONDS=3600
  
  # Password policy (none, standard, enhanced, strict)
  PASSWORD_POLICY=standard
  
  # --- Token Durations ---
  # Duration for the web session cookie
  TOKEN_DURATION_HOURS=24
  # Duration for the API JWT access token
  ACCESS_TOKEN_DURATION_MINUTES=15
  # Duration for the API JWT refresh token
  REFRESH_TOKEN_DURATION_DAYS=7
  
  # --- Optional: Path Overrides ---
  # Uncomment and change these to avoid URL conflicts with your backend application.
  # AUTH_PATH_LOGIN=/login
  # AUTH_PATH_REGISTER=/register
  # AUTH_PATH_LOGOUT=/logout
  # AUTH_PATH_ACCOUNT=/account
  # AUTH_PATH_ACCOUNT_PASSWORD=/account/password
  # AUTH_PATH_ADMIN=/admin
  # AUTH_PATH_ADMIN_USERS_API=/api/admin/users
  # AUTH_ASSETS_PATH=/assets
  ```
  
  ### Frontend Selection
  
  You can choose between two frontend modes using the `FRONTEND_TYPE` environment variable:
  
  -   **`js` (or empty)**: This is the default mode. The server renders the basic HTML templates, and all authentication logic (rendering forms, handling user input) is expected to be managed by your frontend JavaScript code, which will interact with the Go backend's API endpoints.
  -   **`php`**: To use the PHP-based views, you must have a running PHP-FPM service. This mode proxies GET requests for authentication pages to your PHP-FPM service, while POST requests (like login submissions) are handled by the Go backend.
  
  #### PHP Frontend Setup
  
  If you choose `FRONTEND_TYPE=php`, follow these steps:
  
  1.  **Set Frontend Type in `.env`**:
      ```dotenv
      FRONTEND_TYPE=php
      ```
  
  2.  **Configure PHP-FPM Connection in `.env`**:
      You need to provide the path to the PHP-FPM socket and the document root.
      -   `PHP_FPM_SOCKET`: The path to the PHP-FPM socket file (e.g., `/run/php-fpm/php-fpm.sock`).
      -   `PHP_DOC_ROOT`: The **absolute path** to the directory containing the PHP view files (e.g., `login.php`). This path must be accessible *by the PHP-FPM process*.
  
  3.  **Copy PHP Files and Set Permissions**:
      The user that the PHP-FPM service runs as needs read access to the PHP template files.
  
      First, determine the PHP-FPM user. You can often find this in your PHP-FPM pool configuration file (e.g., `/etc/php/8.3/fpm/pool.d/www.conf`) or by checking the running processes:
      ```sh
      # Example command to find the PHP-FPM user
      ps aux | grep php-fpm
      ```
      Common users are `www-data`, `http`, or `apache`.
  
      Next, copy the `templates/php` directory to a location accessible by PHP-FPM (e.g., `/var/www/html/auth-proxy`) and set the correct ownership.
  
      ```sh
      # Example setup, assuming the user is 'http'
      sudo cp -r templates/php /var/www/html/auth-proxy/php
      sudo chown -R http:http /var/www/html/auth-proxy
      ```
  
      Finally, update your `.env` file with the correct paths:
      ```dotenv
      # --- PHP Frontend Settings ---
      FRONTEND_TYPE=php
      PHP_FPM_SOCKET=/run/php-fpm/php-fpm.sock
      PHP_DOC_ROOT=/var/www/html/auth-proxy/php
      ```
  
  ### Database Setup Examples
  
  If you are using PostgreSQL or MySQL, you will need to create a database and a user for the proxy.
  
  #### PostgreSQL
  
  Run these commands in `psql`:
  
  ```sql
  -- Create a dedicated database
  CREATE DATABASE auth_proxy;
  
  -- Create a dedicated user
  CREATE USER auth_user WITH PASSWORD 'your_strong_password';
  
  -- Grant privileges on the database to the user
  GRANT ALL PRIVILEGES ON DATABASE auth_proxy TO auth_user;
  ```
  
  Your `DATABASE_URL` in the `.env` file would then be:
  `DATABASE_URL=postgres://auth_user:your_strong_password@localhost:5432/auth_proxy?sslmode=disable`
  
  #### MySQL / MariaDB
  
  Run these commands in the MySQL client:
  
  ```sql
  -- Create a dedicated database
  CREATE DATABASE auth_proxy CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
  
  -- Create a dedicated user
  CREATE USER 'auth_user'@'localhost' IDENTIFIED BY 'your_strong_password';
  
  -- Grant privileges on the database to the user
  GRANT ALL PRIVILEGES ON auth_proxy.* TO 'auth_user'@'localhost';
  
  -- Apply the changes
  FLUSH PRIVILEGES;
  ```
  
  Your `DATABASE_URL` in the `.env` file would then be:
  `DATABASE_URL=mysql://auth_user:your_strong_password@tcp(127.0.0.1:3306)/auth_proxy?parseTime=true`
  
  ## Usage
  
  1.  **Create an Admin User**:
  
      Before starting the server, create your first admin user using the `admin-cli` tool. Make sure your `.env` file is configured correctly, as the CLI uses it to connect to the database.
  
      The `--username` and `--password` flags are required.
  
      *Successful command:*
      ```sh
      ./admin-cli --username <your-admin-username> --password <your-strong-password>
      ```
  
      *Example of missing flags:*
      ```sh
      $ ./admin-cli 
      time=2025-10-12T04:28:09.014+09:00 level=ERROR msg="Both --username and --password flags are required"
      ```
  
  2.  **Run the Proxy Server**:
  
      ```sh
      ./auth-proxy-server
      ```
  
      The server will start on port `:8080` by default.
  
  3.  **Access the Application**:
  
      - Open your browser and navigate to `http://localhost:8080`.
      - You will be redirected to the login page.
      - Log in with the admin credentials you created.
      - Once authenticated, you will be seamlessly proxied to the `TARGET_URL`.
      - You can access the admin dashboard at `http://localhost:8080/admin` (or your configured path).
  
  ## Issuing API Tokens (Bearer Tokens)
  
  In addition to session-based authentication for web browsers, the proxy can issue JWT (JSON Web Tokens) for programmatic API access. These tokens can be used as Bearer Tokens in the `Authorization` header to authenticate requests to protected backend APIs.
  
  To obtain an access token and a refresh token, send a `POST` request to the `/api/auth/token` endpoint with the user's credentials in the JSON body.
  
  **Example using `curl`:**
  
  ```sh
  curl -X POST -H "Content-Type: application/json" -d '{
    "username": "your-username",
    "password": "your-password"
  }' http://localhost:8080/api/auth/token
  ```
  
  **Successful Response:**
  
  If the credentials are valid, the server will respond with a JSON object containing an `access_token` and a `refresh_token`.
  
  ```json
  {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxLCJyb2xlIjoiYWRtaW4iLCJleHAiOjE2Njc4OTg5ODl9.abcdef123456...",
    "refresh_token": "def456..."
  }
  ```
  
  The `access_token` is a short-lived JWT that should be sent in the `Authorization` header for API requests:
  
  ```
  Authorization: Bearer <access_token>
  ```
  
  The `refresh_token` is a long-lived token that can be used to obtain a new access token once the old one expires. To do this, send a `POST` request to the `/auth/refresh` endpoint.
  
  **Note:** The token lifetimes can be configured in your `.env` file. See the configuration table for details.
  
  ### Proxying to Protected Backend APIs
  
  When `PROTECT_API=true`, any request to a path under `API_PATH` (e.g., `/api/`) that is not one of the internal administrative endpoints will be authenticated and then proxied to your backend `TARGET_URL`.
  
  This allows you to protect your own backend APIs using the same authentication mechanism. Authentication is verified using either a valid `Authorization: Bearer` token or, as a fallback, a valid web session cookie.
  
  **Example `curl` to a protected backend API:**
  
  ```sh
  ACCESS_TOKEN="your_access_token"
  curl -H "Authorization: Bearer $ACCESS_TOKEN" http://localhost:8080/api/config
  ```
  
  **Example successful response from the backend:**
  ```json
  {"success":true,"data":{"StorageDir":"/home/haturatu","MountDirs":[],"MaxFileSize":10000,"SpecificDirs":["/home/haturatu/git"],"Aria2cEnabled":true}}
  ```
  
  ## Admin API Endpoints
  
  For administrative tasks, the proxy provides several API endpoints that can be accessed programmatically. All of these endpoints require a valid Bearer Token from a user with the `admin` role.
  
  The base path for these endpoints is `/api/admin/users`, which can be customized with the `AUTH_PATH_ADMIN_USERS_API` environment variable.
  
  ### List Users
  
  - **Endpoint**: `GET /api/admin/users`
  - **Description**: Retrieves a list of all users in the system.
  - **Example**:
    ```sh
    ACCESS_TOKEN="your_admin_access_token"
    curl -H "Authorization: Bearer $ACCESS_TOKEN" http://localhost:8080/api/admin/users
    ```
  
  ### Create User
  
  - **Endpoint**: `POST /api/admin/users`
  - **Description**: Creates a new user.
  - **Body**:
    ```json
    {
      "username": "newuser",
      "password": "a-strong-password",
      "role": "user"
    }
    ```
  - **Example**:
    ```sh
    ACCESS_TOKEN="your_admin_access_token"
    curl -X POST -H "Authorization: Bearer $ACCESS_TOKEN" \
         -H "Content-Type: application/json" \
         -d '{"username": "newuser", "password": "Password123", "role": "user"}' \
         http://localhost:8080/api/admin/users
    ```
  
  ### Update User Role
  
  - **Endpoint**: `POST /api/admin/users/{id}/role`
  - **Description**: Updates the role of a specific user by their ID.
  - **Body**:
    ```json
    {
      "role": "admin"
    }
    ```
  - **Example**:
    ```sh
    USER_ID=2
    ACCESS_TOKEN="your_admin_access_token"
    curl -X POST -H "Authorization: Bearer $ACCESS_TOKEN" \
         -H "Content-Type: application/json" \
         -d '{"role": "admin"}' \
         http://localhost:8080/api/admin/users/$USER_ID/role
    ```
  
  ### Update User Status
  
  - **Endpoint**: `POST /api/admin/users/{id}/status`
  - **Description**: Activates or deactivates a user by their ID.
  - **Body**:
    ```json
    {
      "is_active": false
    }
    ```
  - **Example**:
    ```sh
    USER_ID=2
    ACCESS_TOKEN="your_admin_access_token"
    curl -X POST -H "Authorization: Bearer $ACCESS_TOKEN" \
         -H "Content-Type: application/json" \
         -d '{"is_active": false}' \
         http://localhost:8080/api/admin/users/$USER_ID/status
    ```
  
  ### Delete User
  
  - **Endpoint**: `DELETE /api/admin/users/{id}`
  - **Description**: Deletes a user by their ID.
  - **Example**:
    ```sh
    USER_ID=2
    ACCESS_TOKEN="your_admin_access_token"
    curl -X DELETE -H "Authorization: Bearer $ACCESS_TOKEN" \
         http://localhost:8080/api/admin/users/$USER_ID
    ```
  
  ## Configuration Details
  
  | Environment Variable | Description | Default Value |
  | --- | --- | --- |
  | `TARGET_URL` | **(Required)** The URL of the backend service to proxy to. | - |
  | `SESSION_SECRET` | **(Required)** A long, random secret key for encrypting session cookies and signing JWTs. | `default-secret-key-for-dev` |
  | `XSRF_SECRET_KEY` | **(Required)** A 32-byte, base64-encoded random key for XSRF protection. Generate with `openssl rand -base64 32`. | - |
  | `DATABASE_URL` | The connection string for PostgreSQL or MySQL. If set, this overrides `DATABASE_PATH`. | - |
  | `DATABASE_PATH` | The file path for the SQLite database. Used only if `DATABASE_URL` is not set. | `./auth.db` |
  | `LOG_LEVEL` | Sets the logging level. Can be `DEBUG`, `INFO`, `WARN`, `ERROR`. | `INFO`                 |
  | `LISTEN_PORT` | The port for the proxy server to listen on. | `8080`                 |
  | `FRONTEND_TYPE` | Switches the frontend rendering mode. Can be `js` or `php`. | `js` |
  | `PHP_FPM_SOCKET` | The file path to the PHP-FPM socket. Used only when `FRONTEND_TYPE` is `php`. | `/run/php-fpm/php-fpm.sock` |
  | `PHP_DOC_ROOT` | The absolute path to the PHP files directory. Used only when `FRONTEND_TYPE` is `php`. | - |
  | `MAX_LOGIN_ATTEMPTS` | Number of failed login attempts before an account is locked. | `5` |
  | `LOCKOUT_DURATION_MINUTES` | Duration in minutes for how long an account remains locked. | `10` |
  | `USER_CREATION_RATE_LIMIT_MAX_REQUESTS` | Max number of user registrations allowed from a single IP within the time window. | `5` |
  | `USER_CREATION_RATE_LIMIT_WINDOW_SECONDS` | The time window in seconds for the user creation rate limit. | `3600` (1 hour) |
  | `PASSWORD_POLICY` | Sets the password strength requirements (`none`, `standard`, `enhanced`, `strict`). | `standard` |
  | `TOKEN_DURATION_HOURS` | The duration in hours for the web session cookie. | `24` |
  | `ACCESS_TOKEN_DURATION_MINUTES` | The duration in minutes for a JWT access token for API clients. | `15` |
  | `REFRESH_TOKEN_DURATION_DAYS` | The duration in days for a JWT refresh token for API clients. | `7` |
  | `PROTECT_FRONTEND` | If `true`, proxies all frontend paths through session authentication. | `false` |
  | `PROTECT_API` | If `true`, proxies all API paths through bearer token authentication. | `false` |
  | `FRONT_PATH` | The base path for frontend routes to be protected by `PROTECT_FRONTEND`. | `/` |
  | `API_PATH` | The base path for API routes to be protected by `PROTECT_API`. | `/api/` |
  | `REGISTER` | If set to `false`, disables new user registration. | `true` |
  | `AUTH_PATH_*` | A set of variables to customize the internal URLs for login, admin, etc. | Various, e.g., `/login`|
  | `AUTH_ASSETS_PATH` | The URL path for serving internal static assets (CSS, JS). | `/assets` |
  | `ENV` | The runtime environment. Set to `production` to enable secure cookies. | - |
  
  ## demo
  <img width="1366" height="461" alt="image" src="https://github.com/user-attachments/assets/17632b15-b0a3-4cc7-bafa-7392a209bcc7" />
  <img width="1366" height="461" alt="image" src="https://github.com/user-attachments/assets/bea8beb4-485b-4fac-9015-bf2c9d3490ac" />
  
  ```
  
