# Docker Compose

The same application image supports SQLite, PostgreSQL, MySQL and external PostgreSQL/MySQL.

## Setup

```sh
git clone https://github.com/haturatu/auth-proxy.git
cd auth-proxy
cp .env.example .env
openssl rand -hex 32      # SESSION_SECRET
openssl rand -base64 32   # XSRF_SECRET_KEY
```

Put the generated secrets in `.env`. Set `TARGET_URL` to the protected backend's URL. The example `http://host.docker.internal:8081` targets a service on the Docker host (with supported Docker). To reach a service in another Compose stack, attach them to a common Docker network.

The proxy only publishes on `127.0.0.1:8080` by default. Put a TLS terminating Nginx/Caddy proxy in front. Keep `COOKIE_SECURE=true` for HTTPS, including TLS termination upstream. Set it to `false` **only for localhost HTTP development**. The default frontend is `js`; PHP mode requires a separately configured PHP-FPM socket.

## Choose the database

| DB | .env COMPOSE_FILE | Additional variables |
| --- | --- | --- |
| SQLite (default) | `compose.yaml` | none |
| PostgreSQL | `compose.yaml:compose.postgres.yaml` | `DB_PASSWORD` |
| MySQL | `compose.yaml:compose.mysql.yaml` | `DB_PASSWORD` and `MYSQL_ROOT_PASSWORD` |
| External PostgreSQL/MySQL | `compose.yaml` | `DATABASE_URL` |

Use a URI-safe random password (`openssl rand -hex 24`) for the bundled DBs. `DB_USER` and `DB_NAME` default to `auth`. On Linux/macOS, multiple `COMPOSE_FILE` entries are colon-separated.

```sh
docker compose config -q
docker compose up -d --build
docker compose ps
```

Without setting `COMPOSE_FILE`, select a DB explicitly:

```sh
docker compose -f compose.yaml -f compose.postgres.yaml up -d --build
docker compose -f compose.yaml -f compose.mysql.yaml up -d --build
```

Use only one DB option. SQLite persists in `sqlite_data` at `/data/auth.db`. PostgreSQL/MySQL have separate named volumes, no published DB ports, and healthchecks. The application retries DB connection at startup.

For an external DB, use only `compose.yaml`, with an appropriate TLS-validated URL:

```dotenv
DATABASE_URL=postgres://user:password@db.example.com:5432/auth?sslmode=verify-full
# DATABASE_URL=mysql://user:password@db.example.com:3306/auth?parseTime=true&tls=true
```

Percent-encode URL-reserved characters in passwords.

## Operations

```sh
docker compose logs -f auth-proxy
docker compose exec auth-proxy /app/admin-cli --username admin --password-stdin
# Type the password and press Enter.
docker compose down
```

`GET /healthz` checks DB availability; block public access at the front proxy if unnecessary. The app runs as an unprivileged user.

**WARNING:** `docker compose down -v` deletes stored database data. Switching the selected DB does **not** migrate users, tokens or sessions; back up and migrate explicitly. The existing table creation logic is not a full schema migration system.

## Username collation

New and existing MySQL/MariaDB databases use `utf8mb4_bin` for the `users.username` unique column so `Admin` and `admin` are distinct, as in the default SQLite/PostgreSQL configurations. The startup migration checks the old collation and changes it if necessary; the ALTER can lock a large table, so schedule rollout accordingly. The application does not perform Unicode NFC/NFD normalization; restrict visually confusable identifiers via local registration policy if that matters for your deployment. MySQL/MariaDB trailing-space collation semantics may still differ, so avoid usernames containing trailing spaces.
