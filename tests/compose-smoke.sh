#!/usr/bin/env bash
set -euo pipefail
db="${1:-sqlite}"
export COMPOSE_PROJECT_NAME=auth-proxy-smoke AUTH_PORT=18080 BIND_ADDRESS=127.0.0.1
export TARGET_URL=http://example.invalid COOKIE_SECURE=false
export SESSION_SECRET="$(openssl rand -hex 32)"
export XSRF_SECRET_KEY="$(openssl rand -base64 32)"
export DB_USER=auth DB_NAME=auth
export DB_PASSWORD="$(openssl rand -hex 24)"
export MYSQL_ROOT_PASSWORD="$(openssl rand -hex 24)"
export DATABASE_URL="" COMPOSE_FILE=compose.yaml
files=(-f compose.yaml)
case "$db" in
  sqlite) ;;
  postgres) files+=(-f compose.postgres.yaml) ;;
  mysql) files+=(-f compose.mysql.yaml) ;;
  *) echo "unknown DB: $db" >&2; exit 2 ;;
esac
compose() { docker compose "${files[@]}" "$@"; }
cleanup() {
  status=$?
  if (( status != 0 )); then compose ps || true; compose logs --tail=150 || true; fi
  compose down -v --remove-orphans || true
  exit "$status"
}
trap cleanup EXIT
compose config -q
compose up -d --no-build
for attempt in $(seq 1 60); do
  if curl --fail --silent http://127.0.0.1:18080/healthz >/dev/null; then break; fi
  sleep 2
done
curl --fail --silent http://127.0.0.1:18080/healthz >/dev/null
printf '%s\n' 'correct-horse-battery-staple-123' | compose exec -T auth-proxy /app/admin-cli --username smoke-admin --password-stdin
# Distinct-case accounts must remain distinct in every database backend.
printf '%s\n' 'correct-horse-battery-staple-123' | compose exec -T auth-proxy /app/admin-cli --username SmokeCase --password-stdin
printf '%s\n' 'correct-horse-battery-staple-123' | compose exec -T auth-proxy /app/admin-cli --username smokecase --password-stdin
response="$(curl --fail --silent -H 'Content-Type: application/json' -d '{"username":"smoke-admin","password":"correct-horse-battery-staple-123"}' http://127.0.0.1:18080/api/auth/token)"
echo "$response" | grep -q '"access_token"'
echo "$response" | grep -q '"refresh_token"'
compose restart auth-proxy
for attempt in $(seq 1 30); do
  if curl --fail --silent http://127.0.0.1:18080/healthz >/dev/null; then break; fi
  sleep 2
done
curl --fail --silent http://127.0.0.1:18080/healthz >/dev/null
echo "Smoke test passed: $db"
