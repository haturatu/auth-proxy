#!/usr/bin/env bash
set -euo pipefail

kind=${1:-postgres}
name="auth-proxy-sso-sql-$kind-$$"
password=$(openssl rand -hex 24)
cleanup() { docker rm -fv "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT

case "$kind" in
  postgres)
    docker run -d --name "$name" -p 127.0.0.1:15432:5432 \
      -e POSTGRES_USER=auth -e POSTGRES_DB=auth -e POSTGRES_PASSWORD="$password" postgres:17-alpine >/dev/null
    for attempt in $(seq 1 90); do
      if docker exec "$name" pg_isready -U auth -d auth >/dev/null 2>&1; then break; fi
      sleep 1
    done
    export SSO_TEST_DATABASE_URL="postgres://auth:$password@127.0.0.1:15432/auth?sslmode=disable"
    ;;
  mysql)
    docker run -d --name "$name" -p 127.0.0.1:13306:3306 \
      -e MYSQL_USER=auth -e MYSQL_DATABASE=auth -e MYSQL_PASSWORD="$password" -e MYSQL_ROOT_PASSWORD="$password" mysql:8.4 >/dev/null
    for attempt in $(seq 1 90); do
      if docker exec -e MYSQL_PWD="$password" "$name" mysql -h 127.0.0.1 -u auth -D auth -e 'SELECT 1' >/dev/null 2>&1; then break; fi
      sleep 1
    done
    export SSO_TEST_DATABASE_URL="mysql://auth:$password@127.0.0.1:13306/auth"
    ;;
  *) echo 'usage: bash tests/sso-sql.sh postgres|mysql' >&2; exit 1 ;;
esac

go test ./sso -run '^TestSSOSQLBackend$' -count=1 -timeout=120s
