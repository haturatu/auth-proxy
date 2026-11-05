#!/usr/bin/env bash
set -euo pipefail

repo=$(cd "$(dirname "$0")/../.." && pwd)
scratch=$(mktemp -d)
nginx_name="auth-proxy-sso-e2e-$$"
nginx_image=${NGINX_IMAGE:-nginx:stable-alpine@sha256:0e52bd054126cdc040b1276c0af347aeb02a41b9cfe305d6094767ac30e97949}
server_pid=""
cleanup() {
  docker rm -f "$nginx_name" >/dev/null 2>&1 || true
  if [[ -n "$server_pid" ]]; then kill "$server_pid" 2>/dev/null || true; wait "$server_pid" 2>/dev/null || true; fi
  rm -rf "$scratch"
}
trap cleanup EXIT

mkdir -p "$scratch/nginx/tls"
cp -R "$repo/examples/sso/nginx/." "$scratch/nginx/"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=auth.example.test \
  -addext 'subjectAltName=DNS:auth.example.test,DNS:app-a.example.test,DNS:app-b.other.test' \
  -keyout "$scratch/nginx/tls/privkey.pem" -out "$scratch/nginx/tls/fullchain.pem" 2>/dev/null
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$scratch/signing.pem" 2>/dev/null

python3 - "$repo" "$scratch" <<'PY'
from pathlib import Path
import sys
repo, scratch = map(Path, sys.argv[1:])
config = (repo / "examples/sso/config.yaml").read_text()
for old, new in [("auth.example.com", "auth.example.test"), ("app-a.example.com", "app-a.example.test"), ("app-b.other.net", "app-b.other.test")]:
    config = config.replace(old, new)
config = config.replace("https://auth.example.test", "https://auth.example.test:18443").replace("https://app-a.example.test", "https://app-a.example.test:18443").replace("https://app-b.other.test", "https://app-b.other.test:18443")
(scratch / "sso.yaml").write_text(config)
for file in (scratch / "nginx").rglob("*.conf"):
    data = file.read_text().replace("listen 443", "listen 18443")
    data = data.replace("127.0.0.1:8080", "127.0.0.1:18080").replace("127.0.0.1:8081", "127.0.0.1:18081").replace("127.0.0.1:8082", "127.0.0.1:18082")
    data = data.replace("app-a.example.com", "app-a.example.test").replace("app-b.other.net", "app-b.other.test").replace("auth.example.com", "auth.example.test")
    data = data.replace("Host auth.example.test;", "Host auth.example.test:18443;")
    file.write_text(data)
PY

cd "$repo"
go build -o "$scratch/server" ./cmd/server
ln -s "$repo/templates" "$scratch/templates"
(
  cd "$scratch"
  exec env -i PATH="$PATH" HOME="$HOME" LISTEN_PORT=18080 TARGET_URL= \
    SESSION_SECRET=sso-e2e-only-session-secret-with-more-than-32-bytes \
    XSRF_SECRET_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= \
    DATABASE_PATH="$scratch/auth.db" SSO_CONFIG="$scratch/sso.yaml" \
    SSO_SIGNING_KEY_FILE="$scratch/signing.pem" COOKIE_SECURE=true \
    TRUSTED_PROXY_CIDRS=127.0.0.1/32 AUTH_RATE_LIMIT_MAX_REQUESTS=1000 \
    "$scratch/server"
) >"$scratch/server.stdout" 2>"$scratch/server.stderr" &
server_pid=$!

for attempt in $(seq 1 100); do
  if curl --silent --fail http://127.0.0.1:18080/healthz >/dev/null; then break; fi
  if ! kill -0 "$server_pid" 2>/dev/null; then cat "$scratch/server.stderr" >&2; exit 1; fi
  sleep .1
done

docker run --rm --network host -v "$scratch/nginx:/etc/nginx:ro" "$nginx_image" nginx -t
docker run -d --name "$nginx_name" --network host -v "$scratch/nginx:/etc/nginx:ro" "$nginx_image" >/dev/null
for attempt in $(seq 1 100); do
  if curl --silent --insecure --fail --resolve auth.example.test:18443:127.0.0.1 --noproxy '*' https://auth.example.test:18443/oauth2/jwks >/dev/null; then break; fi
  sleep .1
done

cd "$repo/tests/sso-e2e"
npm ci --no-audit --no-fund
if ! SSO_TEST_DB="$scratch/auth.db" npm test; then
  # Neither log contains callback query strings or cookie values.
  cat "$scratch/server.stderr" >&2
  docker logs "$nginx_name" >&2
  exit 1
fi
