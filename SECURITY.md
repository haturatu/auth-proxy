# Security & deployment (Go 1.27)

This project is an authentication layer in front of third-party applications. Protect the application listener using a firewall and terminate TLS before exposing it to the Internet.

## VLAN-to-VLAN direct access (no reverse proxy)

For a browser opened at `http://192.168.10.5:8080` from VLAN 20 (for example 192.168.20.10), **no trusted proxy or origin entry is necessary**. Go checks the page's scheme+hostname/port against the request, not the client's source IP. The anonymous CSRF session cookie and existing DB-backed authentication cookie work over HTTP with `COOKIE_SECURE=auto` (they are not encrypted in transit).

```dotenv
LISTEN_PORT=8080
COOKIE_SECURE=auto
TRUSTED_PROXY_CIDRS=
CSRF_TRUSTED_ORIGINS=
```

Keep the listener restricted to trusted VLANs. HTTP is vulnerable to passive observation and active interception even on a LAN; use HTTPS if possible. The application does not infer trust from RFC1918 ranges. A spoofed `X-Forwarded-For` or `X-Forwarded-Proto` from another VLAN is ignored.

## TLS behind a reverse proxy

Set `COOKIE_SECURE=true` to ensure HttpOnly + Secure + SameSite=Lax cookies even when the Go listener sees HTTP. Configure `TRUSTED_PROXY_CIDRS` with **only your actual reverse proxy peer IP(s)**, never `192.168.0.0/16` merely because it is private.

```dotenv
COOKIE_SECURE=true
TRUSTED_PROXY_CIDRS=127.0.0.1/32
```

Example Nginx when Nginx is the direct internet-facing listener:

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $http_host;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Username "";
    proxy_set_header X-User-Role "";
}
```

The Go proxy traverses X-Forwarded-For from right to left while the current peer is trusted. Never expose your backend app directly when it trusts `X-Username` or `X-User-Role`; the proxy regenerates these from verified authentication context.

## Browser CSRF and API clients

- Browser forms require a 15-minute signed XSRF token bound to an anonymous cookie or authenticated session. Do not remove the `anon_xsrf` cookie on login pages.
- Go `CrossOriginProtection` rejects unsafe cross-origin browser requests to auth UI and admin API, not to arbitrary upstream/proxied paths.
- A cookie-authenticated mutation to the admin API additionally requires the XSRF token issued by the admin page. The existing JavaScript uses `X-XSRF-Token` for this.
- Generic proxied API writes that use `BearerAuth` require a Bearer token; cookie fallback is only allowed for safe read methods. This is a deliberate tightening of behavior.
- `CSRF_TRUSTED_ORIGINS` is an optional **exact** comma-separated list of additional browser origins, such as `http://192.168.20.10:8080`, for deliberate cross-origin access. It is NOT a source-IP allowlist, CORS configuration, or an authentication bypass. Same-origin direct VLAN usage needs no entry.

## Secrets and passwords

`SESSION_SECRET` must be at least 32 bytes of high-entropy data; missing/short values fail startup. Use `openssl rand -base64 48`. JWT HS256 signing uses `crypto/hkdf` (context `auth-proxy/jwt-hs256/v1`). New JWTs cannot be validated by old builds. During rollout, set `JWT_ACCEPT_LEGACY_SIGNATURE=true` only long enough for earlier access JWTs to expire, then turn it off. Keep the previous SESSION_SECRET during that window.

`XSRF_SECRET_KEY` remains an independent 32-byte base64-encoded random secret: `openssl rand -base64 32`.

The default password hashing algorithm remains bcrypt (cost 14). Setting `PASSWORD_HASH_ALGORITHM=pbkdf2-sha256` optionally uses Go 1.24+ `crypto/pbkdf2`, PBKDF2-HMAC-SHA256 with 600,000 iterations and per-password 16-byte random salts. Existing bcrypt hashes still verify. PBKDF2 is **not** an improvement over bcrypt for every threat model; keep the default unless compatibility requirements justify an alternative.

## Resource limits

Auth/admin request bodies are limited to 64 KiB; upstream proxying remains streaming and does not impose this limit. The listener uses a 5-second header timeout, 60-second idle timeout, 32 KiB max headers, and 128 header values. Adjust only after checking actual clients.

## Exclusions

FIPS 140-3, ML-KEM, and ML-DSA are intentionally not added.
