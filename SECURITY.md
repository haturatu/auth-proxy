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
- Protected proxied API routes use `API_AUTH_MODE=bearer` by default. `session` explicitly allows browser-cookie authentication for HTML subresources, fetch, SSE and WebSocket; `either` accepts a Bearer token or a cookie, but never falls back after an invalid `Authorization` header. Cookie-mode unsafe requests are protected by browser-verified same-origin signals (`API_SESSION_CSRF=origin`, default); set `API_SESSION_CSRF=xsrf` to also require a session-bound XSRF token. Admin APIs continue to use scoped XSRF validation.
- `CSRF_TRUSTED_ORIGINS` is an optional **exact** comma-separated list of additional browser origins, such as `http://192.168.20.10:8080`, for deliberate cross-origin access. It is NOT a source-IP allowlist, CORS configuration, or an authentication bypass. Same-origin direct VLAN usage needs no entry.

## Secrets and passwords

`SESSION_SECRET` must be at least 32 bytes of high-entropy data; missing/short values fail startup. Use `openssl rand -base64 48`. JWT HS256 signing uses `crypto/hkdf` (context `auth-proxy/jwt-hs256/v1`). All previously issued JWT access tokens signed with the raw `SESSION_SECRET` are immediately invalidated after upgrading. There is deliberately no legacy-signature fallback, migration flag, or grace period. Clients must obtain a newly signed access JWT. Database-backed refresh tokens are a separate mechanism and may still be exchangeable; explicitly revoke them in the database if all sessions must be invalidated.

`XSRF_SECRET_KEY` remains an independent 32-byte base64-encoded random secret: `openssl rand -base64 32`.

The default password hashing algorithm remains bcrypt (cost 14). Setting `PASSWORD_HASH_ALGORITHM=pbkdf2-sha256` optionally uses Go 1.24+ `crypto/pbkdf2`, PBKDF2-HMAC-SHA256 with 600,000 iterations and per-password 16-byte random salts. Existing bcrypt hashes still verify. PBKDF2 is **not** an improvement over bcrypt for every threat model; keep the default unless compatibility requirements justify an alternative.

## Resource limits

Auth/admin request bodies are limited to 64 KiB; upstream proxying remains streaming and does not impose this limit. The listener uses a 5-second header timeout, 60-second idle timeout, 32 KiB max headers, and 128 header values. Adjust only after checking actual clients.

## Exclusions

FIPS 140-3, ML-KEM, and ML-DSA are intentionally not added.

## Breaking changes by design

This hardening does **not** support legacy raw-secret JWT signing. Cookie authentication for proxied APIs is available only through the explicit `session` or `either` mode. Redeploy clients with Bearer tokens and sign in again as needed. This does not change the separate browser admin session, the signed `xsrftoken` protection, or the explicit requirement for direct HTTP access from another VLAN.

## Browser-session API gateway (IAP-like)

For the complete design, CSRF flow and backend assertion verification, see [Browser API authentication](docs/browser-session-auth.md). This uses a first-party session gateway with IAP/BFF-style identity forwarding; it is not itself an OAuth 2.0 BFF client.

`PROTECT_API=true` is mandatory for protecting backend `/api/*`; `PROTECT_FRONTEND=true` alone does not protect the API. The default is `API_AUTH_MODE=bearer`. Choose `API_AUTH_MODE=session` for cookie-only browser apps, or `either` to support both browsers and machine clients. These are deliberate opt-ins, not silent cookie fallback. In cookie mode, `API_SESSION_CSRF=origin` (default) rejects cross-site unsafe requests using Fetch Metadata/Origin; `xsrf` adds a signed per-session token for clients that can fetch `/api/auth/csrf`.

Cookie-authenticated APIs require same-origin Fetch Metadata / Origin checks, exact-Origin validation on WebSocket upgrades and signed XSRF tokens for unsafe methods. Same-origin browser JavaScript can retrieve a scoped token from `GET /api/auth/csrf` and send it as `X-XSRF-Token`. Native EventSource and browser WebSocket cannot add arbitrary Authorization headers; they can use cookies on same-origin connections. WebSocket requests without an Origin header are rejected in session modes. The API returns JSON 401 and `X-Login-URL` for non-navigation requests; native EventSource does **not** expose response headers to JavaScript, so its `onerror` handler must use a separate fetch/session-check if login detection is needed.

Upstream identity request headers are always cleared and rebuilt from authenticated context. The edge never forwards `auth_token`, `anon_xsrf` or the client's Authorization credential. Optional `UPSTREAM_ASSERTION_ED25519_SEED` (a dedicated 32-byte base64 seed) signs a 60-second EdDSA `X-Auth-Request-JWT` with issuer `auth-proxy`, audience `UPSTREAM_ASSERTION_AUDIENCE` (default TARGET_URL host:port), subject, username, role, iat, exp and jti. Set `UPSTREAM_ASSERTION_AS_BEARER=true` only if a backend needs that signed assertion as Authorization. Verify the JWT using the public Ed25519 key in the backend; **never share the private seed**. If using unsigned identity headers alone, keep upstream accessible only from the proxy, not directly from the LAN.

For direct cross-VLAN HTTP access such as `http://192.168.10.5:8080`, browsers can use same-origin cookies by setting `COOKIE_SECURE=false`, without trusted-proxy CIDRs. This is insecure against network interception; use HTTPS when possible. The default Docker configuration uses Secure cookies.

## Trusted reverse proxy boundary

`TRUSTED_PROXY_CIDRS` must list only immediate, controlled reverse-proxy peers, preferably individual `/32` or `/128` addresses. Never use an entire VLAN, RFC1918 range, `0.0.0.0/0` or `::/0`. An empty value is the secure default: direct clients cannot spoof `X-Forwarded-For`. `GetClientIP` walks XFF right-to-left, accepts parsed IP addresses only, and bounds the input to 4096 bytes and 32 hops. Invalid or fully trusted chains fall back to the observed immediate peer, not an attacker-provided value.

If an upstream proxy sends **only** `X-Real-IP` rather than `X-Forwarded-For`, its identity will be used as the source for rate limits. Configure the front door to supply a sanitized XFF chain and restrict the auth-proxy listener to that trusted proxy. `Forwarded`/`X-Real-IP` are not alternate trusted sources.
