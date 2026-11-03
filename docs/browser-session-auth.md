# Browser API authentication: Cookie session gateway

This design is **IAP-like** and follows the separation of browser session management from signed upstream identity forwarding. It is not a complete OAuth 2.0 BFF implementation: the proxy itself handles local authentication, not OAuth authorization-code exchange.

**References:** [RFC 10017 §6.1](https://www.rfc-editor.org/rfc/rfc10017.html#section-6.1) · [Google IAP signed headers](https://docs.cloud.google.com/iap/docs/signed-headers-howto) · [OWASP WebSocket Security](https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html) · [Go CrossOriginProtection](https://pkg.go.dev/net/http#CrossOriginProtection).

## Select the authentication plane

```dotenv
PROTECT_API=true
API_AUTH_MODE=session
```

- `bearer` (default): only `Authorization: Bearer <access JWT>`, for CLI/batch/services.
- `session`: only an `auth_token` HttpOnly session cookie, for browser apps without custom Authorization headers.
- `either`: valid Bearer JWT if Authorization is present; otherwise a checked browser session cookie. Invalid Authorization **never** falls back to the cookie.

`PROTECT_API=false` does **not** protect `/api/` even if frontend protection is enabled. The server refuses `API_AUTH_MODE=session` or `either` when `PROTECT_API=false`.

When the browser opens `http://192.168.10.5:8080` from another VLAN (`192.168.20.14`), its requests to that exact origin are same-origin. The client source IP is *not* part of the origin comparison. On direct HTTP, set `COOKIE_SECURE=false` (the Docker default is `true`); this exposes credentials to possible LAN interception. Prefer HTTPS, and never add an entire private subnet to `TRUSTED_PROXY_CIDRS`.

## Browser request and token flows

The session cookie is sent automatically on same-origin `fetch('/api/...')`, `new EventSource('/api/events')`, WebSocket handshakes, and normal HTML subresource requests. Native EventSource and browser WebSocket do not provide generic arbitrary Authorization header options. Use same-origin browser APIs instead of putting tokens in query parameters.

Read-only GET/HEAD requests require a valid session but **not** an XSRF token. Unsafe methods (POST, PUT, PATCH, DELETE, etc.) additionally require a signed XSRF token bound to that session and the configured API scope. Fetch it with:

```js
const { xsrf_token } = await fetch('/api/auth/csrf', {
  credentials: 'same-origin',
  cache: 'no-store',
}).then(r => { if (!r.ok) throw new Error('Not signed in'); return r.json(); });

await fetch('/api/items', {
  method: 'POST',
  credentials: 'same-origin',
  headers: { 'Content-Type': 'application/json', 'X-XSRF-Token': xsrf_token },
  body: JSON.stringify({ name: 'example' }),
});
```

The JSON 401 includes `X-Login-URL` for ordinary fetch clients and `Cache-Control: no-store`. **Native EventSource cannot inspect response headers**. On `onerror`, check login state using a separate fetch endpoint and navigate to login if it returns 401. Navigation-style requests (`Accept: text/html`, `Sec-Fetch-Mode: navigate`) can receive a 302 login redirect.

Cookie requests reject conflicting `Origin` / `Referer` / `Sec-Fetch-Site` signals. WebSocket `Upgrade` handshakes additionally **require an exact matching Origin**, because WebSocket uses GET but can perform state-changing actions. Set WebSocket message limits and recheck long-lived permissions in the upstream; the proxy only authenticates the handshake. SameSite=Lax and `CrossOriginProtection` on first-party routes are layers, not replacements for per-session XSRF tokens.

Cross-origin credentialed browser APIs are **not** silently enabled. `CSRF_TRUSTED_ORIGINS` applies to the first-party web UI protection, not to this strictly same-origin cookie API mode. If you need multiple public origins, prefer a single-origin reverse proxy or design a separate exact-Origin CORS policy with secure SameSite=None cookies and explicit CSRF defenses.

## Upstream identity

The edge removes caller-controlled identity headers, `Authorization`, the `auth_token` cookie and its `anon_xsrf` cookie before proxying, leaving unrelated upstream cookies intact. It supplies verified `X-Auth-Request-User`, `X-Auth-Request-Role`, `X-Auth-Request-User-ID` and legacy `X-Username` / `X-User-Role` names from the authenticated context.

To provide a verifiable identity assertion:

```dotenv
UPSTREAM_ASSERTION_ED25519_SEED=<base64 encoded 32-byte seed generated via openssl rand -base64 32>
UPSTREAM_ASSERTION_AUDIENCE=backend.internal:8081
UPSTREAM_ASSERTION_AS_BEARER=false
```

Generate a dedicated private seed and export the corresponding **public** verification key:

```sh
export UPSTREAM_ASSERTION_ED25519_SEED="$(openssl rand -base64 32)"
go run ./cmd/assertion-public-key
```

Provision only the resulting base64-encoded **public key** to each upstream service, ideally using an authenticated deployment channel. Do not expose the seed in CI logs or container image layers.

The seed is a **dedicated private signing key**, not `SESSION_SECRET`. The resulting `X-Auth-Request-JWT` uses EdDSA (Ed25519), with `iss=auth-proxy`, `aud` (target host:port by default), `sub` (user ID), `preferred_username`, `role`, `iat`, `exp` (60 seconds), and random `jti`. The upstream **must verify signature and audience, issuer, and expiry** using its provisioned public key. Setting `UPSTREAM_ASSERTION_AS_BEARER=true` additionally puts the signed assertion into `Authorization: Bearer` for backends requiring it. It never forwards the caller's raw JWT or edge session cookie.

Without a verifying backend, unsigned identity headers are safe only when the backend is network-isolated from clients (loopback, internal Docker network, firewall). Do not publish such a backend directly on another VLAN. Signed claims do not automatically revalidate already-established WebSocket sessions after revocation.

Authenticated responses use `Cache-Control: private, no-store` and `Vary: Cookie` to avoid accidental caching of per-user responses.

## Streaming and reverse proxies

The Go reverse proxy already supports HTTP upgrade and SSE streaming. Avoid global `WriteTimeout` on the gateway: long-running events and WebSocket sessions need a streaming-friendly configuration.

For Nginx in front of the gateway, consider `proxy_buffering off` for event streams, a longer `proxy_read_timeout`, and `proxy_set_header Upgrade $http_upgrade` plus a proper Connection mapping for WebSockets. Restrict the trusted forwarding proxy list to the real Nginx peer, not all RFC1918 clients. Prefer periodic heartbeat events for idle SSE connections. HTTP-only direct VLAN users should not set `COOKIE_SECURE=true` if they expect browsers to send cookies.
