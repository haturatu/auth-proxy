# Refresh Token Rotation and Replay Detection

API refresh credentials are opaque random values. The database stores only their SHA-256 digests.

## Issuance and rotation

1. A client receives an access JWT and a refresh token at sign-in.
2. A valid refresh request atomically consumes the existing token and issues its replacement.
3. The consumed token's digest is retained in `consumed_refresh_tokens` for a bounded period, to recognize replay after rotation.
4. A second submission of a consumed token is denied. When the spent-token digest is known, the current refresh credential for that user is revoked. Unknown or malformed credentials cannot revoke an unrelated user.
5. Background cleanup removes expired active and consumed credentials.

This schema supports SQLite, PostgreSQL, and MySQL. Legacy `refresh_tokens.is_revoked` columns can remain on existing databases after upgrade; new installations no longer require the redundant state.

## Operational characteristics

Because this implementation uses one refresh token per user, a replay indication invalidates that user's currently active refresh credential, and the client must sign in again. Parallel refresh requests using the same token do not both succeed. API access JWTs are separate short-lived credentials; expired or otherwise invalid JWTs are not revived by a consumed refresh token.

Clients should serialize refresh attempts, persist each successful replacement atomically, and treat an HTTP 401 from refresh as a request to authenticate again. This is not a cross-device token-family model; a future multi-session implementation must add a session/family identifier before revoking by family rather than by user.
