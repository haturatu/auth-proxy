# パスキー認証と複数ドメイン SSO

1 台の Nginx で TLS を終端し、1 つの auth-proxy を認証基盤として使用できます。アプリは通常の HTTP サーバーのまま配置します。`SSO_CONFIG` を設定しなければ、従来の `TARGET_URL` によるリバースプロキシとして動作します。

## 構成

| 公開オリジン | 転送先 | 役割 |
| --- | --- | --- |
| `https://auth.example.com` | auth-proxy | パスキー、共通 SSO、OIDC |
| `https://app-a.example.com` | App A | user・admin 向けアプリ |
| `https://app-b.other.net` | App B | admin 向けアプリ |

パスキーは `auth.example.com` だけで操作します。RP ID と唯一の WebAuthn Origin は認証ドメインに固定され、Related Origin Requests やサードパーティ Cookie は使用しません。

Nginx は `auth_request` でアプリ用セッションを確認します。未認証のトップレベル HTML GET に限り、Gateway が Authorization Code Flow と S256 PKCE を開始します。認証ドメインの SSO セッションが有効なら、追加のパスキー操作なしでアプリへ戻ります。Gateway は state、ブラウザーへの紐付け、認可コード、PKCE、ID トークンの署名・issuer・audience・有効期限・nonce を確認してアプリ用 Cookie を発行します。

| Cookie | 送信先 | 有効期間 |
| --- | --- | --- |
| `__Host-sso_session` | 認証ホストのみ | 12 時間 |
| `__Host-app_session` | 発行されたアプリのホストのみ | 最大 8 時間、親 SSO の期限以内 |
| `__Host-sso_flow_*` | SSO を開始したアプリのホストのみ | 5 分 |
| `__Host-sso_login`・`__Host-sso_registration` | 認証ホストのみ | 5 分 |

すべて `Secure; HttpOnly; SameSite=Lax; Path=/` で、`Domain` は付与しません。SSO・アプリ用セッションと認可コードはハッシュで保存します。PKCE verifier、認証処理の一時情報、パスキーの永続レコードは、`SESSION_SECRET` から HKDF で導出した鍵による AES-GCM で暗号化します。

## 設定と起動

1. [設定例](../examples/sso/config.yaml)を配置し、issuer、RP ID、アプリの Origin とコールバック URL、許可ロールを変更します。
2. DNS と TLS 証明書を準備します。
3. RSA 秘密鍵と環境変数を準備します。
4. Nginx 設定を配置し、アプリの upstream を変更します。
5. auth-proxy と Nginx を起動します。

```sh
umask 077
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out sso-signing.pem
export SESSION_SECRET="$(openssl rand -hex 32)"
export XSRF_SECRET_KEY="$(openssl rand -base64 32)"
export SSO_CONFIG=/absolute/path/to/sso.yaml
export SSO_SIGNING_KEY_FILE=/absolute/path/to/sso-signing.pem
export LISTEN_HOST=127.0.0.1
export LISTEN_PORT=8080
export COOKIE_SECURE=true
export TRUSTED_PROXY_CIDRS=127.0.0.1/32
export ALLOWED_HOSTS=auth.example.com,127.0.0.1:8080
go run ./cmd/server
```

SSO 専用で動かす場合、`TARGET_URL` は省略できます。従来の直接プロキシも併用する場合は設定してください。既存のユーザー管理・管理者 API・パスワード認証は引き続き使用できます。SSO 用のログイン画面は `/sso/login`、アカウント画面は `/sso/account` です。既存の `/login` によるセッションと SSO セッションは別々です。

`SESSION_SECRET` と RSA 秘密鍵は再起動後も維持し、複数レプリカで共有してください。前者を変更すると、暗号化済みパスキーを読み出せなくなります。DB と合わせて安全にバックアップします。RSA 鍵は RS256 用で、2048 ビット以上の PKCS#1 または PKCS#8 PEM に対応します。自動的な鍵ローテーションは行いません。RSA 鍵を切り替えると既発行 ID トークンの検証ができなくなるため、公開鍵キャッシュと最大 5 分のトークン有効期間を考慮して切り替えます。

`trusted_gateway_cidrs` は内部 API を呼べる Nginx の接続元を指定します。`TRUSTED_PROXY_CIDRS` はログとレート制限で転送元ヘッダーを信頼する接続元です。どちらも実際の Nginx のアドレスに限定してください。内部 API の判定では `X-Forwarded-For` を使用しません。

Nginx の設定ファイルは [examples/sso/nginx](../examples/sso/nginx/) にあります。`nginx.conf` は `auth_request` モジュールを含む Nginx を想定しています。内部 API とアプリの HTTP ポートはインターネットに公開しないでください。

Linux で Docker を使う場合は、[Compose 設定例](../examples/sso/compose.yaml)を利用できます。既存アプリはループバックの 8081・8082 番ポートで起動します。コンテナはホストネットワークを使用します。

```sh
export SSO_TLS_DIR=/absolute/path/to/tls
# SSO_TLS_DIR 内に fullchain.pem と privkey.pem を配置する。
# auth-proxy コンテナの UID 10001 が署名鍵を読めるようにする。
sudo chown 10001:10001 "$SSO_SIGNING_KEY_FILE"
sudo chmod 0400 "$SSO_SIGNING_KEY_FILE"
docker compose -f examples/sso/compose.yaml up -d --build
```

Compose 設定例では公開登録を無効にしています。既存のユーザー DB を利用するか、管理者 CLI でアカウントを作成してパスワードで `/sso/login` にログインし、アカウント画面からパスキーを追加してください。公開登録を許可する環境では `REGISTER=true` を指定すると、ログイン画面からパスキー専用アカウントを作成できます。パスワードを持たないユーザーに、空のパスワードでログインすることはできません。

アプリ追加時は YAML の `applications` と Nginx の仮想ホストを追加して auth-proxy を再起動します。Origin は HTTPS、ホスト名は小文字、アプリ ID は小文字英数字とハイフンです。issuer と各アプリはそれぞれ別のホストに配置します。Cookie はポートで分離されないため、同じホストの別ポートをアプリとして登録することも拒否します。HTTPS の既定ポート 443 は Origin に明記しません。コールバック URL はそのアプリの Origin に `/_auth/callback` を付けた値と完全一致させます。ワイルドカード、追加のクエリー、任意の戻り先 URL は受け付けません。戻り先にはそのアプリ内のパスとクエリーのみを保存します。

## Nginx とアプリの境界

認証チェックは `X-Auth-App-ID` と `X-Original-Host` の組み合わせを登録情報と照合します。Nginx は内部ヘッダーを上書きし、元のメソッド、Origin、Fetch Metadata と WebSocket Upgrade を転送します。

未認証時は名前付き location の `@sso_start` を使います。通常の `error_page` による URI への内部転送では POST が GET に変わるため、元のメソッドを失うおそれがあります。設定例は元のメソッドを保持し、認証サービスへの呼び出しだけを `proxy_method GET` に変更します。POST を保存・再送する機能はありません。API、fetch、HEAD、POST、WebSocket をログインへリダイレクトしません。`API_PATH` 配下（既定は `/api/`）は HTML ナビゲーションでも 401 を返します。それ以外の API は JSON の Accept または Fetch Metadata により画面遷移と区別します。

変更系リクエストと WebSocket 接続には、アプリの Origin と完全一致する Origin ヘッダーが必要です。クロスオリジンの fetch、同一サイト内の別ホストからの fetch も拒否します。アプリ側の CSRF 対策も維持してください。アプリが GET で状態を変更する設計は、この境界で保護できません。既に確立した WebSocket やストリームは、ログアウト時に切断されません。新しい接続・リクエストで認証状態を再確認します。

アプリが信頼する ID 情報は `X-Auth-Request-User`、`X-Auth-Request-User-ID`、`X-Auth-Request-Role` に限定します。設定例ではこれらを上書きし、既知の代替 ID ヘッダーと Authorization を除去します。アプリ独自の別の ID ヘッダーを信頼する場合は、それも Nginx で除去または上書きしてください。

認証チェックの応答に含まれる `X-Auth-Request-Cookie` は、サービス所有 Cookie を取り除いた Cookie ヘッダーです。Nginx はこの値だけをアプリに送ります。アプリ独自の Cookie は維持されます。アプリが auth-proxy 所有の Cookie 名を使用しないようにしてください。

認証 DB への接続に失敗した場合、内部 API は 503 を返し、Nginx はアクセスを許可しません。認証チェックはログイン用レート制限の対象外なので、ログイン失敗が既存のアプリセッションを遮断することはありません。公開認証操作には既存の `AUTH_RATE_LIMIT_*` 設定を適用します。

パスキー登録の開始には、既存の `USER_CREATION_RATE_LIMIT_*` による制限も適用します。既に開始した登録の完了は、この追加枠を消費しません。

アクセスログにはクエリー文字列を出力しません。Nginx のコールバック location では、認可コードを含み得る標準エラーログも無効にしています。DEBUG・INFO は stdout、WARN・ERROR は stderr に出力し、起動不能時は終了コード 1 を返します。

## セッション失効と認証情報

| 操作 | 失効範囲 |
| --- | --- |
| `POST /_auth/logout` | 現在のアプリセッションのみ |
| `POST /sso/logout` | 現在の SSO とそれに関連する全アプリセッション |
| パスワード・パスキーで再ログイン | 置換される古い SSO とそのアプリセッション |
| パスワード変更・パスキー追加・削除 | そのユーザーの全端末の既存セッション・更新トークン・従来のアクセス JWT |
| 管理者によるアカウント無効化・ロール変更 | 次の認証チェックから反映 |

パスキーの追加時は、署名検証済みの新しいパスキーを保存してから新しい SSO を発行します。削除時はログアウトします。追加・削除には 5 分以内の認証が必要です。パスワードのないユーザーの最後のパスキーは削除できません。

`sso_sessions` と `app_sessions` は複数端末・複数アプリの同時利用を許可します。既存の `auth_tokens` と `refresh_tokens` のユーザー単位の置換動作は、従来機能の互換性のため維持しています。SSO ではそのテーブルを流用しません。

初回起動時、既存の `users.password_hash` は `password_credentials` に移され、元の列は空の互換用列になります。パスキー専用ユーザーにはパスワード認証情報の行がありません。`credentials_version` は認証情報の変更で増加し、JWT と SSO の失効判定に使用します。旧形式のアクセス JWT は再発行が必要です。DB の変更前にバックアップしてください。旧バイナリーへ戻す場合はバックアップから復元するか、移動したパスワードハッシュを戻す必要があります。

移行時は旧バージョンの全インスタンスを停止してから新バージョンを起動してください。旧バージョンと新バージョンを同じ DB に対して混在稼働させないでください。Compose 設定例の `sso_data` は新しいボリュームなので、既存の SQLite DB を使う場合はバックアップから移すか、その既存ボリュームを明示してマウントします。

スキーマは SQLite、PostgreSQL、MySQL に対応します。一時的な WebAuthn 処理、state、認可コードも DB に保存するため、HTTP セッションのスティッキー設定は不要です。期限切れレコードは定期削除されますが、有効期限は各リクエストで判定します。

## OIDC エンドポイント

| メソッドとパス | 用途 |
| --- | --- |
| `GET /.well-known/openid-configuration` | Discovery |
| `GET /oauth2/jwks` | RS256 公開鍵 |
| `GET /oauth2/authorize` | Code Flow と S256 PKCE |
| `POST /oauth2/token` | 一度限りの認可コード交換 |
| `GET /oauth2/userinfo` | アクセストークンによるユーザー情報取得 |
| `POST /webauthn/register/begin`・`finish` | パスキー登録 |
| `POST /webauthn/login/begin`・`finish` | Discoverable Credential による認証 |
| `GET /webauthn/credentials` | 自分のパスキー一覧 |
| `DELETE /webauthn/credentials/{id}` | 自分のパスキー削除 |
| `GET /internal/authz` | Nginx 専用の認証・認可判定 |
| `GET /gateway/start`・`callback` | Nginx 専用の RP 処理 |
| `POST /gateway/logout` | Nginx 専用のアプリログアウト |

同じプロセス内の Gateway は HTTP ループバックをせず、公開トークンエンドポイントと共通の認可コード交換・検証処理を呼び出します。外部 OIDC クライアントも、登録済みの正確なコールバック URL を使ってコード交換できます。`client_secret_env` を指定したクライアントには `client_secret_basic` が必須です。未指定の場合は公開クライアントとして扱い、PKCE はどちらでも必須です。秘密情報は YAML に書かず環境変数で渡します。

サポートするのは `response_type=code`、query レスポンス、`openid`・`profile` スコープです。認可コードは 1 分、一時トランザクションは 5 分、ID・アクセストークンは 5 分で期限切れになります。Implicit Flow、Refresh Grant、動的クライアント登録、`prompt`・`max_age`・署名付き認可リクエストは実装しておらず、対応しない認可モードは拒否します。汎用 OP の全機能や OIDC 認定を提供するものではありません。

## 検証

```sh
go test ./...
go test -race -timeout=120s ./...
go vet ./...

# Docker、Node.js、OpenSSL、Python 3、curl を使用する。
cd tests/sso-e2e
npm ci
npx playwright install --with-deps chromium
cd ../..
bash tests/sso-e2e/run.sh
bash tests/sso-sql.sh postgres
bash tests/sso-sql.sh mysql
```

既存の Chromium を使う場合は `CHROMIUM_PATH=/absolute/path/to/chromium` を指定できます。統合テストは一時 DB と自己署名証明書を使い、ループバックの 18080・18081・18082・18443 番ポートで起動します。テスト終了後にプロセス、コンテナ、一時ファイルを削除します。

ブラウザーテストは Chromium の仮想認証器で実際の WebAuthn 署名を生成し、Nginx 設定例を経由して、異なる親ドメイン間の SSO、別端末、権限分離、Cookie 分離、ID ヘッダーの上書き、POST、WebSocket、ログアウト、署名・Origin の不正、パスキーの追加・削除を検証します。Go テストではコード再利用の競合、PKCE・nonce・audience の不一致、期限切れ、ブラウザーへの state 紐付け、DB 停止時の拒否も検証します。
