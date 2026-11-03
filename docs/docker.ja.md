# Docker Compose で起動する

同じ Docker イメージで SQLite（標準）、PostgreSQL、MySQL、外部 PostgreSQL/MySQL に対応します。

## 初期設定

```sh
git clone https://github.com/haturatu/auth-proxy.git
cd auth-proxy
cp .env.example .env
openssl rand -hex 32      # SESSION_SECRET 用
openssl rand -base64 32   # XSRF_SECRET_KEY 用
```

生成した値を `.env` に設定し、`TARGET_URL` を保護対象アプリの URL に変更します。`http://host.docker.internal:8081` は Docker ホスト上のアプリに接続する例です。別の Compose プロジェクトなら共通ネットワークに接続し、サービス名を使ってください。

標準では `127.0.0.1:8080` に公開します。Nginx などで HTTPS を終端し、`COOKIE_SECURE=true` を維持してください（終端後のアプリへの通信が HTTP でも同じ）。`false` は localhost の HTTP テスト専用です。Docker の標準 UI は JS モードです。PHP-FPM を使用する場合はソケットとテンプレートの共有設定が別途必要です。

## DB の選択

| DB | `COMPOSE_FILE` | 必要な追加設定 |
| --- | --- | --- |
| SQLite（標準） | `compose.yaml` | なし |
| PostgreSQL | `compose.yaml:compose.postgres.yaml` | `DB_PASSWORD` |
| MySQL | `compose.yaml:compose.mysql.yaml` | `DB_PASSWORD`、`MYSQL_ROOT_PASSWORD` |
| 外部 DB | `compose.yaml` | `DATABASE_URL` |

`DB_USER` と `DB_NAME` は省略すると `auth` です。付属 DB のパスワードは `openssl rand -hex 24` など URI-safe なランダム値を使ってください。

`.env` に `COMPOSE_FILE` を設定したら共通コマンドで起動できます。

```sh
docker compose config -q
docker compose up -d --build
docker compose logs -f auth-proxy
```

ファイルを明示的に選ぶこともできます。

```sh
docker compose -f compose.yaml -f compose.postgres.yaml up -d --build
docker compose -f compose.yaml -f compose.mysql.yaml up -d --build
```

外部 DB の場合は `COMPOSE_FILE=compose.yaml` のみを使用し、`DATABASE_URL` に TLS を有効にした接続文字列を設定します。URL の予約文字を含むパスワードは URL エンコードが必要です。

```dotenv
DATABASE_URL=postgres://user:password@db.example.com:5432/auth?sslmode=verify-full
# DATABASE_URL=mysql://user:password@db.example.com:3306/auth?parseTime=true&tls=true
```

## 管理と注意点

```sh
docker compose exec auth-proxy /app/admin-cli --username admin --password-stdin
# パスワードを入力して Enter
docker compose down
```

`GET /healthz` は DB 接続を確認します。外部公開が不要なら前段で遮断してください。コンテナは非 root ユーザーで実行します。

`docker compose down -v` は保存データも消します。DB の種類を変更してもユーザー・セッションは自動移行されません。事前にバックアップして移行してください。現状の `CREATE TABLE IF NOT EXISTS` は本格的なスキーママイグレーションではありません。
