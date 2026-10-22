<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**  *generated with [DocToc](https://github.com/thlorenz/doctoc)*

- [Auth Proxy (認証プロキシ)](#auth-proxy-%E8%AA%8D%E8%A8%BC%E3%83%97%E3%83%AD%E3%82%AD%E3%82%B7)
  - [なぜ作ったか](#%E3%81%AA%E3%81%9C%E4%BD%9C%E3%81%A3%E3%81%9F%E3%81%8B)
  - [おためし](#%E3%81%8A%E3%81%9F%E3%82%81%E3%81%97)
  - [主な機能](#%E4%B8%BB%E3%81%AA%E6%A9%9F%E8%83%BD)
  - [セキュリティと認証の詳細](#%E3%82%BB%E3%82%AD%E3%83%A5%E3%83%AA%E3%83%86%E3%82%A3%E3%81%A8%E8%AA%8D%E8%A8%BC%E3%81%AE%E8%A9%B3%E7%B4%B0)
    - [XSRF保護](#xsrf%E4%BF%9D%E8%AD%B7)
    - [パスワードの暗号化](#%E3%83%91%E3%82%B9%E3%83%AF%E3%83%BC%E3%83%89%E3%81%AE%E6%9A%97%E5%8F%B7%E5%8C%96)
    - [認証フロー](#%E8%AA%8D%E8%A8%BC%E3%83%95%E3%83%AD%E3%83%BC)
      - [1. Web UI（セッションベース）](#1-web-ui%E3%82%BB%E3%83%83%E3%82%B7%E3%83%A7%E3%83%B3%E3%83%99%E3%83%BC%E3%82%B9)
      - [2. API（JWTベース）](#2-apijwt%E3%83%99%E3%83%BC%E3%82%B9)
    - [セッション管理](#%E3%82%BB%E3%83%83%E3%82%B7%E3%83%A7%E3%83%B3%E7%AE%A1%E7%90%86)
      - [Web UIセッション](#web-ui%E3%82%BB%E3%83%83%E3%82%B7%E3%83%A7%E3%83%B3)
      - [APIセッション（JWTによるステートレス管理）](#api%E3%82%BB%E3%83%83%E3%82%B7%E3%83%A7%E3%83%B3jwt%E3%81%AB%E3%82%88%E3%82%8B%E3%82%B9%E3%83%86%E3%83%BC%E3%83%88%E3%83%AC%E3%82%B9%E7%AE%A1%E7%90%86)
    - [トランスポート層セキュリティ（HTTPS）](#%E3%83%88%E3%83%A9%E3%83%B3%E3%82%B9%E3%83%9D%E3%83%BC%E3%83%88%E5%B1%A4%E3%82%BB%E3%82%AD%E3%83%A5%E3%83%AA%E3%83%86%E3%82%A3https)
  - [はじめに](#%E3%81%AF%E3%81%98%E3%82%81%E3%81%AB)
    - [前提条件](#%E5%89%8D%E6%8F%90%E6%9D%A1%E4%BB%B6)
    - [インストール](#%E3%82%A4%E3%83%B3%E3%82%B9%E3%83%88%E3%83%BC%E3%83%AB)
    - [設定](#%E8%A8%AD%E5%AE%9A)
- [`.env` ファイルの例:](#env-%E3%83%95%E3%82%A1%E3%82%A4%E3%83%AB%E3%81%AE%E4%BE%8B)
    - [フロントエンドの選択](#%E3%83%95%E3%83%AD%E3%83%B3%E3%83%88%E3%82%A8%E3%83%B3%E3%83%89%E3%81%AE%E9%81%B8%E6%8A%9E)
      - [PHPフロントエンドのセットアップ](#php%E3%83%95%E3%83%AD%E3%83%B3%E3%83%88%E3%82%A8%E3%83%B3%E3%83%89%E3%81%AE%E3%82%BB%E3%83%83%E3%83%88%E3%82%A2%E3%83%83%E3%83%97)
    - [データベース設定例](#%E3%83%87%E3%83%BC%E3%82%BF%E3%83%99%E3%83%BC%E3%82%B9%E8%A8%AD%E5%AE%9A%E4%BE%8B)
      - [PostgreSQL](#postgresql)
      - [MySQL / MariaDB](#mysql--mariadb)
  - [使い方](#%E4%BD%BF%E3%81%84%E6%96%B9)
  - [APIトークン（ベアラートークン）の発行](#api%E3%83%88%E3%83%BC%E3%82%AF%E3%83%B3%E3%83%99%E3%82%A2%E3%83%A9%E3%83%BC%E3%83%88%E3%83%BC%E3%82%AF%E3%83%B3%E3%81%AE%E7%99%BA%E8%A1%8C)
    - [保護されたバックエンドAPIへのプロキシ](#%E4%BF%9D%E8%AD%B7%E3%81%95%E3%82%8C%E3%81%9F%E3%83%90%E3%83%83%E3%82%AF%E3%82%A8%E3%83%B3%E3%83%89api%E3%81%B8%E3%81%AE%E3%83%97%E3%83%AD%E3%82%AD%E3%82%B7)
  - [管理APIエンドポイント](#%E7%AE%A1%E7%90%86api%E3%82%A8%E3%83%B3%E3%83%89%E3%83%9D%E3%82%A4%E3%83%B3%E3%83%88)
    - [ユーザー一覧の取得](#%E3%83%A6%E3%83%BC%E3%82%B6%E3%83%BC%E4%B8%80%E8%A6%A7%E3%81%AE%E5%8F%96%E5%BE%97)
    - [ユーザーの作成](#%E3%83%A6%E3%83%BC%E3%82%B6%E3%83%BC%E3%81%AE%E4%BD%9C%E6%88%90)
    - [ユーザーロールの更新](#%E3%83%A6%E3%83%BC%E3%82%B6%E3%83%BC%E3%83%AD%E3%83%BC%E3%83%AB%E3%81%AE%E6%9B%B4%E6%96%B0)
    - [ユーザーステータスの更新](#%E3%83%A6%E3%83%BC%E3%82%B6%E3%83%BC%E3%82%B9%E3%83%86%E3%83%BC%E3%82%BF%E3%82%B9%E3%81%AE%E6%9B%B4%E6%96%B0)
    - [ユーザーの削除](#%E3%83%A6%E3%83%BC%E3%82%B6%E3%83%BC%E3%81%AE%E5%89%8A%E9%99%A4)
  - [設定詳細](#%E8%A8%AD%E5%AE%9A%E8%A9%B3%E7%B4%B0)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

# Auth Proxy (認証プロキシ)

これはGoで書かれたシンプルな認証リバースプロキシです。あらゆるバックエンドウェブサービスの前に配置できる、柔軟な認証レイヤーを提供します。

ユーザー登録、ログイン、セッション管理を処理し、認証されたリクエストを設定済みのバックエンドにプロキシします。また、ユーザー管理のための管理ダッシュボードも含まれています。

## なぜ作ったか
私の作成しているものがありますが  
[GitHub - haturatu/puremania: No security, very fast, web UI self-hosted online storage](https://github.com/haturatu/puremania)  
がありますが、これに複雑になりがちな認証機能を持たせなくなかったからです。  
また、一つのアプリケーションに認証を組み込むとセキュリティ上は良いですがID/Passwordなどをそれぞれに合わせて作成する必要がありとても面倒です。  
特にセルフホストが好きな人にとってはどうアクセス制御するか、です。  
ある主、このサーバーが認証基盤として機能して同じDBを参照することによってユーザ情報は共有できます。

## おためし
```bash
git clone https://github.com/haturatu/auth-proxy.git
cd auth-proxy
chmod +x run-demo.sh
bash run-demo.sh
```

## 主な機能

- **認証**: ログイン、ログアウト、登録ページを提供します。
- **リバースプロキシ**: 認証されたユーザーをバックエンドサービスにプロキシします。
- **管理ダッシュボード**: ユーザーを管理（ロールの更新、有効化/無効化、削除）するためのシンプルなUI。
- **柔軟なデータベースサポート**: PostgreSQL, MySQL, SQLiteに対応。
- **プラグイン可能なフロントエンド**: 複数のフロントエンドモード（JS駆動またはPHP）をサポート。
- **セキュリティ強化**:
    - **ブルートフォース攻撃からの保護**: 設定可能な回数ログインに失敗したユーザーアカウントをロックします。この保護は、Web UIからのログインと `/api/auth/token` エンドポイントの両方に適用されます。
    - **ユーザー作成レート制限**: 同一IPアドレスから短時間に多くのユーザーが作成されるのを防ぎます。
    - **設定可能なパスワードポリシー**: パスワードの強度要件を強制します。詳細は下記を参照。
    - **セキュアなセッションクッキー**: セッション管理に `HttpOnly` のセキュアなクッキーを使用します。
- **高い設定可能性**: データベース接続、セキュリティポリシー、内部URLパスなど、ほぼ全ての側面を `.env` ファイルで設定可能です。
- **構造化ロギング**: `slog` を使用した詳細なアプリケーションログとセキュリティログ。
- **管理者作成用CLI**: 初期管理者ユーザーを簡単に作成するためのコマンドラインツール。

## セキュリティと認証の詳細

### XSRF保護

このプロキシには、悪意のある攻撃を防ぐためのXSRF（クロスサイトリクエストフォージェリ）保護が含まれています。これは`golang.org/x/net/xsrftoken`ライブラリを使用して実装されています。

ユーザーがフォームのあるページにアクセスすると、一意のXSRFトークンが生成され、フォームに埋め込まれます。フォームが送信されると、サーバーはトークンがユーザーのセッションに保存されているものと一致するかどうかを確認します。一致しない場合、リクエストは拒否されます。

この保護はデフォルトで有効になっています。以下の環境変数を使用して設定できます。

- `XSRF_SECRET_KEY`: XSRFトークンの署名に使用される、長くてランダムな秘密鍵。

### パスワードの暗号化

ユーザーのパスワードは、平文（プレーンテキスト）では一切保存されません。パスワード専用に設計された強力で適応性のあるハッシュ関数である **bcrypt** アルゴリズムを使用して、安全にハッシュ化されます。ユーザーがログインする際、入力されたパスワードはハッシュ化され、保存されているハッシュ値と比較されます。これにより、万が一データベースが侵害された場合でも、元のパスワードが漏洩するのを防ぎます。

### 認証フロー

このプロキシは、異なるユースケースに対応するため、2つの主要な認証フローをサポートしています。

#### 1. Web UI（セッションベース）

このフローは、Webブラウザを介してアプリケーションを操作するユーザー向けに設計されています。

1.  ユーザーがログインページからユーザー名とパスワードを送信します。
2.  サーバーは、データベース内の情報と照合して認証情報を検証します。
3.  成功すると、暗号学的に安全なランダムトークンが生成され、ユーザーに関連付けられてデータベースに保存されます。
4.  このトークンは、`auth_token` という名前の安全な `HttpOnly` クッキーとしてユーザーのブラウザに送信され、セッションが確立されます。

#### 2. API（JWTベース）

このフローは、プログラムによるクライアントやサービス向けに設計されています。

1.  クライアントが、ユーザーのユーザー名とパスワードを含む`POST`リクエストを`/api/auth/token`エンドポイントに送信します。
2.  サーバーは認証情報を検証します。
3.  成功すると、2種類のトークンを生成して返します。
    *   ユーザー情報（ID、ロール）と有効期限を含む、短命の**JWTアクセストークン**。このトークンは改ざんを防ぐために署名されています。
    *   新しいアクセストークンを取得するために使用できる、長命の**リフレッシュトークン**。これはデータベースに保存されます。

### セッション管理

#### Web UIセッション

ブラウザからの後続のリクエストでは、`auth_token`クッキーが自動的にサーバーに送信されます。ミドルウェアがこのトークンをデータベースで検索して検証します。トークンが有効で期限切れでなければ、リクエストは認証され、処理が続行されます。ユーザーがログアウトすると、セッショントークンはデータベースから削除され、セッションが無効になります。

#### APIセッション（JWTによるステートレス管理）

APIリクエストの場合、クライアントは`Authorization: Bearer <token>`ヘッダーにJWTアクセストークンを含める必要があります。サーバー上のミドルウェアが、トークンの署名と有効期限を検証します。このプロセスはステートレスであり、リクエストごとにデータベースを検索する必要がないため、非常に効率的です。アクセストークンが期限切れになった場合、クライアントはリフレッシュトークンを使用して、再認証することなく新しいアクセストークンを要求できます。

**認証の優先順位に関する注意:** APIエンドポイントが保護されている場合（`PROTECT_API=true`）、ミドルウェアはまず`Authorization: Bearer`ヘッダーを探します。このヘッダーが存在しない場合、フォールバックとして`auth_token`セッションクッキーの検証を試みます。これにより、Web UIにログインしているユーザーは、ブラウザセッションを使用してAPIに対しても認証できます。しかし、これはAPIエンドポイントが有効なJWTまたは有効なセッションクッキーのいずれかによってアクセス可能であることを意味します。

### トランスポート層セキュリティ（HTTPS）

本番環境では、このプロキシをTLS終端リバースプロキシ（Nginx, Caddy, またはクラウドライスバランサーなど）の背後で実行することが**極めて重要**です。

このアプリケーション自体はHTTPS終端を処理しません。デフォルトでは、HTTPで通信します。もしセキュアなプロキシを前段に置かずにデプロイした場合、ログイン時に送信されるユーザーのパスワードのような機密データが、中間者（MITM）攻撃によって傍受される可能性があります。  
しかし、MITMは現実的に非常に難しく、通常は同じネットワーク上にいる必要があります。  
簡単に防止できるとすればバックエンドアプリケーションとこの認証プロキシをNginxのようなHTTPサーバーの背後に置くことです。実質的に通信はTLS通信でラップされることになります。(完全な方法ではありませんが)  

## はじめに

### 前提条件

- Go 1.27.3 以降
- (任意) PHPフロントエンドを使用する場合は、実行中のPHP-FPMサービス。
- (任意) PostgreSQL または MySQL データベースサーバー。

### インストール

1.  **リポジトリをクローン:**
    ```sh
    git clone https://github.com/haturatu/auth-proxy
    cd auth-proxy
    ```

2.  **依存関係をインストール:**
    ```sh
    go mod tidy
    ```

3.  **バイナリをビルド:**
    ```sh
    go build -o auth-proxy-server ./cmd/server && go build -o admin-cli ./cmd/admin-cli
    ```

### 設定

設定はプロジェクトのルートにある `.env` ファイルで管理されます。`.env` という名前のファイルを作成し、必要な変数を追加してください。

# `.env` ファイルの例:

```dotenv
# --- サーバー設定 ---
# プロキシサーバーがリッスンするポート
LISTEN_PORT=8080

# --- 必須 ---
# 保護したいバックエンドサービスのURL
TARGET_URL=http://localhost:8081

# セッションクッキーとJWTを保護するための長くてランダムな文字列
# 本番環境では、openssl rand -base64 45 を使って新しいキーを生成してください
SESSION_SECRET=my-super-secret-key

# (必須) XSRF保護のための32バイトのランダムなキー。
# 生成コマンド: openssl rand -base64 32
XSRF_SECRET_KEY=

# --- データベース ---
# 以下のいずれかのオプションを使用してください:

# オプション1: PostgreSQL または MySQL (推奨)
# 例: postgres://user:password@host:port/dbname?sslmode=disable
# 例: mysql://user:password@tcp(host:port)/dbname?charset=utf8mb4&parseTime=true
DATABASE_URL=mysql://test:test@127.0.0.1:3306/auth

# オプション2: SQLite (DATABASE_URLが設定されていない場合のデフォルト)
# DATABASE_PATH=./auth.db

# --- フロントエンド & プロキシ ---
# フロントエンドモード: "js" (デフォルト) または "php"
FRONTEND_TYPE=js
# trueの場合、フロントエンドパスをセッション認証で保護します
PROTECT_FRONTEND=false
# trueの場合、APIパスをベアラートークン認証で保護します
PROTECT_API=false
# 保護対象のフロントエンドのベースパス
FRONT_PATH=/
# 保護対象のAPIのベースパス
API_PATH=/api/

# --- セキュリティポリシー ---

# ブルートフォース攻撃からの保護設定
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_DURATION_MINUTES=10

# ユーザー作成レート制限設定
USER_CREATION_RATE_LIMIT_MAX_REQUESTS=5
USER_CREATION_RATE_LIMIT_WINDOW_SECONDS=3600

# パスワードポリシー (none, standard, enhanced, strict)
PASSWORD_POLICY=standard

# --- トークン有効期間 ---
# Webセッションクッキーの有効期間
TOKEN_DURATION_HOURS=24
# API JWTアクセストークンの有効期間
ACCESS_TOKEN_DURATION_MINUTES=15
# API JWTリフレッシュトークンの有効期間
REFRESH_TOKEN_DURATION_DAYS=7

# --- 任意: パスのオーバーライド ---
# バックエンドアプリケーションとのURL競合を避けるためにコメントを解除して変更してください。
# AUTH_PATH_LOGIN=/login
# AUTH_PATH_REGISTER=/register
# AUTH_PATH_LOGOUT=/logout
# AUTH_PATH_ACCOUNT=/account
# AUTH_PATH_ACCOUNT_PASSWORD=/account/password
# AUTH_PATH_ADMIN=/admin
# AUTH_PATH_ADMIN_USERS_API=/api/admin/users
# AUTH_ASSETS_PATH=/assets
```

### フロントエンドの選択

`FRONTEND_TYPE` 環境変数を使用して、2つのフロントエンドモードから選択できます。

-   **`js` (または空)**: これがデフォルトモードです。サーバーは基本的なHTMLテンプレートを描画し、すべての認証ロジック（フォームの描画、ユーザー入力の処理など）は、GoバックエンドのAPIエンドポイントと通信するフロントエンドのJavaScriptコードによって管理されることが想定されています。
-   **`php`**: PHPベースのビューを使用するには、実行中のPHP-FPMサービスが必要です。このモードは、認証ページのGETリクエストをPHP-FPMサービスにプロキシし、POSTリクエスト（ログイン送信など）はGoバックエンドで処理します。

#### PHPフロントエンドのセットアップ

`FRONTEND_TYPE=php` を選択した場合は、以下の手順に従ってください。

1.  **`.env`でフロントエンドタイプを設定**:
    ```dotenv
    FRONTEND_TYPE=php
    ```

2.  **`.env`でPHP-FPM接続を設定**:
    PHP-FPMソケットへのパスとドキュメントルートを提供する必要があります。
    -   `PHP_FPM_SOCKET`: PHP-FPMソケットファイルへのパス（例: `/run/php-fpm/php-fpm.sock`）。
    -   `PHP_DOC_ROOT`: PHPビューファイル（例: `login.php`）を含むディレクトリへの**絶対パス**。このパスは、*PHP-FPMプロセスからアクセス可能*である必要があります。

3.  **PHPファイルのコピーと権限設定**:
    PHP-FPMサービスを実行するユーザーは、PHPテンプレートファイルへの読み取りアクセス権が必要です。

    まず、PHP-FPMの実行ユーザーを特定します。これは、PHP-FPMプール設定ファイル（例: `/etc/php/8.3/fpm/pool.d/www.conf`）で確認するか、実行中のプロセスを調べることで確認できます。
    ```sh
    # PHP-FPMユーザーを見つけるためのコマンド例
    ps aux | grep php-fpm
    ```
    一般的なユーザーは `www-data`、`http`、`apache` です。

    次に、`templates/php` ディレクトリをPHP-FPMがアクセス可能な場所（例: `/var/www/html/auth-proxy`）にコピーし、正しい所有権を設定します。

    ```sh
    # セットアップ例（ユーザーが 'http' の場合）
    sudo cp -r templates/php /var/www/html/auth-proxy/php
    sudo chown -R http:http /var/www/html/auth-proxy
    ```

    最後に、`.env` ファイルを正しいパスで更新します。
    ```dotenv
    # --- PHP Frontend Settings ---
    FRONTEND_TYPE=php
    PHP_FPM_SOCKET=/run/php-fpm/php-fpm.sock
    PHP_DOC_ROOT=/var/www/html/auth-proxy/php
    ```

### データベース設定例

PostgreSQLまたはMySQLを使用している場合は、プロキシ用のデータベースとユーザーを作成する必要があります。

#### PostgreSQL

`psql` で以下のコマンドを実行します:

```sql
-- 専用データベースを作成
CREATE DATABASE auth_proxy;

-- 専用ユーザーを作成
CREATE USER auth_user WITH PASSWORD 'your_strong_password';

-- ユーザーにデータベースの全権限を付与
GRANT ALL PRIVILEGES ON DATABASE auth_proxy TO auth_user;
```

その場合、`.env` ファイルの `DATABASE_URL` は次のようになります:
`DATABASE_URL=postgres://auth_user:your_strong_password@localhost:5432/auth_proxy?sslmode=disable`

#### MySQL / MariaDB

MySQLクライアントで以下のコマンドを実行します:

```sql
-- 専用データベースを作成
CREATE DATABASE auth_proxy CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 専用ユーザーを作成
CREATE USER 'auth_user'@'localhost' IDENTIFIED BY 'your_strong_password';

-- ユーザーにデータベースの全権限を付与
GRANT ALL PRIVILEGES ON auth_proxy.* TO 'auth_user'@'localhost';

-- 変更を適用
FLUSH PRIVILEGES;
```

その場合、`.env` ファイルの `DATABASE_URL` は次のようになります:
`DATABASE_URL=mysql://auth_user:your_strong_password@tcp(127.0.0.1:3306)/auth_proxy?parseTime=true`

## 使い方

1.  **管理者ユーザーの作成**:

    サーバーを起動する前に、`admin-cli` ツールを使用して最初の管理者ユーザーを作成します。CLIはデータベース接続に `.env` ファイルを使用するため、正しく設定されていることを確認してください。

    `--username` と `--password` フラグは必須です。

    *成功時のコマンド:*
    ```sh
    ./admin-cli --username <your-admin-username> --password <your-strong-password>
    ```

    *フラグが不足している場合の例:*
    ```sh
    $ ./admin-cli
    time=2025-10-12T04:28:09.014+09:00 level=ERROR msg="Both --username and --password flags are required"
    ```

2.  **プロキシサーバーの実行**:

    ```sh
    ./auth-proxy-server
    ```

    サーバーはデフォルトでポート `:8080` で起動します。

3.  **アプリケーションへのアクセス**:

    -   ブラウザを開き、`http://localhost:8080` にアクセスします。
    -   ログインページにリダイレクトされます。
    -   作成した管理者認証情報でログインします。
    -   認証されると、`TARGET_URL` にシームレスにプロキシされます。
    -   管理ダッシュボードには `http://localhost:8080/admin` （または設定したパス）でアクセスできます。

## APIトークン（ベアラートークン）の発行

Webブラウザ向けのセッションベースの認証に加えて、プロキシはプログラムによるAPIアクセスのためにJWT（JSON Web Token）を発行できます。これらのトークンは、保護されたバックエンドAPIへのリクエストを認証するために、`Authorization` ヘッダーでベアラートークンとして使用できます。

アクセストークンとリフレッシュトークンを取得するには、`/api/auth/token` エンドポイントに、JSONボディにユーザーの認証情報を入れて `POST` リクエストを送信します。

**`curl` を使用した例:**

```sh
curl -X POST -H "Content-Type: application/json" -d '{
  "username": "your-username",
  "password": "your-password"
}' http://localhost:8080/api/auth/token
```

**成功時のレスポンス:**

認証情報が有効な場合、サーバーは `access_token` と `refresh_token` を含むJSONオブジェクトで応答します。

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxLCJyb2xlIjoiYWRtaW4iLCJleHAiOjE2Njc4OTg5ODl9.abcdef123456...",
  "refresh_token": "def456..."
}
```

`access_token` は短命のJWTであり、APIリクエストの `Authorization` ヘッダーで送信する必要があります:

```
Authorization: Bearer <access_token>
```

`refresh_token` は長命のトークンで、古いアクセストークンが期限切れになったときに新しいアクセストークンを取得するために使用できます。これを行うには、`/auth/refresh` エンドポイントに `POST` リクエストを送信します。

**注意:** トークンの有効期間は `.env` ファイルで設定できます。詳細は設定表を参照してください。

### 保護されたバックエンドAPIへのプロキシ

`PROTECT_API=true` の場合、`API_PATH`（例: `/api/`）以下のパスへのリクエストのうち、内部の管理エンドポイントではないものは、認証された上でバックエンドの `TARGET_URL` へとプロキシされます。

これにより、独自のバックエンドAPIを同じ認証メカニズムで保護することができます。認証は、有効な `Authorization: Bearer` トークン、またはフォールバックとして有効なWebセッションクッキーのいずれかを使用して検証されます。

**保護されたバックエンドAPIへの `curl` の例:**

```sh
ACCESS_TOKEN="your_access_token"
curl -H "Authorization: Bearer $ACCESS_TOKEN" http://localhost:8080/api/config
```

**バックエンドからの成功レスポンス例:**
```json
{"success":true,"data":{"StorageDir":"/home/haturatu","MountDirs":[],"MaxFileSize":10000,"SpecificDirs":["/home/haturatu/git"],"Aria2cEnabled":true}}
```

## 管理APIエンドポイント

管理タスクのために、プロキシはプログラムからアクセス可能なAPIエンドポイントをいくつか提供しています。これらのエンドポイントはすべて、`admin`ロールを持つユーザーの有効なベアラートークンが必要です。

これらのエンドポイントのベースパスは `/api/admin/users` であり、これは `AUTH_PATH_ADMIN_USERS_API` 環境変数でカスタマイズ可能です。

### ユーザー一覧の取得

- **エンドポイント**: `GET /api/admin/users`
- **説明**: システム内の全ユーザーのリストを取得します。
- **例**:
  ```sh
  ACCESS_TOKEN="your_admin_access_token"
  curl -H "Authorization: Bearer $ACCESS_TOKEN" http://localhost:8080/api/admin/users
  ```

### ユーザーの作成

- **エンドポイント**: `POST /api/admin/users`
- **説明**: 新しいユーザーを作成します。
- **ボディ**:
  ```json
  {
    "username": "newuser",
    "password": "a-strong-password",
    "role": "user"
  }
  ```
- **例**:
  ```sh
  ACCESS_TOKEN="your_admin_access_token"
  curl -X POST -H "Authorization: Bearer $ACCESS_TOKEN" \
       -H "Content-Type: application/json" \
       -d '{"username": "newuser", "password": "Password123", "role": "user"}' \
       http://localhost:8080/api/admin/users
  ```

### ユーザーロールの更新

- **エンドポイント**: `POST /api/admin/users/{id}/role`
- **説明**: IDで指定された特定のユーザーのロールを更新します。
- **ボディ**:
  ```json
  {
    "role": "admin"
  }
  ```
- **例**:
  ```sh
  USER_ID=2
  ACCESS_TOKEN="your_admin_access_token"
  curl -X POST -H "Authorization: Bearer $ACCESS_TOKEN" \
       -H "Content-Type: application/json" \
       -d '{"role": "admin"}' \
       http://localhost:8080/api/admin/users/$USER_ID/role
  ```

### ユーザーステータスの更新

- **エンドポイント**: `POST /api/admin/users/{id}/status`
- **説明**: IDで指定されたユーザーを有効化または無効化します。
- **ボディ**:
  ```json
  {
    "is_active": false
  }
  ```
- **例**:
  ```sh
  USER_ID=2
  ACCESS_TOKEN="your_admin_access_token"
  curl -X POST -H "Authorization: Bearer $ACCESS_TOKEN" \
       -H "Content-Type: application/json" \
       -d '{"is_active": false}' \
       http://localhost:8080/api/admin/users/$USER_ID/status
  ```

### ユーザーの削除

- **エンドポイント**: `DELETE /api/admin/users/{id}`
- **説明**: IDで指定されたユーザーを削除します。
- **例**:
  ```sh
  USER_ID=2
  ACCESS_TOKEN="your_admin_access_token"
  curl -X DELETE -H "Authorization: Bearer $ACCESS_TOKEN" \
       http://localhost:8080/api/admin/users/$USER_ID
  ```

## 設定詳細

| 環境変数 | 説明 | デフォルト値 |
| --- | --- | --- |
| `TARGET_URL` | **(必須)** プロキシ先のバックエンドサービスのURL。 | - |
| `SESSION_SECRET` | **(必須)** セッションクッキーの暗号化とJWTの署名に使用する、長くてランダムな秘密鍵。 | `default-secret-key-for-dev` |
| `DATABASE_URL` | PostgreSQLまたはMySQLの接続文字列。設定されている場合、`DATABASE_PATH`より優先されます。 | - |
| `DATABASE_PATH` | SQLiteデータベースのファイルパス。`DATABASE_URL`が設定されていない場合のみ使用されます。 | `./auth.db` |
| `LOG_LEVEL` | ログレベルを設定します。`DEBUG`, `INFO`, `WARN`, `ERROR`が指定できます。 | `INFO`                 |
| `LISTEN_PORT` | プロキシサーバーがリッスンするポート。 | `8080`                 |
| `FRONTEND_TYPE` | フロントエンドのレンダリングモードを切り替えます。`js`または`php`が指定できます。 | `js` |
| `PHP_FPM_SOCKET` | PHP-FPMソケットへのファイルパス。`FRONTEND_TYPE`が`php`の場合のみ使用されます。 | `/run/php-fpm/php-fpm.sock` |
| `PHP_DOC_ROOT` | PHPファイルディレクトリへの絶対パス。`FRONTEND_TYPE`が`php`の場合のみ使用されます。 | - |
| `MAX_LOGIN_ATTEMPTS` | アカウントがロックされるまでのログイン失敗回数。 | `5` |
| `LOCKOUT_DURATION_MINUTES` | アカウントがロックされている期間（分）。 | `10` |
| `USER_CREATION_RATE_LIMIT_MAX_REQUESTS` | 時間枠内に単一IPから許可されるユーザー登録の最大数。 | `5` |
| `USER_CREATION_RATE_LIMIT_WINDOW_SECONDS` | ユーザー作成レート制限の時間枠（秒）。 | `3600` (1時間) |
| `PASSWORD_POLICY` | パスワード強度要件を設定します (`none`, `standard`, `enhanced`, `strict`)。 | `standard` |
| `TOKEN_DURATION_HOURS` | Webセッションクッキーの有効期間（時間）。 | `24` |
| `ACCESS_TOKEN_DURATION_MINUTES` | APIクライアント用のJWTアクセストークンの有効期間（分）。 | `15` |
| `REFRESH_TOKEN_DURATION_DAYS` | APIクライアント用のJWTリフレッシュトークンの有効期間（日）。 | `7` |
| `PROTECT_FRONTEND` | `true`の場合、すべてのフロントエンドパスをセッション認証経由でプロキシします。 | `false` |
| `PROTECT_API` | `true`の場合、すべてのAPIパスをベアラートークン認証経由でプロキシします。 | `false` |
| `FRONT_PATH` | `PROTECT_FRONTEND`で保護されるフロントエンドのベースパス。 | `/` |
| `API_PATH` | `PROTECT_API`で保護されるAPIルートのベースパス。 | `/api/` |
| `REGISTER` | `false`に設定すると、新規ユーザー登録を無効にします。 | `true` |
| `AUTH_PATH_*` | ログイン、管理者ページなどの内部URLをカスタマイズするための変数セット。 | 様々、例: `/login`|
| `AUTH_ASSETS_PATH` | 内部静的アセット（CSS, JS）を提供するためのURLパス。 | `/assets` |
| `ENV` | ランタイム環境。セキュアなクッキーを有効にするには`production`に設定します。 | - |
| `XSRF_SECRET_KEY` | **(必須)** XSRF保護のための32バイトのランダムなキー。`openssl rand -base64 32` で生成します。 | - |
