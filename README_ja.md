# TinySocks

[English](README.md) | [中文](README_zh.md) | [日本語](README_ja.md)

TinySocks は、同じリスナーで SOCKS5 と HTTP プロキシリクエストを処理する単一ポートプロキシです。IPv4 / IPv6、ユーザー名/パスワード認証、IP/CIDR 許可リスト、SOCKS5 UDP ASSOCIATE をサポートします。

実行時の統計は、組み込みの `/stats` ページで確認できます。

## TL;DR

```bash
docker run --rm \
  -p 1080:1080 \
  -e TINYSOCKS_USERNAME=admin \
  -e TINYSOCKS_PASSWORD=change-me \
  -e TINYSOCKS_BYPASS_IP=127.0.0.0/8,::1/128 \
  ghcr.io/wzhone/tinysocks:latest
```

## 特長

- 単一ポートで SOCKS5 と HTTP プロキシをサポート
- HTTP 転送、HTTP CONNECT、SOCKS5 CONNECT
- SOCKS5 UDP ASSOCIATE
- IPv4 / IPv6
- ユーザー名/パスワード認証と IP/CIDR 許可リスト
- 組み込みの `/stats` ページ
- Docker、Linux systemd サービス、Windows サービスをサポート

## インストール

[GitHub Releases](https://github.com/wzhone/tinysocks/releases) から対象プラットフォームのバイナリをダウンロードするか、Docker イメージを使用します。

```bash
docker pull ghcr.io/wzhone/tinysocks:latest
```

ソースからビルド:

```bash
cargo build --release --locked
```

ソースからビルドするには Rust 1.96 以降が必要です。

## 使い方

### Docker

コンテナはデフォルトで `tinysocks run` を実行し、`0.0.0.0:1080` で待ち受けます。実行時オプションは環境変数で設定できます。また、イメージ名の後に CLI 引数を追加して上書きできます。

SOCKS5 UDP ASSOCIATE は、セッションごとに一時 UDP リレーポートを使用します。Docker で UDP ASSOCIATE を使用する場合は host network を使用してください。

### バイナリ

```bash
tinysocks 127.0.0.1:1080 \
  --username admin \
  --password change-me \
  run
```

クライアントは、同じアドレスとポートに SOCKS5 または HTTP プロキシプロトコルで接続できます。

## 統計

ブラウザで `http://<proxy-host>:<proxy-port>/stats` を開くと、接続数とトラフィックカウンターを確認できます。認証が有効で、クライアント IP が許可リストに含まれていない場合は、プロキシと同じユーザー名とパスワードを使用してください。

## 設定

| オプション | 環境変数 | デフォルト | 説明 |
|---|---|---|---|
| `[BIND ADDR]` | `TINYSOCKS_BIND` | `127.0.0.1:1080` | 待ち受けアドレスとポート |
| `-m, --max-connections` | `TINYSOCKS_MAX_CONNECTIONS` | `1024` | グローバル同時接続数の上限 |
| `-u, --username` | `TINYSOCKS_USERNAME` | - | プロキシユーザー名 |
| `-p, --password` | `TINYSOCKS_PASSWORD` | - | プロキシパスワード |
| `--bypass-ip` | `TINYSOCKS_BYPASS_IP` | - | 認証をスキップする IP または CIDR のカンマ区切りリスト |

CLI 引数は環境変数より優先されます。ユーザー名/パスワード認証、または少なくとも 1 つの `--bypass-ip` 許可リスト項目を設定してください。

## サービスインストール

`install` と `uninstall` はホストサービスの管理に使用します。

### Linux systemd

```bash
sudo tinysocks 0.0.0.0:1080 \
  --username admin \
  --password change-me \
  install
```

Linux では、`install` はサービス認証情報を `/etc/tinysocks/tinysocks.env` に `0600` 権限で保存し、systemd unit からその環境ファイルを参照します。

アンインストール:

```bash
sudo tinysocks uninstall
```

### Windows

管理者ターミナルで実行します。

```powershell
.\tinysocks.exe 0.0.0.0:1080 `
  --username admin `
  --password change-me `
  install
```

アンインストール:

```powershell
.\tinysocks.exe uninstall
```

## ライセンス

[MIT](LICENSE)
