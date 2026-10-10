# TinySocks

[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/wzhone/tinysocks/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/wzhone/tinysocks/actions/workflows/ci.yml)
[![GitHub Release](https://img.shields.io/github/v/release/wzhone/tinysocks)](https://github.com/wzhone/tinysocks/releases/latest)

[English](README.md) | [中文](README_zh.md) | [日本語](README_ja.md)

TinySocks は単一ポートの SOCKS5 / HTTP プロキシです。

## TL;DR

サンプルのパスワード `change-me` は自分のパスワードに置き換えてください。

```bash
docker run -d --name tinysocks --restart unless-stopped \
  -p 1080:1080 \
  -e TINYSOCKS_USERNAME=admin \
  -e TINYSOCKS_PASSWORD=change-me \
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

ビルド済みバイナリ：[GitHub Releases](https://github.com/wzhone/tinysocks/releases)（Linux / Windows x86_64）。

### Linux x86_64 / systemd

root 権限が必要です。

```bash
curl -fLO https://github.com/wzhone/tinysocks/releases/latest/download/tinysocks-linux-x86_64.tar.gz &&
tar -xzf tinysocks-linux-x86_64.tar.gz &&
cd tinysocks-linux-x86_64 &&
sudo ./tinysocks 0.0.0.0:1080 --username admin --password 'change-me' install
```

### Windows x86_64

[tinysocks-windows-x86_64.zip](https://github.com/wzhone/tinysocks/releases/latest/download/tinysocks-windows-x86_64.zip) をダウンロード・展開し、`tinysocks-windows-x86_64` で管理者 PowerShell を開きます：

```powershell
.\tinysocks.exe 0.0.0.0:1080 --username admin --password 'change-me' install
```

### ソースからビルド

```bash
git clone https://github.com/wzhone/tinysocks.git
cd tinysocks
cargo build --release --locked
cd target/release
```

Rust 1.96+ が必要です。出力先は `target/release/tinysocks`（Windows：`tinysocks.exe`）です。

## 使い方

クライアントで SOCKS5 または HTTP を選び、サーバーアドレス、ポート `1080`、設定したユーザー名とパスワードを入力します。

リモートアクセスにはサーバーのファイアウォールで TCP `1080` を許可します。

### コマンド形式

```text
tinysocks [OPTIONS] [BIND ADDR] [COMMAND]
```

| コマンド | 動作 |
|---|---|
| コマンドなし | フォアグラウンドで実行、Ctrl+C で停止 |
| `install` | サービスをインストール・起動し、自動起動を設定 |
| `uninstall` | サービスを停止・削除し、インストール済みファイルを削除 |
| `help [COMMAND]` | ヘルプを表示 |

```bash
./tinysocks --help
./tinysocks install --help
```

### Docker

コンテナは `0.0.0.0:1080` で待ち受けます。環境変数、またはイメージ名の後の CLI 引数で設定します。

Docker で SOCKS5 UDP ASSOCIATE を使う場合は `-p 1080:1080` を `--network host` に置き換えます。

### バイナリ

```bash
./tinysocks 127.0.0.1:1080 \
  --username admin \
  --password 'change-me'
```

リモートアクセスには `0.0.0.0:1080`（IPv4）または `[::]:1080`（IPv6）を指定します。

ローカルから認証なしで接続：

```bash
./tinysocks 127.0.0.1:1080 --bypass-ip '127.0.0.1,::1'
```

## 統計

`http://<proxy-host>:<proxy-port>/stats` で接続数とトラフィック統計を確認できます。許可リスト外のクライアントはプロキシの認証情報でログインします。

統計を無効にする場合（現在はソースビルドが必要）：

```bash
./tinysocks 127.0.0.1:1080 --username admin --password 'change-me' --disable-stats
```

`TINYSOCKS_DISABLE_STATS=true` でも設定できます。サービスのインストール時は `install` の前に `--disable-stats` を指定します。

## 設定

| オプション | 環境変数 | デフォルト | 説明 |
|---|---|---|---|
| `[BIND ADDR]` | `TINYSOCKS_BIND` | `127.0.0.1:1080` | 待ち受けアドレスとポート |
| `-m, --max-connections <NUM>` | `TINYSOCKS_MAX_CONNECTIONS` | `1024` | 同時接続数の上限、`1`–`1000000` |
| `-u, --username <NAME>` | `TINYSOCKS_USERNAME` | - | プロキシユーザー名、パスワードと同時に設定 |
| `-p, --password <PASSWORD>` | `TINYSOCKS_PASSWORD` | - | プロキシパスワード |
| `--bypass-ip <IP_OR_CIDR>` | `TINYSOCKS_BYPASS_IP` | - | 認証を省略する IP / CIDR、カンマ区切り、指定は 1 回 |
| `--disable-stats` | `TINYSOCKS_DISABLE_STATS` | `false` | 統計を無効にする |
| `-h, --help` | - | - | コマンドヘルプを表示 |
| `-V, --version` | - | - | プログラムのバージョンを表示 |

CLI 引数は環境変数より優先されます。ユーザー名とパスワード、または `--bypass-ip` の設定が必要です。

## サービス管理

### Linux systemd

```bash
sudo systemctl status tinysocks --no-pager
sudo journalctl -u tinysocks -n 50 --no-pager
```

`/etc/tinysocks/tinysocks.env` の認証情報を変更した後は再起動します：

```bash
sudo systemctl restart tinysocks
```

アンインストール:

```bash
sudo /usr/local/bin/tinysocks uninstall
```

### Windows

```powershell
Get-Service TinySocks
Restart-Service TinySocks
```

展開先ディレクトリからアンインストール：

```powershell
.\tinysocks.exe uninstall
```

## ライセンス

[MIT](LICENSE)
