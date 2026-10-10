# TinySocks

[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/wzhone/tinysocks/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/wzhone/tinysocks/actions/workflows/ci.yml)
[![GitHub Release](https://img.shields.io/github/v/release/wzhone/tinysocks)](https://github.com/wzhone/tinysocks/releases/latest)

[English](README.md) | [中文](README_zh.md) | [日本語](README_ja.md)

TinySocks 是一个单端口 SOCKS5 / HTTP 代理。

## TL;DR

将示例密码 `change-me` 替换为自己的密码。

```bash
docker run -d --name tinysocks --restart unless-stopped \
  -p 1080:1080 \
  -e TINYSOCKS_USERNAME=admin \
  -e TINYSOCKS_PASSWORD=change-me \
  ghcr.io/wzhone/tinysocks:latest
```

## 特性

- 单端口同时支持 SOCKS5 和 HTTP 代理
- 支持 HTTP 转发、HTTP CONNECT 和 SOCKS5 CONNECT
- 支持 SOCKS5 UDP ASSOCIATE
- 支持 IPv4 / IPv6
- 支持用户名/密码认证和 IP/CIDR 白名单
- 内置 `/stats` 统计页面
- 支持 Docker、Linux systemd 服务和 Windows 服务

## 安装

预编译：[GitHub Releases](https://github.com/wzhone/tinysocks/releases)（Linux / Windows x86_64）。

### Linux x86_64 / systemd

```bash
curl -fLO https://github.com/wzhone/tinysocks/releases/latest/download/tinysocks-linux-x86_64.tar.gz &&
tar -xzf tinysocks-linux-x86_64.tar.gz &&
cd tinysocks-linux-x86_64 &&
sudo ./tinysocks 0.0.0.0:1080 --username admin --password 'change-me' install
```

### Windows x86_64

下载 [tinysocks-windows-x86_64.zip](https://github.com/wzhone/tinysocks/releases/latest/download/tinysocks-windows-x86_64.zip)，解压后进入 `tinysocks-windows-x86_64`，以管理员身份打开 PowerShell：

```powershell
.\tinysocks.exe 0.0.0.0:1080 --username admin --password 'change-me' install
```

### 从源码构建

```bash
git clone https://github.com/wzhone/tinysocks.git
cd tinysocks
cargo build --release --locked
cd target/release
```

需要 Rust 1.96+，程序生成在 `target/release/tinysocks`（Windows：`tinysocks.exe`）。

## 使用方式

客户端选择 SOCKS5 或 HTTP，填写服务器地址、端口 `1080` 和配置的用户名、密码。

远程访问需在服务器防火墙中放行 TCP `1080`。

### 命令格式

```text
tinysocks [OPTIONS] [BIND ADDR] [COMMAND]
```

| 子命令 | 行为 |
|---|---|
| 不指定子命令 | 前台运行，Ctrl+C 停止 |
| `install` | 安装、启动服务并设为开机自启 |
| `uninstall` | 停止、卸载服务并删除安装文件 |
| `help [COMMAND]` | 显示帮助 |

```bash
./tinysocks --help
./tinysocks install --help
```

### Docker

容器监听 `0.0.0.0:1080`，支持环境变量和镜像名后的 CLI 参数。

Docker 使用 SOCKS5 UDP ASSOCIATE 时，将 `-p 1080:1080` 替换为 `--network host`。

### 二进制

```bash
./tinysocks 127.0.0.1:1080 \
  --username admin \
  --password 'change-me'
```

远程 IPv4 访问使用 `0.0.0.0:1080`，IPv6 使用 `[::]:1080`。

本机免认证：

```bash
./tinysocks 127.0.0.1:1080 --bypass-ip '127.0.0.1,::1'
```

## 运行统计

访问 `http://<proxy-host>:<proxy-port>/stats` 查看连接和流量统计。非白名单客户端使用代理凭据登录。

关闭统计（当前需源码构建）：

```bash
./tinysocks 127.0.0.1:1080 --username admin --password 'change-me' --disable-stats
```

也可设置 `TINYSOCKS_DISABLE_STATS=true`。安装服务时，将 `--disable-stats` 放在 `install` 前。

## 配置

| 参数 | 环境变量 | 默认值 | 说明 |
|---|---|---|---|
| `[BIND ADDR]` | `TINYSOCKS_BIND` | `127.0.0.1:1080` | 监听地址和端口 |
| `-m, --max-connections <NUM>` | `TINYSOCKS_MAX_CONNECTIONS` | `1024` | 并发连接上限，`1`–`1000000` |
| `-u, --username <NAME>` | `TINYSOCKS_USERNAME` | - | 代理用户名，与密码同时配置 |
| `-p, --password <PASSWORD>` | `TINYSOCKS_PASSWORD` | - | 代理密码 |
| `--bypass-ip <IP_OR_CIDR>` | `TINYSOCKS_BYPASS_IP` | - | 免认证 IP / CIDR，逗号分隔，只能传一次 |
| `--disable-stats` | `TINYSOCKS_DISABLE_STATS` | `false` | 关闭统计 |
| `-h, --help` | - | - | 显示命令帮助 |
| `-V, --version` | - | - | 显示程序版本 |

CLI 参数优先于环境变量。必须配置用户名和密码，或 `--bypass-ip`。

## 服务管理

### Linux systemd

```bash
sudo systemctl status tinysocks --no-pager
sudo journalctl -u tinysocks -n 50 --no-pager
```

修改 `/etc/tinysocks/tinysocks.env` 中的凭据后重启：

```bash
sudo systemctl restart tinysocks
```

卸载：

```bash
sudo /usr/local/bin/tinysocks uninstall
```

### Windows

```powershell
Get-Service TinySocks
Restart-Service TinySocks
```

从解压目录卸载：

```powershell
.\tinysocks.exe uninstall
```

## 许可证

[MIT](LICENSE)
