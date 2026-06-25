# TinySocks

[English](README.md) | [中文](README_zh.md) | [日本語](README_ja.md)

TinySocks 是一个单端口代理，在同一个监听地址上同时处理 SOCKS5 和 HTTP 代理请求。它支持 IPv4 / IPv6、用户名/密码认证、IP/CIDR 白名单和 SOCKS5 UDP ASSOCIATE。

运行统计可通过内置 `/stats` 页面查看。

## TL;DR

```bash
docker run --rm \
  -p 1080:1080 \
  -e TINYSOCKS_USERNAME=admin \
  -e TINYSOCKS_PASSWORD=change-me \
  -e TINYSOCKS_BYPASS_IP=127.0.0.0/8,::1/128 \
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

从 [GitHub Releases](https://github.com/wzhone/tinysocks/releases) 下载对应平台的二进制文件，或直接使用 Docker 镜像：

```bash
docker pull ghcr.io/wzhone/tinysocks:latest
```

从源码构建：

```bash
cargo build --release --locked
```

源码构建需要 Rust 1.96 或更高版本。

## 使用方式

### Docker

容器默认执行 `tinysocks run`，并监听 `0.0.0.0:1080`。运行参数可通过环境变量设置，也可以在镜像名后追加 CLI 参数覆盖。

SOCKS5 UDP ASSOCIATE 会为每个会话使用临时 UDP 中继端口。通过 Docker 使用 UDP ASSOCIATE 时，请使用 host network。

### 二进制

```bash
tinysocks 127.0.0.1:1080 \
  --username admin \
  --password change-me \
  run
```

客户端可以用 SOCKS5 或 HTTP 协议连接同一个地址和端口。

## 运行统计

在浏览器中打开 `http://<proxy-host>:<proxy-port>/stats` 可以查看连接和流量计数。如果客户端 IP 不在白名单中，请使用代理配置的同一组用户名和密码。

## 配置

| 参数 | 环境变量 | 默认值 | 说明 |
|---|---|---|---|
| `[BIND ADDR]` | `TINYSOCKS_BIND` | `127.0.0.1:1080` | 监听地址和端口 |
| `-m, --max-connections` | `TINYSOCKS_MAX_CONNECTIONS` | `1024` | 全局并发连接数上限 |
| `-u, --username` | `TINYSOCKS_USERNAME` | - | 代理用户名 |
| `-p, --password` | `TINYSOCKS_PASSWORD` | - | 代理密码 |
| `--bypass-ip` | `TINYSOCKS_BYPASS_IP` | - | 逗号分隔的 IP 或 CIDR，命中后跳过认证 |

CLI 参数优先于环境变量。必须配置用户名/密码，或至少配置一个 `--bypass-ip` 白名单。

## 服务安装

`install` 和 `uninstall` 用于宿主机服务管理。

### Linux systemd

```bash
sudo tinysocks 0.0.0.0:1080 \
  --username admin \
  --password change-me \
  install
```

在 Linux 上，`install` 会把服务凭据写入 `/etc/tinysocks/tinysocks.env`，权限为 `0600`，systemd unit 只引用这个环境文件。

卸载：

```bash
sudo tinysocks uninstall
```

### Windows

在管理员终端中执行：

```powershell
.\tinysocks.exe 0.0.0.0:1080 `
  --username admin `
  --password change-me `
  install
```

卸载：

```powershell
.\tinysocks.exe uninstall
```

## 许可证

[MIT](LICENSE)
