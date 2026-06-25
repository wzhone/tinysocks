# TinySocks

[English](README.md) | [中文](README_zh.md) | [日本語](README_ja.md)

TinySocks is a single-port proxy that handles SOCKS5 and HTTP proxy requests on the same listener. It supports IPv4 / IPv6, username/password authentication, IP/CIDR allowlists, and SOCKS5 UDP ASSOCIATE.

Runtime statistics are available from the built-in `/stats` page.

## TL;DR

```bash
docker run --rm \
  -p 1080:1080 \
  -e TINYSOCKS_USERNAME=admin \
  -e TINYSOCKS_PASSWORD=change-me \
  -e TINYSOCKS_BYPASS_IP=127.0.0.0/8,::1/128 \
  ghcr.io/wzhone/tinysocks:latest
```

## Features

- Single-port SOCKS5 and HTTP proxy
- HTTP forwarding, HTTP CONNECT, and SOCKS5 CONNECT
- SOCKS5 UDP ASSOCIATE
- IPv4 / IPv6
- Username/password authentication and IP/CIDR allowlists
- Built-in `/stats` page
- Docker, Linux systemd service, and Windows service support

## Installation

Download a binary for your platform from [GitHub Releases](https://github.com/wzhone/tinysocks/releases), or use the Docker image:

```bash
docker pull ghcr.io/wzhone/tinysocks:latest
```

Build from source:

```bash
cargo build --release --locked
```

Building from source requires Rust 1.96 or newer.

## Usage

### Docker

The container runs `tinysocks` by default and listens on `0.0.0.0:1080`. Runtime options can be set with environment variables, or overridden by appending CLI arguments after the image name.

SOCKS5 UDP ASSOCIATE uses an ephemeral UDP relay port per session. Use host networking when running UDP ASSOCIATE through Docker.

### Binary

```bash
tinysocks 127.0.0.1:1080 \
  --username admin \
  --password change-me
```

Clients can connect to the same address and port with either SOCKS5 or HTTP proxy protocol.

## Statistics

Open http://<proxy-host>:<proxy-port>/stats in your browser to view connection and traffic counters. If your client IP is not allowlisted, use the same username and password configured for the proxy.

## Configuration

| Option | Environment variable | Default | Description |
|---|---|---|---|
| `[BIND ADDR]` | `TINYSOCKS_BIND` | `127.0.0.1:1080` | Listen address and port |
| `-m, --max-connections` | `TINYSOCKS_MAX_CONNECTIONS` | `1024` | Global concurrent connection limit |
| `-u, --username` | `TINYSOCKS_USERNAME` | - | Proxy username |
| `-p, --password` | `TINYSOCKS_PASSWORD` | - | Proxy password |
| `--bypass-ip` | `TINYSOCKS_BYPASS_IP` | - | Comma-separated IPs or CIDRs that skip authentication |

CLI arguments take precedence over environment variables. Configure username/password authentication, or at least one `--bypass-ip` allowlist entry.

## Service Installation

`install` and `uninstall` manage host services. The Linux systemd service is named `tinysocks`; the Windows service is named `TinySocks`.

### Linux systemd

```bash
sudo tinysocks 0.0.0.0:1080 \
  --username admin \
  --password change-me \
  install
```

On Linux, `install` stores service credentials in `/etc/tinysocks/tinysocks.env` with `0600` permissions and references that file from the systemd unit.

Uninstall:

```bash
sudo tinysocks uninstall
```

### Windows

Run from an administrator terminal:

```powershell
.\tinysocks.exe 0.0.0.0:1080 `
  --username admin `
  --password change-me `
  install
```

Uninstall:

```powershell
.\tinysocks.exe uninstall
```

## License

[MIT](LICENSE)
