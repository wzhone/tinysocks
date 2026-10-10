# TinySocks

[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/wzhone/tinysocks/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/wzhone/tinysocks/actions/workflows/ci.yml)
[![GitHub Release](https://img.shields.io/github/v/release/wzhone/tinysocks)](https://github.com/wzhone/tinysocks/releases/latest)

[English](README.md) | [中文](README_zh.md) | [日本語](README_ja.md)

TinySocks is a single-port SOCKS5 / HTTP proxy.

## TL;DR

Replace the example password `change-me` with your own.

```bash
docker run -d --name tinysocks --restart unless-stopped \
  -p 1080:1080 \
  -e TINYSOCKS_USERNAME=admin \
  -e TINYSOCKS_PASSWORD=change-me \
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

Prebuilt binaries: [GitHub Releases](https://github.com/wzhone/tinysocks/releases) (Linux / Windows x86_64).

### Linux x86_64 / systemd

Requires root privileges.

```bash
curl -fLO https://github.com/wzhone/tinysocks/releases/latest/download/tinysocks-linux-x86_64.tar.gz &&
tar -xzf tinysocks-linux-x86_64.tar.gz &&
cd tinysocks-linux-x86_64 &&
sudo ./tinysocks 0.0.0.0:1080 --username admin --password 'change-me' install
```

### Windows x86_64

Download [tinysocks-windows-x86_64.zip](https://github.com/wzhone/tinysocks/releases/latest/download/tinysocks-windows-x86_64.zip), extract it, and open an administrator PowerShell in `tinysocks-windows-x86_64`:

```powershell
.\tinysocks.exe 0.0.0.0:1080 --username admin --password 'change-me' install
```

### Build from source

```bash
git clone https://github.com/wzhone/tinysocks.git
cd tinysocks
cargo build --release --locked
cd target/release
```

Requires Rust 1.96+. Output: `target/release/tinysocks` (`tinysocks.exe` on Windows).

## Usage

In your client, select SOCKS5 or HTTP and enter the server address, port `1080`, and configured username and password.

For remote access, allow TCP port `1080` in the server firewall.

### Command line

```text
tinysocks [OPTIONS] [BIND ADDR] [COMMAND]
```

| Command | Behavior |
|---|---|
| No command | Run in the foreground; stop with Ctrl+C |
| `install` | Install, start, and enable the service at boot |
| `uninstall` | Stop and remove the service and installed files |
| `help [COMMAND]` | Print help |

```bash
./tinysocks --help
./tinysocks install --help
```

### Docker

The container listens on `0.0.0.0:1080`. Use environment variables or CLI arguments after the image name.

For SOCKS5 UDP ASSOCIATE in Docker, replace `-p 1080:1080` with `--network host`.

### Binary

```bash
./tinysocks 127.0.0.1:1080 \
  --username admin \
  --password 'change-me'
```

For remote access, bind to `0.0.0.0:1080` (IPv4) or `[::]:1080` (IPv6).

Local access without credentials:

```bash
./tinysocks 127.0.0.1:1080 --bypass-ip '127.0.0.1,::1'
```

## Statistics

Open `http://<proxy-host>:<proxy-port>/stats` for connection and traffic statistics. Clients outside the allowlist log in with the proxy credentials.

Disable statistics (currently requires a source build):

```bash
./tinysocks 127.0.0.1:1080 --username admin --password 'change-me' --disable-stats
```

Or set `TINYSOCKS_DISABLE_STATS=true`. For service installation, put `--disable-stats` before `install`.

## Configuration

| Option | Environment variable | Default | Description |
|---|---|---|---|
| `[BIND ADDR]` | `TINYSOCKS_BIND` | `127.0.0.1:1080` | Listen address and port |
| `-m, --max-connections <NUM>` | `TINYSOCKS_MAX_CONNECTIONS` | `1024` | Concurrent connection limit, `1`–`1000000` |
| `-u, --username <NAME>` | `TINYSOCKS_USERNAME` | - | Proxy username; set with the password |
| `-p, --password <PASSWORD>` | `TINYSOCKS_PASSWORD` | - | Proxy password |
| `--bypass-ip <IP_OR_CIDR>` | `TINYSOCKS_BYPASS_IP` | - | IPs / CIDRs exempt from authentication; comma-separated, pass once |
| `--disable-stats` | `TINYSOCKS_DISABLE_STATS` | `false` | Disable statistics |
| `-h, --help` | - | - | Print command help |
| `-V, --version` | - | - | Print the program version |

CLI arguments override environment variables. Configure a username and password, or `--bypass-ip`.

## Service Management

### Linux systemd

```bash
sudo systemctl status tinysocks --no-pager
sudo journalctl -u tinysocks -n 50 --no-pager
```

After editing credentials in `/etc/tinysocks/tinysocks.env`, restart:

```bash
sudo systemctl restart tinysocks
```

Uninstall:

```bash
sudo /usr/local/bin/tinysocks uninstall
```

### Windows

```powershell
Get-Service TinySocks
Restart-Service TinySocks
```

Uninstall from the extracted directory:

```powershell
.\tinysocks.exe uninstall
```

## License

[MIT](LICENSE)
