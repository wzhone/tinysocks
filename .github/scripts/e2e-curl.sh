#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

TINYSOCKS_BIN="${TINYSOCKS_BIN:-${PROXY_BIN:-$REPO_ROOT/target/debug/tinysocks}}"
TMP_DIR="$(mktemp -d)"
PIDS=()

cleanup() {
  local status=$?

  if [[ $status -ne 0 ]]; then
    for log in "$TMP_DIR"/*.log; do
      [[ -f "$log" ]] || continue
      echo "===== ${log##*/} ====="
      sed -n '1,200p' "$log"
    done
  fi

  for pid in "${PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  wait "${PIDS[@]}" 2>/dev/null || true
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

for cmd in curl openssl python3; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd" >&2
    exit 1
  fi
done

if [[ ! -x "$TINYSOCKS_BIN" ]]; then
  echo "tinysocks binary is not executable: $TINYSOCKS_BIN" >&2
  echo "run cargo build --locked before this script" >&2
  exit 1
fi

read -r AUTH_PROXY_PORT ALLOW_PROXY_PORT HTTP_PORT HTTPS_PORT < <(
  python3 - <<'PY'
import socket

sockets = []
for _ in range(4):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sockets.append(sock)

print(" ".join(str(sock.getsockname()[1]) for sock in sockets))

for sock in sockets:
    sock.close()
PY
)

cat >"$TMP_DIR/upstream.py" <<'PY'
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
import ssl


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self._send(f"{self.server.label} GET {self.path}\n".encode())

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        payload = self.rfile.read(length).decode("utf-8")
        self._send(f"{self.server.label} POST {self.path} body={payload}\n".encode())

    def _send(self, body):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print(fmt % args, flush=True)


server = ThreadingHTTPServer(("127.0.0.1", int(os.environ["PORT"])), Handler)
server.label = os.environ["LABEL"]

cert = os.environ.get("TLS_CERT")
key = os.environ.get("TLS_KEY")
if cert and key:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, keyfile=key)
    server.socket = context.wrap_socket(server.socket, server_side=True)

server.serve_forever()
PY

openssl req \
  -x509 \
  -newkey rsa:2048 \
  -nodes \
  -days 1 \
  -subj "/CN=localhost" \
  -keyout "$TMP_DIR/key.pem" \
  -out "$TMP_DIR/cert.pem" \
  >"$TMP_DIR/openssl.log" 2>&1

PORT="$HTTP_PORT" LABEL="HTTP" python3 "$TMP_DIR/upstream.py" \
  >"$TMP_DIR/http-upstream.log" 2>&1 &
PIDS+=("$!")

PORT="$HTTPS_PORT" LABEL="HTTPS" TLS_CERT="$TMP_DIR/cert.pem" TLS_KEY="$TMP_DIR/key.pem" \
  python3 "$TMP_DIR/upstream.py" >"$TMP_DIR/https-upstream.log" 2>&1 &
PIDS+=("$!")

TINYSOCKS_BIND="127.0.0.1:$AUTH_PROXY_PORT" \
TINYSOCKS_USERNAME="ci-user" \
TINYSOCKS_PASSWORD="ci-pass" \
TINYSOCKS_MAX_CONNECTIONS=128 \
TINYSOCKS_BYPASS_IP="192.0.2.1/32" \
"$TINYSOCKS_BIN" \
  >"$TMP_DIR/proxy-auth.log" 2>&1 &
PIDS+=("$!")

"$TINYSOCKS_BIN" \
  "127.0.0.1:$ALLOW_PROXY_PORT" \
  --bypass-ip "127.0.0.0/8,::1/128" \
  >"$TMP_DIR/proxy-allowlist.log" 2>&1 &
PIDS+=("$!")

wait_for_port() {
  local port="$1"
  local name="$2"

  for _ in $(seq 1 100); do
    if python3 - "$port" <<'PY'
import socket
import sys

with socket.socket() as sock:
    sock.settimeout(0.2)
    try:
        sock.connect(("127.0.0.1", int(sys.argv[1])))
    except OSError:
        sys.exit(1)
PY
    then
      return 0
    fi
    sleep 0.1
  done

  echo "$name did not listen on 127.0.0.1:$port" >&2
  exit 1
}

wait_for_port "$HTTP_PORT" "HTTP upstream"
wait_for_port "$HTTPS_PORT" "HTTPS upstream"
wait_for_port "$AUTH_PROXY_PORT" "auth proxy"
wait_for_port "$ALLOW_PROXY_PORT" "allowlist proxy"

assert_body_contains() {
  local expected="$1"
  shift

  local body
  body="$(curl --noproxy "" --fail --silent --show-error --max-time 10 "$@")"
  if [[ "$body" != *"$expected"* ]]; then
    echo "expected response to contain: $expected" >&2
    echo "actual response:" >&2
    printf '%s\n' "$body" >&2
    exit 1
  fi
}

assert_http_status() {
  local expected="$1"
  shift

  local status
  status="$(curl --noproxy "" --silent --output /dev/null --write-out '%{http_code}' --max-time 10 "$@" || true)"
  if [[ "$status" != "$expected" ]]; then
    echo "expected HTTP status $expected, got $status" >&2
    exit 1
  fi
}

expect_failure() {
  local label="$1"
  shift

  if "$@" >"$TMP_DIR/expected-failure.out" 2>"$TMP_DIR/expected-failure.err"; then
    echo "expected command to fail: $label" >&2
    cat "$TMP_DIR/expected-failure.out" >&2
    exit 1
  fi
}

echo "HTTP proxy requires credentials"
assert_http_status 407 \
  --proxy "http://127.0.0.1:$AUTH_PROXY_PORT" \
  "http://127.0.0.1:$HTTP_PORT/no-auth"

echo "HTTP proxy rejects wrong credentials"
assert_http_status 407 \
  --proxy "http://ci-user:wrong-pass@127.0.0.1:$AUTH_PROXY_PORT" \
  "http://127.0.0.1:$HTTP_PORT/wrong-auth"

echo "HTTP proxy forwards GET with credentials"
assert_body_contains "HTTP GET /http-forward?ok=1" \
  --proxy "http://ci-user:ci-pass@127.0.0.1:$AUTH_PROXY_PORT" \
  "http://127.0.0.1:$HTTP_PORT/http-forward?ok=1"

echo "HTTP proxy forwards POST body with credentials"
assert_body_contains "HTTP POST /http-post body=payload=ci" \
  --proxy "http://ci-user:ci-pass@127.0.0.1:$AUTH_PROXY_PORT" \
  --data "payload=ci" \
  "http://127.0.0.1:$HTTP_PORT/http-post"

echo "HTTP CONNECT tunnels HTTPS with credentials"
assert_body_contains "HTTPS GET /connect-tunnel" \
  --proxy "http://ci-user:ci-pass@127.0.0.1:$AUTH_PROXY_PORT" \
  --insecure \
  "https://127.0.0.1:$HTTPS_PORT/connect-tunnel"

echo "SOCKS5 rejects missing credentials"
expect_failure "SOCKS5 without credentials" \
  curl --silent --show-error --max-time 10 \
  --noproxy "" \
  --socks5-hostname "127.0.0.1:$AUTH_PROXY_PORT" \
  "http://127.0.0.1:$HTTP_PORT/socks-no-auth"

echo "SOCKS5 rejects wrong credentials"
expect_failure "SOCKS5 with wrong credentials" \
  curl --silent --show-error --max-time 10 \
  --noproxy "" \
  --socks5-hostname "ci-user:wrong-pass@127.0.0.1:$AUTH_PROXY_PORT" \
  "http://127.0.0.1:$HTTP_PORT/socks-wrong-auth"

echo "SOCKS5 forwards HTTP with credentials"
assert_body_contains "HTTP GET /socks5-auth" \
  --socks5-hostname "ci-user:ci-pass@127.0.0.1:$AUTH_PROXY_PORT" \
  "http://127.0.0.1:$HTTP_PORT/socks5-auth"

echo "allowlisted HTTP client skips credentials"
assert_body_contains "HTTP GET /allowlist-http" \
  --proxy "http://127.0.0.1:$ALLOW_PROXY_PORT" \
  "http://127.0.0.1:$HTTP_PORT/allowlist-http"

echo "allowlisted SOCKS5 client skips credentials"
assert_body_contains "HTTP GET /allowlist-socks5" \
  --socks5-hostname "127.0.0.1:$ALLOW_PROXY_PORT" \
  "http://127.0.0.1:$HTTP_PORT/allowlist-socks5"

echo "curl e2e tests passed"
