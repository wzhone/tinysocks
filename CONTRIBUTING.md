# Contributing

Thanks for contributing to TinySocks.

## Development

TinySocks requires Rust 1.96 or newer.

Run the local checks before opening a pull request:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all --locked
cargo build --locked
.github/scripts/e2e-curl.sh
```

## Code Layout

- `src/main.rs` and `src/cli.rs`: command dispatch and CLI/environment options.
- `src/config.rs`: runtime configuration validation.
- `src/server.rs`: connection admission, limits, and SOCKS5/HTTP dispatch.
- `src/socks.rs`: SOCKS5 authentication, commands, and TCP/UDP relays.
- `src/protocol.rs`: SOCKS5 message encoding/decoding and prefixed stream I/O.
- `src/http.rs`: HTTP authentication, forwarding, CONNECT, and the stats route.
- `src/auth.rs`, `src/io_timeout.rs`, and `src/stats.rs`: shared runtime helpers.
- `src/service/`: foreground lifecycle, shared service arguments, and platform installers.

## Pull Requests

- Keep changes focused and avoid unrelated refactors.
- Add or update tests for behavior changes.
- Update README files when user-facing behavior changes.
- Do not include generated build artifacts.

## Security

Do not report security vulnerabilities in public issues. Follow [SECURITY.md](SECURITY.md).
