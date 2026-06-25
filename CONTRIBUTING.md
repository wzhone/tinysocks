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

## Pull Requests

- Keep changes focused and avoid unrelated refactors.
- Add or update tests for behavior changes.
- Update README files when user-facing behavior changes.
- Do not include generated build artifacts.

## Security

Do not report security vulnerabilities in public issues. Follow [SECURITY.md](SECURITY.md).
