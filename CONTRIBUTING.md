# Contributing to Warden

Thanks for your interest in Warden — an action control plane for AI agents.
Contributions of all kinds are welcome: bug reports, docs, policy examples,
platform adapters, and core changes.

## Ground rules

- **Be respectful.** See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
- **Security issues are private.** Do **not** open a public issue for a
  vulnerability — follow [SECURITY.md](SECURITY.md).
- **License.** By contributing you agree your work is dual-licensed under
  **MIT OR Apache-2.0**, matching the project.

## Development setup

Warden core is Rust; the adapter SDK is Python.

```sh
# Rust core
cargo build
cargo test
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings

# Python SDK
cd sdk/python
pip install -e ".[dev]"
pytest
ruff check .
```

## The checks CI runs (run them before you push)

| Area   | Command                                             |
|--------|-----------------------------------------------------|
| Format | `cargo fmt --all --check`                           |
| Lint   | `cargo clippy --all-targets -- -D warnings`         |
| Tests  | `cargo test` and (in `sdk/python`) `pytest`         |
| Smoke  | `warden demo && warden audit verify --audit .warden-demo/audit.jsonl` |
| Supply chain | `cargo audit`, `cargo deny check`             |

## Pull requests

1. Fork and branch from `main`.
2. Keep changes focused; add tests for behavior changes.
3. Update docs/examples when you change a user-facing surface.
4. Ensure the checks above pass locally.
5. Open the PR with a clear description of the **what** and the **why**.

## Writing a platform adapter

Adapters are pure claims-mapping — they **never sign authority themselves**
(see [docs/platform-integration.md](docs/platform-integration.md), the
"no-forged-authority rule"). A new adapter must:

1. Map the platform's native identity to Warden's canonical claims
   (`sub`, `act`, `roles`, `attrs`, `rel`, `scope`).
2. Pass the conformance kit: the emitted token must verify with
   `warden token verify`. See `sdk/python/tests/`.

## Commit style

Short imperative subject lines (e.g. `policy: add rate-window conditions`).
Reference issues where relevant.
