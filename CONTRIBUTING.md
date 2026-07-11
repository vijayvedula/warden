# Contributing to Warden

Thanks for your interest in Warden — an action control plane for AI agents.
Contributions of all kinds are welcome: bug reports, docs, policy examples,
platform adapters, and core changes.

## You don't need to "join" — just contribute

Warden uses the standard open-source flow: **no access is required to
contribute.** Fork the repo, push a branch to your fork, and open a pull request
— a maintainer reviews and merges. That's it.

Ways to help:

- **Report a bug** or **request a feature** — open an issue (templates guide you).
- **Ask a question or float an idea** — use
  [Discussions](https://github.com/vijayvedula/warden/discussions).
- **Pick up a task** — look for issues labelled
  [`good first issue`](https://github.com/vijayvedula/warden/labels/good%20first%20issue)
  and [`help wanted`](https://github.com/vijayvedula/warden/labels/help%20wanted).
- **Write a platform adapter** — see the SDK and the adapter rules below.
- **Improve the docs / guide / examples.**

Contributors are credited automatically in the repo's contributor graph and
release notes. If you'd like to take on a larger ongoing role, just say so in a
PR or Discussion — sustained, high-quality contributions are how trust (and,
over time, commit access) is earned.

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
