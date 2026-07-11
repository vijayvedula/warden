# Install & build

Warden's core is a single Rust binary. The optional Python SDK provides the
identity adapters and orchestration shims.

## Build the binary

```sh
git clone https://github.com/vijayvedula/warden
cd warden
cargo build --release            # -> target/release/warden
export PATH="$PWD/target/release:$PATH"
warden --help
```

> Requires a recent stable Rust toolchain (see `rust-version` in `Cargo.toml`).
> A debug build (`cargo build`) is fine for local use.

## Run it in a container

A slim, non-root image is provided:

```sh
docker build -t warden .
docker run --rm warden --help
# with a config + policy mounted:
docker run --rm -v "$PWD:/cfg" warden proxy --config /cfg/warden.proxy.toml
```

Tagged releases also publish prebuilt binaries and a container image to GHCR.

## Install the Python SDK

Only needed if you want the identity adapters / orchestration shims (most
[provider guides](../providers/index.md) use it):

```sh
pip install warden-agent-sdk             # core: token builder + conformance kit
pip install "warden-agent-sdk[jwt]"      # + asymmetric JWT signing (PyJWT)
```

The SDK core is pure-stdlib; the proxy always accepts a raw conforming token, so
the SDK is convenience, not a requirement.

## Verify your install

```sh
warden demo                        # self-contained walkthrough, no API key
warden audit verify --audit .warden-demo/audit.jsonl
```

If both succeed, you're ready for the [Quickstart](./quickstart.md).
