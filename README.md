# agent-cid (Rust)

[![CI](https://github.com/p-vbordei/agent-cid-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/p-vbordei/agent-cid-rs/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-green)](./LICENSE)

> **Rust port of [`@p-vbordei/agent-cid`](https://github.com/p-vbordei/agent-cid).** Content-addressed artifact manifest for AI agents — CIDv1 + Ed25519 + DID + RFC 8785 JCS. Byte-deterministic-compatible with the TypeScript reference: passes the same C1–C5 conformance vectors.

## Install

```toml
[dependencies]
agent-cid = "0.1"
```

## Conformance

```bash
cargo test
```

Vectors in `vectors/` are copied verbatim from the [TS conformance suite](https://github.com/p-vbordei/agent-cid/tree/main/conformance/vectors).

## License

Apache-2.0
