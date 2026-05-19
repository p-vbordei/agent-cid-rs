# agent-cid (Rust)

[![CI](https://github.com/p-vbordei/agent-cid-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/p-vbordei/agent-cid-rs/actions/workflows/ci.yml)
[![Spec](https://img.shields.io/badge/spec-v1.0-blue)](./SPEC.md)
[![License](https://img.shields.io/badge/license-Apache%202.0-green)](./LICENSE)

> **Idiomatic Rust port of [@p-vbordei/agent-cid](https://github.com/p-vbordei/agent-cid).** Content-addressed artifact manifest for AI agents — CIDv1 + Ed25519 + DID + RFC 8785 JCS. Byte-deterministic-compatible with the TS reference; passes the same C1–C5 conformance suite.

## What's in the box

- `build(bytes, opts)` — compute CIDv1, fill the manifest, sign with one or more Ed25519 keys.
- `verify(manifest, bytes, opts)` — schema + size + CID + signature + retention.
- `verify_chain(&[(manifest, bytes)], opts)` — traverse `parent_cid` chain.
- `pubkey_to_did_key()` / `did_key_to_pubkey()` — round-trip Ed25519 to `did:key`.
- `fetch_did_web_pubkey(did)` — HTTPS resolution with 64 KiB size cap and 5 s timeout.

## Install

```toml
[dependencies]
agent-cid = "0.1"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

## Quickstart

```rust
use std::sync::Arc;
use agent_cid::{build, verify, pubkey_to_did_key, BuildOpts, SignerInput, VerifyOptions};
use ed25519_dalek::{Signer, SigningKey};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sk = SigningKey::from_bytes(&[0x42u8; 32]);
    let did = pubkey_to_did_key(sk.verifying_key().as_bytes())?;
    let sk2 = sk.clone();
    let signer = SignerInput {
        did: did.clone(),
        sign_fn: Arc::new(move |msg| {
            let sk = sk2.clone();
            Box::pin(async move { Ok(sk.sign(&msg).to_bytes().to_vec()) })
        }),
    };
    let body = br#"{"answer":42}"#.to_vec();
    let manifest = build(&body, BuildOpts {
        producer_did: did, schema_uri: "https://example.org/answer/1".into(),
        media_type: "application/json".into(), signers: vec![signer],
        parent_cid: None, retention: None, created_at: None,
    }).await?;
    let r = verify(&manifest, &body, &VerifyOptions::default()).await;
    println!("{} {}", manifest["cid"], r.ok);
    Ok(())
}
```

Run it:

```bash
cargo run --example quickstart
# built v1: bafkreih...
# verify v1: true
# verify tampered: false
# built v2 (parent_cid set): true
```

## How it relates

| Repo | Role |
| --- | --- |
| [`agent-cid`](https://github.com/p-vbordei/agent-cid) (TS) | Reference implementation + normative SPEC + conformance vectors. |
| [`agent-cid-py`](https://github.com/p-vbordei/agent-cid-py) | Idiomatic Python port; same vectors. |
| [`agent-cid-rs`](https://github.com/p-vbordei/agent-cid-rs) (this) | Idiomatic Rust port; same vectors. |

## Conformance

```bash
cargo test
```

Vectors in `vectors/` are copied verbatim from the [TS conformance suite](https://github.com/p-vbordei/agent-cid/tree/main/conformance/vectors). Every C1–C5 vector must pass byte-identical to the TS reference.

| Clause | Vector | Check |
| --- | --- | --- |
| C1 | `c1-roundtrip` | Build then verify a 1 KiB body. |
| C2 | `c2-tampered-body` | Flip a byte; verify fails with `cid mismatch`. |
| C3 | `c3-parent-chain` | 3-version chain; tampered middle signer is flagged. |
| C4 | `c4-canonical` | JCS bytes match the reference. |
| C5 | `c5-did-web` | did:web resolver returns embedded DID doc pubkey. |

## Architecture

See [docs/architecture.md](docs/architecture.md).

## Development

```bash
git clone https://github.com/p-vbordei/agent-cid-rs
cd agent-cid-rs
cargo build
cargo test
cargo fmt --check
cargo clippy --all-targets
```

## License

Apache-2.0 — see [LICENSE](./LICENSE).
