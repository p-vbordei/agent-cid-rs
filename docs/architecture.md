# agent-cid (Rust) — Architecture

## Goal

Port the `agent-cid` v1.0 spec ([SPEC.md](../SPEC.md)) to idiomatic Rust while keeping every byte that goes on the wire — CIDv1 strings, JCS-canonical manifest bytes, Ed25519 signatures — byte-identical with the TypeScript reference. Pass the same C1–C5 conformance vectors.

## Module map

| `src/<file>` | TS counterpart | Role |
| --- | --- | --- |
| `build.rs` | `src/build.ts` | Compute CID, fill manifest, collect Ed25519 signatures over JCS-canonical bytes. |
| `verify.rs` | `src/verify.ts` | Schema check, size check, CID check, signature verification, retention enforcement; per-resolver pubkey cache; `verify_chain` for `parent_cid` traversal. |
| `canonical.rs` | `src/canonical.ts` | RFC 8785 JCS encoding wrapper around `serde_jcs`. |
| `cid.rs` | `src/cid.ts` | CIDv1 with raw codec + multihash sha-256, base32-lower string form. |
| `did.rs` | `src/did.ts` | `did:key` codec for Ed25519; `did:web → URL` derivation; DID-doc Ed25519 lookup. |
| `did_web.rs` | `src/did-web.ts` | HTTPS-only fetch with 64 KiB cap and 5 s timeout; default resolver for `did:web`. |
| `sign.rs` | `src/sign.ts` | Ed25519 sign + verify, base64 codec. |
| `types.rs` | `src/types.ts` | Public types — `Manifest` (alias for `serde_json::Value`), `BuildOpts`, `VerifyOptions`, `VerifyResult`, `SignerInput`, `DidResolver`, `SignFn`. |
| `error.rs` | (split from `verify.ts`) | `thiserror` error enum for fail paths. |

## Dependency choices

| Concern | Crate | Rationale |
| --- | --- | --- |
| Ed25519 sign / verify | [`ed25519-dalek`](https://crates.io/crates/ed25519-dalek) | Pure-Rust, audited; no native build deps. |
| JCS (RFC 8785) | [`serde_jcs`](https://crates.io/crates/serde_jcs) | Direct RFC 8785 implementation atop serde. See the precision note below. |
| Multihash / CID | inline | CIDv1 + raw codec + sha-256 + base32-lower is ~40 lines. `cid` + `multihash` together would add several crates worth of types for one constant codec. |
| SHA-256 | [`sha2`](https://crates.io/crates/sha2) | RustCrypto standard. |
| Base58 | [`bs58`](https://crates.io/crates/bs58) | Tiny, used by `did:key` multibase. |
| Base32 / base64 | [`data-encoding`](https://crates.io/crates/data-encoding) + [`base64`](https://crates.io/crates/base64) | base32-lower for CID, base64 for signatures. |
| HTTP client | [`reqwest`](https://crates.io/crates/reqwest) (rustls) | Async, `rustls-tls`, supports response-body size cap + timeout. |
| Async runtime | [`tokio`](https://crates.io/crates/tokio) | The reqwest + future story is simplest under tokio; we don't expose a runtime. |

## Byte-determinism invariants

- **CIDv1 string** — base32-lower, raw codec (`0x55`), multihash sha-256 of the body. Output of `bytes_to_cid` must equal the TS output for the same body.
- **Canonical manifest bytes** — JCS-canonical JSON of the manifest with `sigs` removed. This is what signatures cover. Sort order, escaping, and number formatting follow RFC 8785.
- **Signature bytes** — Ed25519 over the canonical bytes; base64-encoded for transport. No domain separation, no prefix.

### JCS precision note

`serde_jcs` preserves `u64`/`i64` integers above 2^53. RFC 8785 requires all JSON numbers to be formatted via ECMA-262 ToString of `f64`, so integers beyond the safe-integer range lose precision in the canonical form. `agent-cid` manifests don't currently use integers in that range (`size` is bytes, `created_at` is a string), so a normalize pass isn't required here — but the same approach used in [`agent-scroll-rs/src/canonical.rs`](https://github.com/p-vbordei/agent-scroll-rs/blob/main/src/canonical.rs) is the documented fallback if the schema ever grows a numeric field that could exceed it.

## Testing strategy

- **Conformance** (`tests/conformance.rs`) — single `all_vectors_pass` test runs every JSON file under `vectors/`, dispatched by `kind` (`roundtrip`, `tampered_body`, `parent_chain`, `canonical`, `did_web_roundtrip`). Vectors are copied verbatim from the TS reference.
- **Planned cross-impl byte equality** — a CI job that runs the TS, Python, and Rust ports against shared vectors and diffs canonical-bytes + CID + signature output. Tracked as future work; the per-port suites already catch divergence in practice because vectors fix the expected CID.

Any wire-format change must be proposed in the TS reference first and the vectors regenerated there. The ports follow.
