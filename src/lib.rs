//! agent-cid — content-addressed artifact manifest for AI agents.
//!
//! Rust port of [`@p-vbordei/agent-cid`](https://github.com/p-vbordei/agent-cid).
//! Byte-deterministic-compatible with the TypeScript reference; passes the
//! same C1–C5 conformance vectors.

pub mod build;
pub mod canonical;
pub mod cid;
pub mod did;
pub mod did_web;
pub mod error;
pub mod sign;
pub mod types;
pub mod verify;

pub use build::build;
pub use cid::{bytes_to_cid, verify_cid};
pub use did::{did_key_to_pubkey, did_web_to_url, parse_ed25519_from_did_doc, pubkey_to_did_key};
pub use did_web::fetch_did_web_pubkey;
pub use error::Error;
pub use types::{BuildOpts, DidResolver, Manifest, Signature, SignerInput, VerifyOptions, VerifyResult};
pub use verify::{verify, verify_chain};
