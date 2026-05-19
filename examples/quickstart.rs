//! End-to-end demo for agent-cid (Rust).
//!
//! Mirrors examples/demo.ts in the TS reference:
//!   1. build a manifest over a small payload, verify it
//!   2. flip one byte → verify fails
//!   3. roll v2 with parent_cid = v1 cid, verify
//!
//! Run: `cargo run --example quickstart`

use std::sync::Arc;

use agent_cid::{
    build, pubkey_to_did_key, types::SignFn, verify, BuildOpts, SignerInput, VerifyOptions,
};
use ed25519_dalek::{Signer, SigningKey};

fn signer_fn(sk: SigningKey) -> SignFn {
    Arc::new(move |msg: Vec<u8>| {
        let sk = sk.clone();
        Box::pin(async move { Ok(sk.sign(&msg).to_bytes().to_vec()) })
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Deterministic key — matches the TS demo's 0x42-fill private key.
    let sk = SigningKey::from_bytes(&[0x42u8; 32]);
    let did = pubkey_to_did_key(sk.verifying_key().as_bytes())?;

    let body_v1 = br#"{"answer":42}"#.to_vec();
    let m1 = build(
        &body_v1,
        BuildOpts {
            producer_did: did.clone(),
            schema_uri: "https://example.org/answer/1".into(),
            media_type: "application/json".into(),
            signers: vec![SignerInput { did: did.clone(), sign_fn: signer_fn(sk.clone()) }],
            parent_cid: None,
            retention: None,
            created_at: None,
        },
    )
    .await?;
    println!("built v1: {}", m1["cid"].as_str().unwrap_or(""));
    let r1 = verify(&m1, &body_v1, &VerifyOptions::default()).await;
    println!("verify v1: {}", r1.ok);

    let mut tampered = body_v1.clone();
    tampered[0] ^= 0xFF;
    let r_bad = verify(&m1, &tampered, &VerifyOptions::default()).await;
    println!("verify tampered: {}", r_bad.ok);

    let body_v2 = br#"{"answer":43}"#.to_vec();
    let m2 = build(
        &body_v2,
        BuildOpts {
            producer_did: did.clone(),
            schema_uri: "https://example.org/answer/1".into(),
            media_type: "application/json".into(),
            signers: vec![SignerInput { did, sign_fn: signer_fn(sk) }],
            parent_cid: Some(m1["cid"].as_str().unwrap().to_string()),
            retention: None,
            created_at: None,
        },
    )
    .await?;
    let r2 = verify(&m2, &body_v2, &VerifyOptions::default()).await;
    println!("built v2 (parent_cid set): {}", r2.ok);

    Ok(())
}
