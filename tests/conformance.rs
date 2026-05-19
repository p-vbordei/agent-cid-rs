use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use agent_cid::types::{Retention, SignFn};
use agent_cid::{
    build, parse_ed25519_from_did_doc, pubkey_to_did_key, verify, verify_chain, BuildOpts,
    SignerInput, VerifyOptions,
};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::Value;

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("vectors")
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn signing_key(hex: &str) -> SigningKey {
    let bytes: [u8; 32] = hex_to_bytes(hex).try_into().expect("32-byte priv");
    SigningKey::from_bytes(&bytes)
}

fn signer_for(sk: SigningKey) -> SignFn {
    Arc::new(move |msg: Vec<u8>| {
        let sk = sk.clone();
        Box::pin(async move {
            let sig = sk.sign(&msg);
            Ok(sig.to_bytes().to_vec())
        })
    })
}

async fn run_build(input: &Value) -> (Value, Vec<u8>) {
    let body = hex_to_bytes(input["body_hex"].as_str().unwrap());
    let sk = signing_key(input["producer_priv_hex"].as_str().unwrap());
    let producer_did = pubkey_to_did_key(sk.verifying_key().as_bytes()).unwrap();

    let mut signers = vec![SignerInput {
        did: producer_did.clone(),
        sign_fn: signer_for(sk),
    }];
    if let Some(extras) = input.get("extra_signers").and_then(|v| v.as_array()) {
        for s in extras {
            let sk = signing_key(s["priv_hex"].as_str().unwrap());
            let did = pubkey_to_did_key(sk.verifying_key().as_bytes()).unwrap();
            signers.push(SignerInput {
                did,
                sign_fn: signer_for(sk),
            });
        }
    }

    let parent_cid = input
        .get("parent_cid")
        .and_then(|v| v.as_str())
        .map(String::from);
    let retention: Option<Retention> = input
        .get("retention")
        .map(|v| serde_json::from_value(v.clone()).unwrap());

    let manifest = build(
        &body,
        BuildOpts {
            producer_did,
            schema_uri: input["schema_uri"].as_str().unwrap().to_string(),
            media_type: input["media_type"].as_str().unwrap().to_string(),
            signers,
            parent_cid,
            retention,
            created_at: Some(input["created_at"].as_str().unwrap().to_string()),
        },
    )
    .await
    .unwrap();
    (manifest, body)
}

fn load_vectors() -> Vec<(String, Value)> {
    let dir = vectors_dir();
    let mut entries: Vec<_> = fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".json"))
        .collect();
    entries.sort_by_key(|e| e.file_name());
    entries
        .into_iter()
        .map(|e| {
            let id = e.path().file_stem().unwrap().to_string_lossy().to_string();
            let v: Value = serde_json::from_slice(&fs::read(e.path()).unwrap()).unwrap();
            (id, v)
        })
        .collect()
}

#[tokio::test]
async fn all_vectors_pass() {
    for (id, v) in load_vectors() {
        let kind = v["kind"].as_str().unwrap();
        match kind {
            "roundtrip" => {
                let (m, body) = run_build(&v["build"]).await;
                assert_eq!(m["cid"], v["expected"]["cid"], "cid mismatch on {id}");
                let r = verify(&m, &body, &VerifyOptions::default()).await;
                assert_eq!(r.ok, v["expected"]["verify_ok"].as_bool().unwrap(), "{id}: {:?}", r.errors);
            }
            "tampered_body" => {
                let (m, body) = run_build(&v["build"]).await;
                let offset = v["tamper_offset"].as_u64().unwrap() as usize;
                let mut tampered = body.clone();
                tampered[offset] ^= 0xFF;
                let r = verify(&m, &tampered, &VerifyOptions::default()).await;
                assert!(!r.ok, "{id} unexpectedly verified");
                let wanted = v["expected"]["error_contains"].as_str().unwrap();
                assert!(
                    r.errors.iter().any(|e| e.contains(wanted)),
                    "{id}: errors don't contain {wanted}: {:?}",
                    r.errors
                );
            }
            "parent_chain" => {
                let links = v["links"].as_array().unwrap();
                let mut built: Vec<(Value, Vec<u8>)> = Vec::new();
                let mut prev: Option<String> = None;
                for link in links {
                    let mut link = link.clone();
                    if link.get("parent_cid").is_none() {
                        if let Some(p) = &prev {
                            link["parent_cid"] = Value::String(p.clone());
                        }
                    }
                    let (m, body) = run_build(&link).await;
                    prev = Some(m["cid"].as_str().unwrap().to_string());
                    built.push((m, body));
                }
                if let Some(idx) = v.get("tamper_link_sig_index").and_then(|v| v.as_u64()) {
                    let idx = idx as usize;
                    let (mut m, body) = built[idx].clone();
                    let sigs = m["sigs"].as_array().unwrap().clone();
                    let mut tampered = sigs[0].clone();
                    tampered["sig"] = Value::String("AAAA".into());
                    m["sigs"] = Value::Array(vec![tampered]);
                    built[idx] = (m, body);
                }
                let r = verify_chain(&built, &VerifyOptions::default()).await;
                assert!(!r.ok, "{id} unexpectedly verified");
                let wanted = v["expected"]["error_contains"].as_str().unwrap();
                assert!(
                    r.errors.iter().any(|e| e.contains(wanted)),
                    "{id}: errors {:?}",
                    r.errors
                );
            }
            "canonical" => {
                use agent_cid::canonical::canonical_encode;
                let out = canonical_encode(&v["input"]).unwrap();
                let s = String::from_utf8(out).unwrap();
                assert_eq!(s, v["expected_canonical"].as_str().unwrap(), "{id}");
            }
            "did_web_roundtrip" => {
                let body = hex_to_bytes(v["build"]["body_hex"].as_str().unwrap());
                let sk = signing_key(v["build"]["producer_priv_hex"].as_str().unwrap());
                let producer_did = v["producer_did"].as_str().unwrap().to_string();
                let manifest = build(
                    &body,
                    BuildOpts {
                        producer_did: producer_did.clone(),
                        schema_uri: v["build"]["schema_uri"].as_str().unwrap().to_string(),
                        media_type: v["build"]["media_type"].as_str().unwrap().to_string(),
                        signers: vec![SignerInput {
                            did: producer_did.clone(),
                            sign_fn: signer_for(sk),
                        }],
                        parent_cid: None,
                        retention: None,
                        created_at: Some(v["build"]["created_at"].as_str().unwrap().to_string()),
                    },
                )
                .await
                .unwrap();

                let did_doc = v["did_doc"].clone();
                let resolver: agent_cid::DidResolver = Arc::new(move |did: String| {
                    let did_doc = did_doc.clone();
                    Box::pin(async move {
                        let pk = parse_ed25519_from_did_doc(&did_doc, &did)?;
                        Ok(pk.to_vec())
                    })
                });
                let opts = VerifyOptions {
                    resolver: Some(resolver),
                    resolver_cache: false,
                    ..VerifyOptions::default()
                };
                let r = verify(&manifest, &body, &opts).await;
                assert_eq!(r.ok, v["expected"]["verify_ok"].as_bool().unwrap(), "{id}: {:?}", r.errors);
            }
            other => panic!("unknown kind {other}"),
        }
        println!("PASS {id}");
    }
}
