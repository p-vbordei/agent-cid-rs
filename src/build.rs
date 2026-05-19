use chrono::Utc;
use serde_json::{json, Map, Value};

use crate::canonical::canonical_encode;
use crate::cid::bytes_to_cid;
use crate::error::Error;
use crate::sign::b64encode;
use crate::types::{BuildOpts, Manifest};

fn iso(dt: chrono::DateTime<Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

pub async fn build(data: &[u8], opts: BuildOpts) -> Result<Manifest, Error> {
    if opts.signers.is_empty() {
        return Err(Error::Invalid("build requires at least one signer".into()));
    }
    let cid = bytes_to_cid(data);
    let mut unsigned = Map::new();
    unsigned.insert("v".into(), json!("agent-cid/1"));
    unsigned.insert("cid".into(), json!(cid));
    unsigned.insert("size".into(), json!(data.len()));
    unsigned.insert("media_type".into(), json!(opts.media_type));
    unsigned.insert("schema_uri".into(), json!(opts.schema_uri));
    unsigned.insert("producer".into(), json!(opts.producer_did));
    unsigned.insert(
        "created_at".into(),
        json!(opts.created_at.clone().unwrap_or_else(|| iso(Utc::now()))),
    );
    if let Some(p) = &opts.parent_cid {
        unsigned.insert("parent_cid".into(), json!(p));
    }
    if let Some(r) = &opts.retention {
        unsigned.insert("retention".into(), serde_json::to_value(r)?);
    }

    let unsigned_value = Value::Object(unsigned.clone());
    let canonical = canonical_encode(&unsigned_value)?;

    let mut sigs: Vec<Value> = Vec::with_capacity(opts.signers.len());
    for s in &opts.signers {
        let bytes = (s.sign_fn)(canonical.clone()).await?;
        sigs.push(json!({
            "signer_did": s.did,
            "alg": "ed25519",
            "sig": b64encode(&bytes),
        }));
    }
    let mut out = unsigned;
    out.insert("sigs".into(), Value::Array(sigs));
    Ok(Value::Object(out))
}
