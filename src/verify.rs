use std::collections::HashMap;
use std::sync::Mutex;

use chrono::DateTime;
use once_cell::sync::Lazy;
use serde_json::{Map, Value};

use crate::canonical::canonical_encode;
use crate::cid::verify_cid;
use crate::did::did_key_to_pubkey;
use crate::did_web::fetch_did_web_pubkey;
use crate::error::Error;
use crate::sign::{b64decode, verify_bytes};
use crate::types::{DidResolver, VerifyOptions, VerifyResult};

const RESOLVER_CACHE_TTL_MS: i64 = 5 * 60 * 1000;

// Cache keyed by resolver pointer + DID. usize key = Arc data pointer.
type CacheValue = ([u8; 32], i64);
static RESOLVER_CACHES: Lazy<Mutex<HashMap<usize, HashMap<String, CacheValue>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

async fn builtin_resolve(did: &str) -> Result<[u8; 32], Error> {
    if did.starts_with("did:key:") {
        return did_key_to_pubkey(did);
    }
    if did.starts_with("did:web:") {
        return fetch_did_web_pubkey(did).await;
    }
    Err(Error::Invalid(format!("unsupported DID method: {did}")))
}

fn validate_manifest(m: &Value) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();
    let Some(obj) = m.as_object() else {
        return Err(vec!["schema: root not an object".into()]);
    };
    if obj.get("v").and_then(|v| v.as_str()) != Some("agent-cid/1") {
        errors.push("schema: v must be \"agent-cid/1\"".into());
    }
    for key in ["cid", "media_type", "schema_uri", "producer", "created_at"] {
        if !obj.get(key).and_then(|v| v.as_str()).map(|s| !s.is_empty()).unwrap_or(false) {
            errors.push(format!("schema: {key} must be non-empty string"));
        }
    }
    let size_ok = obj
        .get("size")
        .and_then(|v| v.as_u64())
        .is_some();
    if !size_ok {
        errors.push("schema: size must be non-negative integer".into());
    }
    let producer = obj.get("producer").and_then(|v| v.as_str()).unwrap_or("");
    if !producer.starts_with("did:") {
        errors.push("schema: producer must start with did:".into());
    }
    if obj.contains_key("parent_cid")
        && !obj.get("parent_cid").and_then(|v| v.as_str()).map(|s| !s.is_empty()).unwrap_or(false)
    {
        errors.push("schema: parent_cid must be non-empty string".into());
    }
    let sigs = obj.get("sigs").and_then(|v| v.as_array());
    match sigs {
        None => errors.push("schema: sigs must be non-empty array".into()),
        Some(arr) if arr.is_empty() => errors.push("schema: sigs must be non-empty array".into()),
        Some(arr) => {
            for (i, s) in arr.iter().enumerate() {
                let Some(so) = s.as_object() else {
                    errors.push(format!("schema: sigs[{i}] not object"));
                    continue;
                };
                let sd = so.get("signer_did").and_then(|v| v.as_str()).unwrap_or("");
                if !sd.starts_with("did:") {
                    errors.push(format!("schema: sigs[{i}].signer_did must start with did:"));
                }
                if so.get("alg").and_then(|v| v.as_str()) != Some("ed25519") {
                    errors.push(format!("schema: sigs[{i}].alg must be \"ed25519\""));
                }
                if !so.get("sig").and_then(|v| v.as_str()).map(|s| !s.is_empty()).unwrap_or(false) {
                    errors.push(format!("schema: sigs[{i}].sig must be non-empty string"));
                }
            }
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn parse_iso_ms(s: &str) -> Option<i64> {
    DateTime::parse_from_rfc3339(s).ok().map(|d| d.timestamp_millis())
}

async fn resolve_one(
    resolver: &Option<DidResolver>,
    cache_key: Option<usize>,
    did: &str,
) -> Result<[u8; 32], Error> {
    // Check cache.
    if let Some(key) = cache_key {
        let now = chrono::Utc::now().timestamp_millis();
        if let Ok(caches) = RESOLVER_CACHES.lock() {
            if let Some(entries) = caches.get(&key) {
                if let Some((pk, exp)) = entries.get(did) {
                    if *exp > now {
                        return Ok(*pk);
                    }
                }
            }
        }
    }

    let pk = match resolver {
        Some(r) => {
            let raw = r(did.to_string()).await?;
            let arr = <[u8; 32]>::try_from(raw.as_slice())
                .map_err(|_| Error::Invalid("resolver returned non-32-byte pubkey".into()))?;
            arr
        }
        None => builtin_resolve(did).await?,
    };

    if let Some(key) = cache_key {
        let now = chrono::Utc::now().timestamp_millis();
        if let Ok(mut caches) = RESOLVER_CACHES.lock() {
            caches
                .entry(key)
                .or_default()
                .insert(did.to_string(), (pk, now + RESOLVER_CACHE_TTL_MS));
        }
    }

    Ok(pk)
}

pub async fn verify(
    manifest: &Value,
    data: &[u8],
    options: &VerifyOptions,
) -> VerifyResult {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    if let Err(es) = validate_manifest(manifest) {
        return VerifyResult { ok: false, errors: es, warnings };
    }

    let obj = manifest.as_object().unwrap();
    let now_ms = options.now_ms.unwrap_or_else(|| chrono::Utc::now().timestamp_millis());

    let size = obj.get("size").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
    if size != data.len() {
        errors.push(format!("size mismatch: manifest {size}, body {}", data.len()));
    }
    let cid = obj.get("cid").and_then(|v| v.as_str()).unwrap_or("");
    if !verify_cid(cid, data) {
        errors.push("cid mismatch".into());
    }

    if let Some(retention) = obj.get("retention").and_then(|v| v.as_object()) {
        if let Some(s) = retention.get("expires_at").and_then(|v| v.as_str()) {
            if let Some(exp) = parse_iso_ms(s) {
                if now_ms > exp {
                    if options.ignore_expiry {
                        warnings.push(format!("expired at {s} (ignored)"));
                    } else {
                        errors.push(format!("expired at {s}"));
                    }
                }
            }
        }
        if let Some(s) = retention.get("stale_after").and_then(|v| v.as_str()) {
            if let Some(stale) = parse_iso_ms(s) {
                if now_ms > stale {
                    warnings.push(format!("stale since {s}"));
                }
            }
        }
    }

    let sigs = obj.get("sigs").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let mut unsigned: Map<String, Value> = obj.clone();
    unsigned.remove("sigs");
    let canonical = match canonical_encode(&Value::Object(unsigned)) {
        Ok(b) => b,
        Err(e) => {
            errors.push(format!("canonical encode: {e}"));
            return VerifyResult { ok: false, errors, warnings };
        }
    };

    let cache_key = if options.resolver_cache {
        Some(
            options
                .resolver
                .as_ref()
                .map(|r| std::sync::Arc::as_ptr(r) as *const () as usize)
                .unwrap_or(0),
        )
    } else {
        None
    };

    for (i, s) in sigs.iter().enumerate() {
        let signer_did = s.get("signer_did").and_then(|v| v.as_str()).unwrap_or("");
        let sig_b64 = s.get("sig").and_then(|v| v.as_str()).unwrap_or("");
        let sig_bytes = match b64decode(sig_b64) {
            Ok(b) => b,
            Err(e) => {
                errors.push(format!("sigs[{i}]: base64 decode: {e}"));
                continue;
            }
        };
        match resolve_one(&options.resolver, cache_key, signer_did).await {
            Ok(pk) => {
                if !verify_bytes(&sig_bytes, &canonical, &pk) {
                    errors.push(format!("sigs[{i}]: invalid signature for {signer_did}"));
                }
            }
            Err(e) => errors.push(format!("sigs[{i}]: {e}")),
        }
    }

    VerifyResult { ok: errors.is_empty(), errors, warnings }
}

pub async fn verify_chain(
    chain: &[(Value, Vec<u8>)],
    options: &VerifyOptions,
) -> VerifyResult {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    let mut prev_cid: Option<String> = None;

    for (i, (m, body)) in chain.iter().enumerate() {
        let r = verify(m, body, options).await;
        for w in r.warnings {
            warnings.push(format!("chain[{i}]: {w}"));
        }
        if !r.ok {
            for e in r.errors {
                errors.push(format!("chain[{i}]: {e}"));
            }
        }
        if let Some(obj) = m.as_object() {
            if i > 0 {
                let got = obj.get("parent_cid").and_then(|v| v.as_str()).map(String::from);
                if got != prev_cid {
                    errors.push(format!(
                        "chain[{i}]: parent_cid mismatch — expected {:?}, got {:?}",
                        prev_cid.as_deref().unwrap_or(""),
                        got.as_deref().unwrap_or("<missing>")
                    ));
                }
            }
            prev_cid = obj.get("cid").and_then(|v| v.as_str()).map(String::from);
        }
    }

    VerifyResult { ok: errors.is_empty(), errors, warnings }
}
