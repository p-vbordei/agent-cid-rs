use std::time::Duration;

use crate::did::{did_web_to_url, parse_ed25519_from_did_doc};
use crate::error::Error;

const DEFAULT_TIMEOUT_MS: u64 = 5000;
const DEFAULT_SIZE_LIMIT: usize = 64 * 1024;

pub async fn fetch_did_web_pubkey(did: &str) -> Result<[u8; 32], Error> {
    fetch_did_web_pubkey_with(did, DEFAULT_TIMEOUT_MS, DEFAULT_SIZE_LIMIT).await
}

pub async fn fetch_did_web_pubkey_with(
    did: &str,
    timeout_ms: u64,
    size_limit: usize,
) -> Result<[u8; 32], Error> {
    let url = did_web_to_url(did)?;
    if !url.starts_with("https://") {
        return Err(Error::Invalid(format!("did:web requires https://, got {url}")));
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(timeout_ms))
        .build()
        .map_err(|e| Error::Http(e.to_string()))?;
    let resp = client
        .get(&url)
        .header("accept", "application/json")
        .send()
        .await
        .map_err(|e| Error::Http(e.to_string()))?;
    let status = resp.status().as_u16();
    if !resp.status().is_success() {
        return Err(Error::DidWebHttp(did.to_string(), status));
    }
    let body = resp.bytes().await.map_err(|e| Error::Http(e.to_string()))?;
    if body.len() > size_limit {
        return Err(Error::DidWebTooLarge {
            size: body.len(),
            limit: size_limit,
        });
    }
    let doc: serde_json::Value = serde_json::from_slice(&body)?;
    parse_ed25519_from_did_doc(&doc, did)
}
