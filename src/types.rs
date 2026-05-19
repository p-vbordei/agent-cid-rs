use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub signer_did: String,
    pub alg: String,
    pub sig: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Retention {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stale_after: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

/// Manifest kept as a generic JSON value so canonicalization round-trips
/// byte-for-byte with the TypeScript reference.
pub type Manifest = Value;

pub type SignFn = Arc<
    dyn Fn(Vec<u8>) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, crate::Error>> + Send>>
        + Send
        + Sync,
>;

#[derive(Clone)]
pub struct SignerInput {
    pub did: String,
    pub sign_fn: SignFn,
}

#[derive(Clone)]
pub struct BuildOpts {
    pub producer_did: String,
    pub schema_uri: String,
    pub media_type: String,
    pub signers: Vec<SignerInput>,
    pub parent_cid: Option<String>,
    pub retention: Option<Retention>,
    pub created_at: Option<String>,
}

pub type DidResolver = Arc<
    dyn Fn(String) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, crate::Error>> + Send>>
        + Send
        + Sync,
>;

pub struct VerifyOptions {
    pub resolver: Option<DidResolver>,
    pub resolver_cache: bool,
    pub resolver_timeout_ms: u64,
    pub ignore_expiry: bool,
    pub now_ms: Option<i64>,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self {
            resolver: None,
            resolver_cache: true,
            resolver_timeout_ms: 5000,
            ignore_expiry: false,
            now_ms: None,
        }
    }
}

#[derive(Debug, Default)]
pub struct VerifyResult {
    pub ok: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}
