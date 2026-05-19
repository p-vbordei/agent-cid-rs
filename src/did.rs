use serde_json::Value;

use crate::error::Error;

const ED25519_MULTICODEC: u8 = 0xED;
const ED25519_PREFIX: [u8; 2] = [0xED, 0x01];

pub fn pubkey_to_did_key(pubkey: &[u8]) -> Result<String, Error> {
    if pubkey.len() != 32 {
        return Err(Error::Invalid(format!(
            "ed25519 pubkey must be 32 bytes, got {}",
            pubkey.len()
        )));
    }
    let mut buf = Vec::with_capacity(34);
    buf.extend_from_slice(&ED25519_PREFIX);
    buf.extend_from_slice(pubkey);
    Ok(format!("did:key:z{}", bs58::encode(&buf).into_string()))
}

pub fn did_key_to_pubkey(did: &str) -> Result<[u8; 32], Error> {
    if !did.starts_with("did:key:z") {
        return Err(Error::Invalid(format!(
            "not a did:key (must start with \"did:key:z\"): {did}"
        )));
    }
    let decoded = bs58::decode(&did["did:key:z".len()..])
        .into_vec()
        .map_err(|e| Error::Invalid(format!("base58 decode: {e}")))?;
    let (code, code_len) = varint_decode(&decoded)?;
    if code != ED25519_MULTICODEC as u64 {
        return Err(Error::Invalid(format!(
            "unsupported did:key multicodec 0x{code:x} (want ed25519 0xed)"
        )));
    }
    let pub_bytes = &decoded[code_len..];
    if pub_bytes.len() != 32 {
        return Err(Error::Invalid(format!(
            "did:key pubkey has wrong length {} (want 32)",
            pub_bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(pub_bytes);
    Ok(out)
}

fn varint_decode(bytes: &[u8]) -> Result<(u64, usize), Error> {
    let mut n: u64 = 0;
    let mut shift = 0u32;
    for (i, b) in bytes.iter().enumerate() {
        n |= ((b & 0x7F) as u64) << shift;
        if b & 0x80 == 0 {
            return Ok((n, i + 1));
        }
        shift += 7;
        if shift >= 64 {
            return Err(Error::Invalid("varint overflow".into()));
        }
    }
    Err(Error::Invalid("varint truncated".into()))
}

pub fn did_web_to_url(did: &str) -> Result<String, Error> {
    let tail = did
        .strip_prefix("did:web:")
        .ok_or_else(|| Error::Invalid(format!("not a did:web: {did}")))?;
    let parts: Vec<String> = tail.split(':').map(percent_decode).collect();
    let host = parts.first().cloned().unwrap_or_default();
    if host.is_empty() {
        return Err(Error::Invalid("did:web missing host".into()));
    }
    let rest = &parts[1..];
    if rest.iter().any(|p| p.is_empty() || p == "." || p == "..") {
        return Err(Error::Invalid(format!(
            "did:web path segment rejected: {}",
            rest.join("/")
        )));
    }
    if rest.is_empty() {
        return Ok(format!("https://{host}/.well-known/did.json"));
    }
    Ok(format!("https://{host}/{}/did.json", rest.join("/")))
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) =
                (char::from(bytes[i + 1]).to_digit(16), char::from(bytes[i + 2]).to_digit(16))
            {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| s.to_string())
}

pub fn parse_ed25519_from_did_doc(doc: &Value, signer_did: &str) -> Result<[u8; 32], Error> {
    let methods = doc
        .get("verificationMethod")
        .and_then(|v| v.as_array())
        .ok_or_else(|| Error::Invalid("DID document has no verificationMethod".into()))?;
    for m in methods {
        let ctrl = m.get("controller").and_then(|v| v.as_str()).unwrap_or("");
        let id = m.get("id").and_then(|v| v.as_str()).unwrap_or("");
        let id_match = ctrl == signer_did || id.starts_with(&format!("{signer_did}#"));
        if !id_match {
            continue;
        }
        if m.get("type").and_then(|v| v.as_str()) != Some("Ed25519VerificationKey2020") {
            continue;
        }
        let mb = match m.get("publicKeyMultibase").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => continue,
        };
        // Same encoding as did:key.
        return did_key_to_pubkey(&format!("did:key:{mb}"));
    }
    Err(Error::Invalid(format!(
        "no Ed25519 verification method found for {signer_did}"
    )))
}
