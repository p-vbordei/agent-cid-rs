use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

pub fn verify_bytes(sig: &[u8], message: &[u8], pubkey: &[u8; 32]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(pubkey) else {
        return false;
    };
    let Ok(arr) = <[u8; 64]>::try_from(sig) else {
        return false;
    };
    let sig = Signature::from_bytes(&arr);
    vk.verify(message, &sig).is_ok()
}

pub fn b64encode(data: &[u8]) -> String {
    STANDARD.encode(data)
}

pub fn b64decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    STANDARD.decode(s.as_bytes())
}
