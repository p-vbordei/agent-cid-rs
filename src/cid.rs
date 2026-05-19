use data_encoding::BASE32_NOPAD;
use sha2::{Digest, Sha256};

const CID_VERSION: u8 = 0x01;
const CODEC_RAW: u8 = 0x55;
const MULTIHASH_SHA256: u8 = 0x12;
const DIGEST_LEN: u8 = 0x20;

pub fn bytes_to_cid(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest: [u8; 32] = hasher.finalize().into();
    let mut buf = Vec::with_capacity(4 + 32);
    buf.push(CID_VERSION);
    buf.push(CODEC_RAW);
    buf.push(MULTIHASH_SHA256);
    buf.push(DIGEST_LEN);
    buf.extend_from_slice(&digest);
    let b32 = BASE32_NOPAD.encode(&buf).to_lowercase();
    format!("b{b32}")
}

pub fn verify_cid(cid: &str, data: &[u8]) -> bool {
    bytes_to_cid(data) == cid
}
