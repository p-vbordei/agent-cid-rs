use serde_json::Value;

use crate::error::Error;

pub fn canonical_encode(value: &Value) -> Result<Vec<u8>, Error> {
    let s = serde_jcs::to_string(value).map_err(|e| Error::Invalid(format!("jcs: {e}")))?;
    Ok(s.into_bytes())
}
