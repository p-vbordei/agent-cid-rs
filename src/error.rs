use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Invalid(String),
    #[error("http error: {0}")]
    Http(String),
    #[error("did:web fetch {0}: HTTP {1}")]
    DidWebHttp(String, u16),
    #[error("did:web doc size {size} > limit {limit}")]
    DidWebTooLarge { size: usize, limit: usize },
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}
