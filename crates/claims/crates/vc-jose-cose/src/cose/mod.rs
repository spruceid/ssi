use ssi_cose::CoseError;

mod credential;
pub use credential::*;

mod presentation;
pub use presentation::*;

#[derive(Debug, thiserror::Error)]
pub enum CoseDecodeError {
    #[error(transparent)]
    Decode(#[from] CoseError),

    #[error(transparent)]
    Payload(#[from] serde_json::Error),
}
