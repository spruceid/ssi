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

pub const MEDIA_TYPE_VC_COSE: &str = "application/vc+cose";

pub const MEDIA_TYPE_VP_COSE: &str = "application/vp+cose";
