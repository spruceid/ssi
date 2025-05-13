mod credential;
pub use credential::*;

mod presentation;
pub use presentation::*;

/// Error that can occur when decoding a JOSE VC or VP.
#[derive(Debug, thiserror::Error)]
pub enum JoseDecodeError {
    /// JWS error.
    #[error(transparent)]
    JWS(#[from] ssi_jws::DecodeError),

    /// JSON payload error.
    #[error(transparent)]
    JSON(#[from] serde_json::Error),
}

pub const MEDIA_TYPE_VC_JWT: &str = "application/vc+jwt";

pub const MEDIA_TYPE_VP_JWT: &str = "application/vp+jwt";
