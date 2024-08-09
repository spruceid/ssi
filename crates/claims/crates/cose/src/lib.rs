//! CBOR Object Signing and Encryption ([COSE]) implementation based on
//! [`coset`].
//!
//! [COSE]: <https://datatracker.ietf.org/doc/html/rfc8152>
//! [`coset`]: <https://crates.io/crates/coset>
use ssi_claims_core::SignatureError;
use std::borrow::Cow;

pub use coset;
pub use coset::{CoseError, CoseKey, CoseSign1, Header, Label, ProtectedHeader};

pub type ContentType = coset::RegisteredLabel<coset::iana::CoapContentFormat>;

pub use ciborium;
pub use ciborium::Value as CborValue;

pub mod key;

mod signature;
pub use signature::*;

mod verification;
pub use verification::*;

pub mod algorithm;

mod sign1;
pub use sign1::*;

/// COSE payload.
pub trait CosePayload {
    /// `typ` header parameter.
    ///
    /// See: <https://www.rfc-editor.org/rfc/rfc9596#section-2>
    fn typ(&self) -> Option<CosePayloadType> {
        None
    }

    fn content_type(&self) -> Option<ContentType> {
        None
    }

    fn payload_bytes(&self) -> Cow<[u8]>;

    /// Sign the payload to produce a `COSE_Sign1` object.
    #[allow(async_fn_in_trait)]
    async fn sign(
        &self,
        signer: impl CoseSigner,
        tagged: bool,
    ) -> Result<CompactCoseSign1Buf, SignatureError> {
        signer.sign(self, None, tagged).await
    }
}

pub const TYP_LABEL: Label = Label::Int(16);

/// COSE payload type.
///
/// Value of the `typ` header parameter.
///
/// See: <https://www.rfc-editor.org/rfc/rfc9596#section-2>
pub enum CosePayloadType {
    UInt(u64),
    Text(String),
}

impl From<CosePayloadType> for CborValue {
    fn from(ty: CosePayloadType) -> Self {
        match ty {
            CosePayloadType::UInt(i) => Self::Integer(i.into()),
            CosePayloadType::Text(t) => Self::Text(t),
        }
    }
}

/// COSE signature bytes.
pub struct CoseSignatureBytes(pub Vec<u8>);

impl CoseSignatureBytes {
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}
