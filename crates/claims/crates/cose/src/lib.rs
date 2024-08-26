//! CBOR Object Signing and Encryption ([COSE]) implementation based on
//! [`coset`].
//!
//! [COSE]: <https://datatracker.ietf.org/doc/html/rfc8152>
//! [`coset`]: <https://crates.io/crates/coset>
//!
//! # Usage
//!
//! ```
//! # #[async_std::main]
//! # async fn main() {
//! # #[cfg(feature = "secp256r1")] {
//! use std::borrow::Cow;
//! use serde::{Serialize, Deserialize};
//! use ssi_claims_core::{VerifiableClaims, ValidateClaims, VerificationParameters};
//! use ssi_cose::{CosePayload, ValidateCoseHeader, CoseSignatureBytes, DecodedCoseSign1, CoseKey, key::CoseKeyGenerate};
//!
//! // Our custom payload type.
//! #[derive(Serialize, Deserialize)]
//! struct CustomPayload {
//!   data: String
//! }
//!
//! // Define how the payload is encoded in COSE.
//! impl CosePayload for CustomPayload {
//!   // Serialize the payload as JSON.
//!   fn payload_bytes(&self) -> Cow<[u8]> {
//!     Cow::Owned(serde_json::to_vec(self).unwrap())
//!   }
//! }
//!
//! // Define how to validate the COSE header (always valid by default).
//! impl<P> ValidateCoseHeader<P> for CustomPayload {}
//!
//! // Define how to validate the payload (always valid by default).
//! impl<P> ValidateClaims<P, CoseSignatureBytes> for CustomPayload {}
//!
//! // Create a payload.
//! let payload = CustomPayload {
//!   data: "Some Data".to_owned()
//! };
//!
//! // Create a signature key.
//! let key = CoseKey::generate_p256(); // requires the `secp256r1` feature.
//!
//! // Sign the payload!
//! let bytes = payload.sign(
//!   &key,
//!   true // should the `COSE_Sign1` object be tagged or not.
//! ).await.unwrap();
//!
//! // Decode the signed COSE object.
//! let decoded: DecodedCoseSign1<CustomPayload> = bytes
//!     .decode(true)
//!     .unwrap()
//!     .try_map(|_, bytes| serde_json::from_slice(bytes))
//!     .unwrap();
//!
//! assert_eq!(decoded.signing_bytes.payload.data, "Some Data");
//!
//! // Verify the signature.
//! let params = VerificationParameters::from_resolver(&key);
//! decoded.verify(&params).await.unwrap();
//! # } }
//! ```
use ssi_claims_core::SignatureError;
use std::borrow::Cow;

pub use coset;
pub use coset::{ContentType, CoseError, CoseKey, CoseSign1, Header, Label, ProtectedHeader};

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
///
/// This trait defines how a custom type can be encoded and signed using COSE.
///
/// # Example
///
/// ```
/// use std::borrow::Cow;
/// use serde::{Serialize, Deserialize};
/// use ssi_cose::{CosePayload, CosePayloadType, ContentType};
///
/// // Our custom payload type.
/// #[derive(Serialize, Deserialize)]
/// struct CustomPayload {
///   data: String
/// }
///
/// // Define how the payload is encoded in COSE.
/// impl CosePayload for CustomPayload {
///   fn typ(&self) -> Option<CosePayloadType> {
///     Some(CosePayloadType::Text(
///       "application/json+cose".to_owned(),
///     ))
///   }
///   
///   fn content_type(&self) -> Option<ContentType> {
///     Some(ContentType::Text("application/json".to_owned()))
///   }
///
///   // Serialize the payload as JSON.
///   fn payload_bytes(&self) -> Cow<[u8]> {
///     Cow::Owned(serde_json::to_vec(self).unwrap())
///   }
/// }
/// ```
pub trait CosePayload {
    /// `typ` header parameter.
    ///
    /// See: <https://www.rfc-editor.org/rfc/rfc9596#section-2>
    fn typ(&self) -> Option<CosePayloadType> {
        None
    }

    /// Content type header parameter.
    fn content_type(&self) -> Option<ContentType> {
        None
    }

    /// Payload bytes.
    ///
    /// Returns the payload bytes representing this value.
    fn payload_bytes(&self) -> Cow<[u8]>;

    /// Sign the payload to produce a serialized `COSE_Sign1` object.
    ///
    /// The `tagged` flag specifies if the COSE object should be tagged or
    /// not.
    #[allow(async_fn_in_trait)]
    async fn sign(
        &self,
        signer: impl CoseSigner,
        tagged: bool,
    ) -> Result<CoseSign1BytesBuf, SignatureError> {
        signer.sign(self, None, tagged).await
    }
}

impl CosePayload for [u8] {
    fn payload_bytes(&self) -> Cow<[u8]> {
        Cow::Borrowed(self)
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
