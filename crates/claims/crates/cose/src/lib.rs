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
pub use coset;
pub use coset::{ContentType, CoseError, CoseSign1, Header, Label, ProtectedHeader};

pub use ciborium;
pub use ciborium::Value as CborValue;

pub mod key;
pub use key::CoseKey;

mod signature;
pub use signature::*;

mod verification;
pub use verification::*;

pub mod algorithm;

mod sign1;
pub use sign1::*;
