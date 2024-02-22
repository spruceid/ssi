//! Verifiable Claims.
use ::serde::{Deserialize, Serialize};
pub use ssi_claims_core::*;

/// JSON Web signature (JWS).
///
/// See: <https://datatracker.ietf.org/doc/html/rfc7515>
pub use ssi_jws as jws;

pub use jws::{CompactJWS, CompactJWSBuf, CompactJWSStr, CompactJWSString};

/// JSON Web tokens (JWT).
///
/// See: <https://datatracker.ietf.org/doc/html/rfc7519>
pub use ssi_jwt as jwt;

pub use jwt::JWTClaims;

/// W3C Verifiable Credentials (VC).
///
/// See: <https://www.w3.org/TR/vc-data-model>
pub use ssi_vc as vc;

pub use vc::{Credential, Presentation, VerifiableCredential, VerifiablePresentation};

/// Data-Integrity Proofs.
///
/// See: <https://www.w3.org/TR/vc-data-integrity>
pub use ssi_data_integrity as data_integrity;

/// JSON-like verifiable credential or JWS (presumably JWT).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum JsonCredentialOrJws<P = json_syntax::Value> {
    /// JSON-like verifiable credential.
    Credential(vc::JsonVerifiableCredential<P>),

    /// JSON Web Signature.
    Jws(jws::CompactJWSString),
}

// impl JsonCredentialOrJws {
// 	pub fn into_credential<P>(self) -> Result<vc::JsonVerifiableCredential<P>, JwtVcIntoCredentialError> {
// 		jwt::decode_unverified(jwt)
// 	}
// }

// pub enum JwtVcIntoCredentialError {
// 	// ...
// }
