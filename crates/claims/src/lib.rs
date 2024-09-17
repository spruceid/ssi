//! Verifiable Claims.
use ::serde::{Deserialize, Serialize};
use data_integrity::{
    CloneCryptographicSuite, CryptographicSuite, DataIntegrity, DebugCryptographicSuite,
    DeserializeCryptographicSuite, SerializeCryptographicSuite,
};
use educe::Educe;
pub use ssi_claims_core::*;

/// JSON Web signature (JWS).
///
/// See: <https://datatracker.ietf.org/doc/html/rfc7515>
pub use ssi_jws as jws;

pub use jws::{Jws, JwsBuf, JwsPayload, JwsSlice, JwsStr, JwsString, JwsVec};

/// JSON Web tokens (JWT).
///
/// See: <https://datatracker.ietf.org/doc/html/rfc7519>
pub use ssi_jwt as jwt;

pub use jwt::JWTClaims;

/// Selective Disclosure for JWTs (SD-JWT).
///
/// See: <https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-08.html>
pub use ssi_sd_jwt as sd_jwt;

/// CBOR Object Signing and Encryption (COSE).
///
/// See: <https://www.rfc-editor.org/rfc/rfc8152.html>
pub use ssi_cose as cose;

/// W3C Verifiable Credentials (VC).
///
/// See: <https://www.w3.org/TR/vc-data-model>
pub use ssi_vc as vc;

/// Securing Verifiable Credentials using JOSE and COSE.
///
/// See: <https://www.w3.org/TR/vc-jose-cose>
pub use ssi_vc_jose_cose as vc_jose_cose;

/// Data-Integrity Proofs.
///
/// See: <https://www.w3.org/TR/vc-data-integrity>
pub use ssi_data_integrity as data_integrity;

/// JSON-like verifiable credential or JWS (presumably JWT).
#[derive(Educe, Serialize, Deserialize)]
#[serde(
    untagged,
    bound(
        serialize = "S: SerializeCryptographicSuite",
        deserialize = "S: DeserializeCryptographicSuite<'de>"
    )
)]
#[educe(Clone(bound("S: CloneCryptographicSuite")))]
#[educe(Debug(bound("S: DebugCryptographicSuite")))]
pub enum JsonCredentialOrJws<S: CryptographicSuite = data_integrity::AnySuite> {
    /// JSON-like verifiable credential.
    Credential(DataIntegrity<vc::AnyJsonCredential, S>),

    /// JSON Web Signature.
    Jws(jws::JwsString),
}

/// JSON-like verifiable presentation or JWS (presumably JWT).
#[derive(Educe, Serialize, Deserialize)]
#[serde(
    untagged,
    bound(
        serialize = "S: SerializeCryptographicSuite",
        deserialize = "S: DeserializeCryptographicSuite<'de>"
    )
)]
#[educe(Clone(bound("S: CloneCryptographicSuite")))]
#[educe(Debug(bound("S: DebugCryptographicSuite")))]
pub enum JsonPresentationOrJws<S: CryptographicSuite = data_integrity::AnySuite> {
    /// JSON-like verifiable presentation.
    Presentation(DataIntegrity<vc::AnyJsonPresentation, S>),

    /// JSON Web Signature.
    Jws(jws::JwsString),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_proof_without_created_vcdm11_json_ecdsa() {
        let _: DataIntegrity<vc::AnyJsonCredential, data_integrity::AnySuite> =
            serde_json::from_value(serde_json::json!({
              "@context": [
                "https://www.w3.org/2018/credentials/v1"
              ],
              "id": "urn:uuid:36245ee9-9074-4b05-a777-febff2e69757",
              "type": [
                "VerifiableCredential",
              ],
              "issuer": "did:example:issuer",
              "credentialSubject": {
                "id": "urn:uuid:1a0e4ef5-091f-4060-842e-18e519ab9440"
              },
              "proof": {
                "type": "DataIntegrityProof",
                "verificationMethod": "did:example:issuer#key1",
                "cryptosuite": "ecdsa-rdfc-2019",
                "proofPurpose": "assertionMethod",
                "proofValue": "sdfjlsdjflskdfj"
              }
            }))
            .unwrap();
    }

    #[test]
    fn accept_proof_without_created_vcdm2_json_or_jws_bbs() {
        let _: JsonCredentialOrJws = serde_json::from_value(serde_json::json!({
          "@context": [
            "https://www.w3.org/ns/credentials/v2"
          ],
          "id": "urn:uuid:36245ee9-9074-4b05-a777-febff2e69757",
          "type": [
            "VerifiableCredential",
          ],
          "issuer": "did:example:issuer",
          "credentialSubject": {
            "id": "urn:uuid:1a0e4ef5-091f-4060-842e-18e519ab9440"
          },
          "proof": {
            "type": "DataIntegrityProof",
            "verificationMethod": "did:example:issuer#key1",
            "cryptosuite": "bbs-2023",
            "proofPurpose": "assertionMethod",
            "proofValue": "sdfjlsdjflskdfj"
          }
        }))
        .unwrap();
    }
}
