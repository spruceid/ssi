pub mod common;
mod error;
pub mod generic_jwt;
pub mod jose;
pub mod jwt;
mod payload;
mod revocation;
mod util;
mod version;
pub mod webauthn;

pub use error::Error;
pub use libipld::Cid;
pub use payload::{capabilities, Payload, TimeInvalid};
pub use revocation::UcanRevocation;
pub use ssi_dids::did_resolve::DIDResolver;
pub use ssi_jwk::JWK;
pub use util::{canonical_cid, get_verification_key};

use serde_json::Value as JsonValue;

/// A deserialized UCAN
#[derive(Clone, PartialEq, Debug)]
pub struct Ucan<S, F = JsonValue, A = JsonValue> {
    signature: S,
    payload: Payload<F, A>,
}

impl<S, F, A> Ucan<S, F, A> {
    /// Get the signature of the UCAN
    pub fn signature(&self) -> &S {
        &self.signature
    }

    /// Get the Payload of the UCAN
    pub fn payload(&self) -> &Payload<F, A> {
        &self.payload
    }

    pub fn into_inner(self) -> (Payload<F, A>, S) {
        (self.payload, self.signature)
    }

    /// Extract or resolve the public key used to issue this UCAN in JWK form
    pub async fn get_verification_key(&self, resolver: &dyn DIDResolver) -> Result<JWK, Error> {
        get_verification_key(&self.payload.issuer, resolver).await
    }
}

#[cfg(test)]
mod tests {
    use super::payload::now;
    use super::*;
    use crate::jwt::{UcanDecode, UcanEncode};
    use did_method_key::DIDKey;
    use serde::Deserialize;
    use ssi_dids::{DIDMethod, Source};
    use ssi_jwk::Algorithm;

    type JoseUcan = Ucan<jose::Signature>;

    #[async_std::test]
    async fn valid() {
        let cases: Vec<ValidTestVector> =
            serde_json::from_str(include_str!("../../tests/ucan-v0.10.0-valid.json")).unwrap();

        for case in cases {
            let ucan = JoseUcan::decode_and_verify(&case.token, DIDKey.to_resolver())
                .await
                .unwrap();

            assert_eq!(ucan.payload, case.assertions.payload);
            assert_eq!(ucan.signature.alg(), case.assertions.header.alg);
        }
    }

    #[async_std::test]
    async fn invalid() {
        let cases: Vec<InvalidTestVector> =
            serde_json::from_str(include_str!("../../tests/ucan-v0.10.0-invalid.json")).unwrap();
        for case in cases {
            match JoseUcan::decode(&case.token) {
                Ok(u) => {
                    if u.payload.validate_time::<u64>(None).is_ok()
                        && Ucan::<jose::Signature, JsonValue>::decode_and_verify(
                            &case.token,
                            DIDKey.to_resolver(),
                        )
                        .await
                        .is_ok()
                    {
                        assert!(false, "{}", case.comment);
                    }
                }
                Err(_e) => {}
            };
        }
    }

    #[async_std::test]
    async fn basic() {
        let key = JWK::generate_ed25519().unwrap();
        let iss = DIDKey.generate(&Source::Key(&key)).unwrap();
        let aud = "did:example:123".to_string();
        let mut payload = Payload::<JsonValue, JsonValue>::new(iss, aud);
        payload.expiration = Some(now() + 60);
        payload.not_before = Some(now() - 60);
        payload
            .capabilities
            .with_action_convert("https://example.com/resource", "https/get", [])
            .unwrap();
        payload.proof = Some(vec![canonical_cid("hello")]);

        let ucan = payload
            .sign_canonicalized_jws(Algorithm::EdDSA, &key)
            .unwrap();

        let encoded = ucan.encode().unwrap();
        JoseUcan::decode_and_verify(&encoded, DIDKey.to_resolver())
            .await
            .unwrap();
    }

    #[derive(Deserialize)]
    struct ValidAssertions {
        pub header: jwt::DummyHeader<Algorithm>,
        pub payload: Payload,
    }

    #[derive(Deserialize)]
    struct ValidTestVector {
        pub token: String,
        pub assertions: ValidAssertions,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct InvalidAssertions {
        pub header: Option<JsonValue>,
        pub payload: Option<JsonValue>,
        pub type_errors: Option<Vec<String>>,
        pub validation_errors: Option<Vec<String>>,
    }

    #[derive(Deserialize)]
    struct InvalidTestVector {
        pub comment: String,
        pub token: String,
        pub assertions: InvalidAssertions,
    }
}
