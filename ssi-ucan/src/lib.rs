pub mod jose;
pub mod jwt;
mod payload;
mod revocation;
pub mod util;
mod version;

// pub use error::Error;
pub use payload::{capabilities, Payload, TimeInvalid};
pub use revocation::Revocation;
pub use util::*;

use serde_json::Value as JsonValue;
use ssi_dids::did_resolve::DIDResolver;
use ssi_jwk::JWK;

/// A deserialized UCAN
#[derive(Clone, PartialEq, Debug)]
pub struct Ucan<F = JsonValue, A = JsonValue, S = jose::Signature> {
    payload: Payload<F, A>,
    signature: S,
}

impl<F, A, S> Ucan<F, A, S> {
    /// Get the Payload of the UCAN
    pub fn payload(&self) -> &Payload<F, A> {
        &self.payload
    }

    pub fn signature(&self) -> &S {
        &self.signature
    }

    pub fn into_inner(self) -> (Payload<F, A>, S) {
        (self.payload, self.signature)
    }

    /// Extract or resolve the JWK used to issue this UCAN, if possible
    pub async fn get_verification_key(
        &self,
        resolver: &dyn DIDResolver,
    ) -> Result<JWK, ssi_dids::Error> {
        get_verification_key(&self.payload.issuer, resolver).await
    }

    /// Decode the UCAN
    pub fn decode<E>(
        encoded: <Self as UcanDecode<E>>::Encoded<'_>,
    ) -> Result<Self, <Self as UcanDecode<E>>::Error>
    where
        Self: UcanDecode<E>,
    {
        UcanDecode::<E>::decode(encoded)
    }

    /// Encode the UCAN
    pub fn encode<E>(
        &self,
    ) -> Result<<Self as UcanEncode<E>>::Encoded<'_>, <Self as UcanEncode<E>>::Error>
    where
        Self: UcanEncode<E>,
    {
        UcanEncode::<E>::encode(self)
    }
}

#[cfg(test)]
mod tests {
    use super::payload::now;
    use super::*;
    use did_method_key::DIDKey;
    use ssi_dids::{DIDMethod, Source};
    use ssi_jwk::Algorithm;

    #[async_std::test]
    async fn valid() {
        let cases: Vec<ValidTestVector> =
            serde_json::from_str(include_str!("../../tests/ucan-v0.10.0-valid.json")).unwrap();

        for case in cases {
            let ucan = Ucan::decode_and_verify(&case.token, DIDKey.to_resolver())
                .await
                .unwrap();

            assert_eq!(ucan.payload, case.assertions.payload);
            assert_eq!(ucan.algorithm, case.assertions.header.algorithm);
        }
    }

    #[async_std::test]
    async fn invalid() {
        let cases: Vec<InvalidTestVector> =
            serde_json::from_str(include_str!("../../tests/ucan-v0.10.0-invalid.json")).unwrap();
        for case in cases {
            match Ucan::<JsonValue>::decode(&case.token) {
                Ok(u) => {
                    if u.payload.validate_time::<u64>(None).is_ok()
                        && Ucan::<JsonValue>::decode_and_verify(&case.token, DIDKey.to_resolver())
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

        let ucan = payload.sign_canonicalized(Algorithm::EdDSA, &key).unwrap();

        let encoded = ucan.encode_as_canonicalized_jwt().unwrap();
        Ucan::<JsonValue>::decode_and_verify(&encoded, DIDKey.to_resolver())
            .await
            .unwrap();
    }

    #[derive(Deserialize)]
    struct ValidAssertions {
        pub header: Header,
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
