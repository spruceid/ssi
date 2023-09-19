mod error;
mod payload;
mod revocation;
mod util;
mod version;

pub use error::Error;
pub use payload::{capabilities, Payload, TimeInvalid};
pub use revocation::Revocation;
pub use util::{canonical_cid, get_verification_key};

use libipld::{codec::Codec, error::Error as IpldError, json::DagJsonCodec, serde::to_ipld};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use ssi_dids::did_resolve::DIDResolver;
use ssi_jwk::{Algorithm, JWK};
use ssi_jws::{decode_jws_parts, split_jws, verify_bytes, Header};

/// A deserialized UCAN
#[derive(Clone, PartialEq, Debug)]
pub struct Ucan<F = JsonValue, A = JsonValue> {
    algorithm: Algorithm,
    payload: Payload<F, A>,
    signature: Vec<u8>,
}

impl<F, A> Ucan<F, A> {
    /// Get the Header of the UCAN
    pub fn algorithm(&self) -> &Algorithm {
        &self.algorithm
    }

    /// Get the Payload of the UCAN
    pub fn payload(&self) -> &Payload<F, A> {
        &self.payload
    }

    /// Get the Signature of the UCAN
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    pub fn into_inner(self) -> (Algorithm, Payload<F, A>, Vec<u8>) {
        (self.algorithm, self.payload, self.signature)
    }

    /// Extract or resolve the JWK used to issue this UCAN, if possible
    pub async fn get_verification_key(&self, resolver: &dyn DIDResolver) -> Result<JWK, Error> {
        get_verification_key(&self.payload.issuer, resolver).await
    }

    /// Decode the UCAN and verify it's signature
    ///
    /// This method will resolve the DID of the issuer and verify the signature
    /// using their public key. This method works over a JWT as the original
    /// encoding is not retained by the UCAN struct.
    pub async fn decode_and_verify(jwt: &str, resolver: &dyn DIDResolver) -> Result<Self, Error>
    where
        F: for<'a> Deserialize<'a>,
        A: for<'a> Deserialize<'a>,
    {
        let ucan = Self::decode(jwt)?;
        let jwk = ucan.get_verification_key(resolver).await?;

        verify_bytes(
            ucan.algorithm,
            jwt.rsplit_once('.')
                .ok_or(ssi_jws::Error::InvalidJWS)?
                .0
                .as_bytes(),
            &jwk,
            &ucan.signature,
        )?;

        Ok(ucan)
    }

    /// Decode the UCAN
    pub fn decode(jwt: &str) -> Result<Self, Error>
    where
        F: for<'a> Deserialize<'a>,
        A: for<'a> Deserialize<'a>,
    {
        let parts = split_jws(jwt).and_then(|(h, p, s)| decode_jws_parts(h, p.as_bytes(), s))?;
        let payload: Payload<F, A> = serde_json::from_slice(&parts.payload)?;

        if parts.header.type_.as_deref() != Some("JWT") {
            return Err(Error::MissingUCANHeaderField("type: JWT"));
        }

        let algorithm = parts.header.algorithm;

        // header can only contain 'typ' and 'alg' fields
        if parts.header
            != (Header {
                algorithm,
                type_: Some("JWT".to_string()),
                ..Default::default()
            })
        {
            return Err(Error::InvalidHeaderEntries(parts.header));
        };

        // aud must be a DID
        if !payload.audience.starts_with("did:") {
            return Err(Error::DIDURL);
        }

        // iss must be a DID
        if !payload.issuer.starts_with("did:") {
            return Err(Error::DIDURL);
        }

        Ok(Self {
            algorithm,
            payload,
            signature: parts.signature,
        })
    }

    /// Encode the UCAN in canonicalized form, by encoding the JWS segments
    /// as JCS/DAG-JSON
    pub fn encode_as_canonicalized_jwt(&self) -> Result<String, Error>
    where
        F: Serialize,
        A: Serialize,
    {
        Ok([
            base64::encode_config(
                DagJsonCodec.encode(
                    &to_ipld(&Header {
                        algorithm: self.algorithm,
                        type_: Some("JWT".to_string()),
                        ..Default::default()
                    })
                    .map_err(IpldError::new)?,
                )?,
                base64::URL_SAFE_NO_PAD,
            ),
            base64::encode_config(
                DagJsonCodec.encode(&to_ipld(&self.payload).map_err(IpldError::new)?)?,
                base64::URL_SAFE_NO_PAD,
            ),
            base64::encode_config(&self.signature, base64::URL_SAFE_NO_PAD),
        ]
        .join("."))
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
