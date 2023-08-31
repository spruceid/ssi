mod error;
mod payload;
mod revocation;
mod util;
mod version;

pub use error::Error;
pub use libipld::Cid;
pub use payload::{capabilities, Payload, TimeInvalid};
pub use revocation::UcanRevocation;
pub use util::canonical_cid;

use libipld::{codec::Codec, error::Error as IpldError, json::DagJsonCodec, serde::to_ipld};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use ssi_dids::{
    did_resolve::{dereference, Content, DIDResolver},
    Resource, VerificationMethod,
};
use ssi_jwk::{Algorithm as Alg, JWK};
use ssi_jws::{split_jws, verify_bytes};
use varsig::{common::webauthn::AssertionSigData, VarSigTrait};

/// A deserialized UCAN
#[derive(Clone, PartialEq, Debug)]
pub struct Ucan<F = JsonValue, A = JsonValue> {
    signature: Signature,
    payload: Payload<F, A>,
}

impl<F, A> Ucan<F, A> {
    /// Get the signature of the UCAN
    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    /// Get the Payload of the UCAN
    pub fn payload(&self) -> &Payload<F, A> {
        &self.payload
    }

    pub fn into_inner(self) -> (Payload<F, A>, Signature) {
        (self.payload, self.signature)
    }

    /// Extract or resolve the JWK used to issue this UCAN
    pub async fn get_verification_key(&self, resolver: &dyn DIDResolver) -> Result<JWK, Error> {
        match (
            self.payload.issuer.get(..4),
            self.payload.issuer.get(4..8),
            dereference(resolver, &self.payload.issuer, &Default::default())
                .await
                .1,
        ) {
            // TODO here we will have some complicated cases w.r.t. did:pkh
            // some did:pkh's have recoverable signatures, some don't and will need
            // a query param on the did
            //
            // did:key without fragment
            (Some("did:"), Some("key:"), Content::DIDDocument(d)) => d
                .verification_method
                .iter()
                .flatten()
                .next()
                .and_then(|v| match v {
                    VerificationMethod::Map(vm) => Some(vm),
                    _ => None,
                })
                .ok_or(Error::VerificationMethodMismatch)?
                .get_jwk()
                .map_err(Error::from),
            // general case, did with fragment
            (Some("did:"), Some(_), Content::Object(Resource::VerificationMethod(vm))) => {
                Ok(vm.get_jwk()?)
            }
            _ => Err(Error::VerificationMethodMismatch),
        }
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
        use ssi_crypto::hashes::sha256::sha256;
        let ucan = Self::decode(jwt)?;
        let jwk = ucan.get_verification_key(resolver).await?;

        let signed = jwt
            .rsplit_once('.')
            .ok_or(ssi_jws::Error::InvalidJWS)?
            .0
            .as_bytes();

        match &ucan.signature {
            Signature::Passkey(s) => {
                let ccd = s.parse_client_data()?;
                if ccd.challenge != base64::encode_config(sha256(signed), base64::URL_SAFE_NO_PAD) {
                    return Err(Error::ChallengeMismatch);
                };
                verify_bytes(
                    jwk.algorithm.unwrap_or(Alg::ES256),
                    &[s.authenticator_data(), &sha256(s.client_data())].concat(),
                    &jwk,
                    &s.signature(),
                )
            }
            Signature::ES256(s) => verify_bytes(Alg::ES256, &signed, &jwk, s),
            Signature::ES512(s) => verify_bytes(Alg::ES256, &signed, &jwk, s),
            Signature::EdDSA(s) => verify_bytes(Alg::EdDSA, &signed, &jwk, s),
            Signature::RS256(s) => verify_bytes(Alg::RS256, &signed, &jwk, s),
            Signature::RS512(s) => verify_bytes(Alg::RS512, &signed, &jwk, s),
            Signature::ES256K(s) => verify_bytes(Alg::ES256K, &signed, &jwk, s),
        }?;

        Ok(ucan)
    }

    /// Decode the UCAN
    pub fn decode(jwt: &str) -> Result<Self, Error>
    where
        F: for<'a> Deserialize<'a>,
        A: for<'a> Deserialize<'a>,
    {
        let parts = split_jws(jwt)?;

        let h_bytes = base64::decode_config(parts.0, base64::URL_SAFE_NO_PAD)?;
        let header = serde_json::from_slice::<DummyHeader>(&h_bytes)?;

        // header can only contain 'typ' and 'alg' fields
        if header.typ != "JWT" {
            return Err(Error::InvalidHeaderEntries);
        };

        let payload: Payload<F, A> =
            serde_json::from_slice(&base64::decode_config(parts.1, base64::URL_SAFE_NO_PAD)?)?;

        // aud must be a DID
        if !payload.audience.starts_with("did:") {
            return Err(Error::DIDURL);
        }

        // iss must be a DID
        if !payload.issuer.starts_with("did:") {
            return Err(Error::DIDURL);
        }
        let sig = base64::decode_config(&parts.2, base64::URL_SAFE_NO_PAD)?;
        let algorithm = header.alg.alg();

        Ok(Self {
            payload,
            signature: match algorithm {
                None => Signature::Passkey(AssertionSigData::from_reader(&mut sig.as_slice())?),
                Some(a) => Signature::new_jws(a, sig)?,
            },
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
                    &to_ipld(&DummyHeader {
                        alg: (&self.signature).into(),
                        typ: "JWT",
                    })
                    .map_err(IpldError::new)?,
                )?,
                base64::URL_SAFE_NO_PAD,
            ),
            base64::encode_config(
                DagJsonCodec.encode(&to_ipld(&self.payload).map_err(IpldError::new)?)?,
                base64::URL_SAFE_NO_PAD,
            ),
            base64::encode_config(&self.signature.encode()?, base64::URL_SAFE_NO_PAD),
        ]
        .join("."))
    }
}

#[derive(Clone, PartialEq, Debug)]
pub enum Signature {
    ES256([u8; 64]),
    ES512([u8; 128]),
    EdDSA([u8; 64]),
    RS256(Vec<u8>),
    RS512(Vec<u8>),
    ES256K([u8; 64]),
    Passkey(AssertionSigData),
}

impl Signature {
    pub fn new_jws(alg: Alg, data: Vec<u8>) -> Result<Self, Error> {
        Ok(match alg {
            Alg::ES256 => Self::ES256(
                data.try_into()
                    .map_err(|_| Error::IncorrectSignatureLength)?,
            ),
            Alg::EdDSA => Self::EdDSA(
                data.try_into()
                    .map_err(|_| Error::IncorrectSignatureLength)?,
            ),
            Alg::RS256 => Self::RS256(data),
            Alg::RS512 => Self::RS512(data),
            Alg::ES256K => Self::ES256K(
                data.try_into()
                    .map_err(|_| Error::IncorrectSignatureLength)?,
            ),
            _ => return Err(Error::JWS(ssi_jws::Error::UnsupportedAlgorithm)),
        })
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum Algorithm {
    ES256,
    ES512,
    EdDSA,
    RS256,
    RS512,
    ES256K,
    Passkey,
}

impl Algorithm {
    pub fn alg(&self) -> Option<Alg> {
        Some(match self {
            Algorithm::ES256 => Alg::ES256,
            Algorithm::EdDSA => Alg::EdDSA,
            Algorithm::RS256 => Alg::RS256,
            Algorithm::RS512 => Alg::RS512,
            Algorithm::ES256K => Alg::ES256K,
            _ => None?,
        })
    }
}

impl Signature {
    fn encode(&self) -> Result<Vec<u8>, Error> {
        Ok(match self {
            Self::ES256(sig) => sig.to_vec(),
            Self::ES512(sig) => sig.to_vec(),
            Self::EdDSA(sig) => sig.to_vec(),
            Self::RS256(sig) => sig.to_vec(),
            Self::RS512(sig) => sig.to_vec(),
            Self::ES256K(sig) => sig.to_vec(),
            Self::Passkey(sig) => sig.to_vec()?,
        })
    }
}

impl From<&Signature> for Algorithm {
    fn from(alg: &Signature) -> Self {
        match alg {
            Signature::Passkey(_) => Algorithm::Passkey,
            Signature::ES256(_) => Algorithm::ES256,
            Signature::ES512(_) => Algorithm::ES512,
            Signature::EdDSA(_) => Algorithm::EdDSA,
            Signature::RS256(_) => Algorithm::RS256,
            Signature::RS512(_) => Algorithm::RS512,
            Signature::ES256K(_) => Algorithm::ES256K,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct DummyHeader<'t> {
    alg: Algorithm,
    typ: &'t str,
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
