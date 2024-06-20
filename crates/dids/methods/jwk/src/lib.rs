use std::borrow::Cow;

use ssi_dids_core::{
    document::{
        self,
        representation::{self, MediaType},
        verification_method::DIDVerificationMethod,
        VerificationRelationships,
    },
    json_ld::syntax::ContextEntry,
    resolution::{DIDMethodResolver, Error, Metadata, Options, Output},
    DIDBuf, DIDMethod, DIDURLBuf, Document, RelativeDIDURLBuf, DID, DIDURL,
};
use ssi_jwk::JWK;
use ssi_verification_methods::ProofPurposes;
use static_iref::iri_ref;

pub const JSON_WEB_KEY_2020_TYPE: &str = "JsonWebKey2020";

/// DID version of the `JsonWebKey2020` verification method.
pub struct DIDJsonWebKey2020 {
    /// Verification method identifier.
    pub id: DIDURLBuf,

    // Key controller.
    pub controller: DIDBuf,

    /// Public key (`publicKeyJwk`).
    pub public_key: JWK,
}

impl DIDJsonWebKey2020 {
    pub fn new(id: DIDURLBuf, controller: DIDBuf, public_key: JWK) -> Self {
        Self {
            id,
            controller,
            public_key,
        }
    }
}

/// Error raised when the conversion to a [`DIDJsonWebKey2020`] failed.
#[derive(Debug, thiserror::Error)]
pub enum InvalidJsonWebKey2020 {
    #[error("invalid type")]
    InvalidType,

    #[error("missing public key")]
    MissingPublicKey,

    #[error("invalid public key")]
    InvalidPublicKey,

    #[error("invalid private key")]
    PrivateKey,
}

impl From<DIDJsonWebKey2020> for DIDVerificationMethod {
    fn from(value: DIDJsonWebKey2020) -> Self {
        let public_key = serde_json::to_value(&value.public_key).unwrap();
        DIDVerificationMethod::new(
            value.id,
            JSON_WEB_KEY_2020_TYPE.to_string(),
            value.controller,
            [("publicKeyJwk".to_string(), public_key)]
                .into_iter()
                .collect(),
        )
    }
}

impl TryFrom<DIDVerificationMethod> for DIDJsonWebKey2020 {
    type Error = InvalidJsonWebKey2020;

    fn try_from(mut value: DIDVerificationMethod) -> Result<Self, Self::Error> {
        if value.type_ == "JsonWebKey2020" {
            match value.properties.remove("publicKeyJwk") {
                Some(key_value) => match serde_json::from_value(key_value) {
                    Ok(public_key) => Ok(Self {
                        id: value.id,
                        controller: value.controller,
                        public_key,
                    }),
                    Err(_) => Err(InvalidJsonWebKey2020::InvalidPublicKey),
                },
                None => Err(InvalidJsonWebKey2020::MissingPublicKey),
            }
        } else {
            Err(InvalidJsonWebKey2020::InvalidType)
        }
    }
}

/// Reference to a `JsonWebKey2020` verification method description.
pub struct JsonWebKey2020Ref<'a> {
    pub id: &'a DIDURL,
    pub controller: &'a DID,
    pub public_key: Cow<'a, JWK>,
}

impl<'a> TryFrom<&'a DIDVerificationMethod> for JsonWebKey2020Ref<'a> {
    type Error = InvalidJsonWebKey2020;

    fn try_from(value: &'a DIDVerificationMethod) -> Result<Self, Self::Error> {
        if value.type_ == "JsonWebKey2020" {
            match value.properties.get("publicKeyJwk") {
                Some(key_value) => match serde_json::from_value(key_value.clone()) {
                    Ok(public_key) => Ok(Self {
                        id: &value.id,
                        controller: &value.controller,
                        public_key: Cow::Owned(public_key),
                    }),
                    Err(_) => Err(InvalidJsonWebKey2020::InvalidPublicKey),
                },
                None => Err(InvalidJsonWebKey2020::MissingPublicKey),
            }
        } else {
            Err(InvalidJsonWebKey2020::InvalidType)
        }
    }
}

/// JSON Web Token (`jwt`) DID method.
pub struct DIDJWK;

impl DIDJWK {
    /// Generates a JWK DID from the given key.
    ///
    /// Note: the resulting DID points to the DID document containing the key,
    /// not the key itself. Use [`Self::generate_url`] to generate a DID URL
    /// pointing to the key.
    ///
    /// # Example
    ///
    /// ```
    /// use did_jwk::DIDJWK;
    ///
    /// let jwk: ssi_jwk::JWK = serde_json::from_value(serde_json::json!({
    ///   "crv": "P-256",
    ///   "kty": "EC",
    ///   "x": "acbIQiuMs3i8_uszEjJ2tpTtRM4EU3yz91PH6CdH2V0",
    ///   "y": "_KcyLj9vWMptnmKtm46GqDz8wf74I5LKgrl2GzH3nSE"
    /// })).unwrap();
    ///
    /// let did = DIDJWK::generate(&jwk);
    /// assert_eq!(did, "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9");
    /// ```
    pub fn generate(key: &JWK) -> DIDBuf {
        let key = key.to_public();
        let normalized = serde_jcs::to_string(&key).unwrap();
        let method_id = multibase::Base::Base64Url.encode(normalized);
        DIDBuf::new(format!("did:jwk:{method_id}").into_bytes()).unwrap()
    }

    /// Generates a JWK DID URL referring to the given key.
    pub fn generate_url(key: &JWK) -> DIDURLBuf {
        let key = key.to_public();
        let normalized = serde_jcs::to_string(&key).unwrap();
        let method_id = multibase::Base::Base64Url.encode(normalized);
        DIDURLBuf::new(format!("did:jwk:{method_id}#0").into_bytes()).unwrap()
    }
}

impl DIDMethod for DIDJWK {
    const DID_METHOD_NAME: &'static str = "jwk";
}

impl DIDMethodResolver for DIDJWK {
    async fn resolve_method_representation<'a>(
        &'a self,
        method_specific_id: &'a str,
        options: Options,
    ) -> Result<Output<Vec<u8>>, Error> {
        resolve_method_representation(method_specific_id, options)
    }
}

fn resolve_method_representation(
    method_specific_id: &str,
    options: Options,
) -> Result<Output<Vec<u8>>, Error> {
    let data = multibase::Base::decode(&multibase::Base::Base64Url, method_specific_id)
        .map_err(|_| Error::InvalidMethodSpecificId(method_specific_id.to_string()))?;

    let jwk: JWK = serde_json::from_slice(&data)
        .map_err(|_| Error::InvalidMethodSpecificId(method_specific_id.to_string()))?;

    let public_jwk = jwk.to_public();

    if public_jwk != jwk {
        return Err(Error::InvalidMethodSpecificId(
            method_specific_id.to_string(),
        ));
    }

    let did = DIDBuf::new(format!("did:jwk:{method_specific_id}").into_bytes()).unwrap();

    let document = Document {
        verification_method: vec![DIDJsonWebKey2020::new(
            DIDURLBuf::new(format!("did:jwk:{method_specific_id}#0").into_bytes()).unwrap(),
            did.clone(),
            jwk,
        )
        .into()],
        verification_relationships: VerificationRelationships::from_reference(
            RelativeDIDURLBuf::new(b"#0".to_vec()).unwrap().into(),
            ProofPurposes::all(),
        ),
        ..Document::new(did)
    };

    let represented = document.into_representation(representation::Options::from_media_type(
        options.accept.unwrap_or(MediaType::JsonLd),
        || representation::json_ld::Options {
            context: representation::json_ld::Context::array(
                representation::json_ld::DIDContext::V1,
                vec![ContextEntry::IriRef(
                    iri_ref!("https://w3id.org/security/suites/jws-2020/v1").to_owned(),
                )],
            ),
        },
    ));

    Ok(Output::new(
        represented.to_bytes(),
        document::Metadata::default(),
        Metadata::from_content_type(Some(represented.media_type().to_string())),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssi_dids_core::{resolution, DIDResolver};

    #[async_std::test]
    async fn p256_roundtrip() {
        let jwk = JWK::generate_p256();
        let did_url = DIDJWK::generate_url(&jwk);
        let resolved = DIDJWK.dereference(&did_url).await.unwrap();

        let vm: JsonWebKey2020Ref = resolved
            .content
            .as_verification_method()
            .unwrap()
            .try_into()
            .unwrap();

        assert_eq!(*vm.public_key, jwk.to_public());
    }

    #[async_std::test]
    async fn from_p256() {
        let did_url = DIDURL::new(b"did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9#0").unwrap();
        let resolved = DIDJWK.dereference(did_url).await.unwrap();

        let vm: JsonWebKey2020Ref = resolved
            .content
            .as_verification_method()
            .unwrap()
            .try_into()
            .unwrap();

        assert_eq!(vm.id, did_url);
        assert_eq!(vm.controller, did_url.did());

        let jwk = serde_json::from_value(serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "acbIQiuMs3i8_uszEjJ2tpTtRM4EU3yz91PH6CdH2V0",
            "y": "_KcyLj9vWMptnmKtm46GqDz8wf74I5LKgrl2GzH3nSE"
        }))
        .unwrap();

        assert_eq!(vm.public_key, jwk);
    }

    #[async_std::test]
    async fn to_p256() {
        let jwk: ssi_jwk::JWK = serde_json::from_value(serde_json::json!({
            "crv": "P-256",
            "kty": "EC",
            "x": "acbIQiuMs3i8_uszEjJ2tpTtRM4EU3yz91PH6CdH2V0",
            "y": "_KcyLj9vWMptnmKtm46GqDz8wf74I5LKgrl2GzH3nSE"
        }))
        .unwrap();

        let expected = "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9";
        let did = DIDJWK::generate(&jwk);
        assert_eq!(did, expected);

        let resolved = DIDJWK
            .resolve_with(&did, resolution::Options::default())
            .await
            .unwrap();

        let vm_method: JsonWebKey2020Ref = resolved
            .document
            .verification_method
            .first()
            .unwrap()
            .try_into()
            .unwrap();

        assert_eq!(*vm_method.public_key, jwk);
    }

    #[async_std::test]
    async fn from_x25519() {
        let did_url = DIDURL::new(b"did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJYMjU1MTkiLCJ1c2UiOiJlbmMiLCJ4IjoiM3A3YmZYdDl3YlRUVzJIQzdPUTFOei1EUThoYmVHZE5yZngtRkctSUswOCJ9#0").unwrap();
        let resolved = DIDJWK.dereference(did_url).await.unwrap();

        let vm: JsonWebKey2020Ref = resolved
            .content
            .as_verification_method()
            .unwrap()
            .try_into()
            .unwrap();

        assert_eq!(vm.id, did_url);
        assert_eq!(vm.controller, did_url.did());

        let jwk = serde_json::from_value(serde_json::json!({
            "kty": "OKP",
            "crv": "X25519",
            "use": "enc",
            "x": "3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"
        }))
        .unwrap();
        assert_eq!(*vm.public_key, jwk);
    }

    #[async_std::test]
    async fn to_x25519() {
        let json = serde_json::json!({
            "kty": "OKP",
            "crv": "X25519",
            "use": "enc",
            "x": "3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"
        });

        let jwk: ssi_jwk::JWK = serde_json::from_value(json).unwrap();
        let expected = "did:jwk:eyJjcnYiOiJYMjU1MTkiLCJrdHkiOiJPS1AiLCJ1c2UiOiJlbmMiLCJ4IjoiM3A3YmZYdDl3YlRUVzJIQzdPUTFOei1EUThoYmVHZE5yZngtRkctSUswOCJ9";
        let did = DIDJWK::generate(&jwk);
        assert_eq!(did, expected);

        let resolved = DIDJWK
            .resolve_with(&did, resolution::Options::default())
            .await
            .unwrap();

        let vm_method: JsonWebKey2020Ref = resolved
            .document
            .verification_method
            .first()
            .unwrap()
            .try_into()
            .unwrap();

        assert_eq!(*vm_method.public_key, jwk);
    }

    #[async_std::test]
    async fn deny_private_key() {
        let jwk = JWK::generate_ed25519().unwrap();
        let json = serde_jcs::to_string(&jwk).unwrap();
        let json_encoded = multibase::Base::Base64Url.encode(&json);
        let did = DIDBuf::new(format!("did:jwk:{}", json_encoded).into_bytes()).unwrap();
        assert!(matches!(
            DIDJWK.resolve(&did).await.unwrap_err(),
            Error::InvalidMethodSpecificId(_)
        ),);
    }
}
