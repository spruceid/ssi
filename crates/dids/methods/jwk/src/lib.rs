use ssi_dids_core::{
    document::{
        self,
        representation::{self, MediaType},
        verification_method::DIDVerificationMethod,
        VerificationRelationships,
    },
    resolution::{DIDMethodResolver, Error, Metadata, Options, Output},
    DIDBuf, DIDMethod, DIDURLBuf, Document, RelativeDIDURLBuf,
};
use ssi_jwk::JWK;
use ssi_verification_methods::ProofPurposes;

mod vm;
pub use vm::*;

/// Verification method returned by `did:jwk`.
pub struct VerificationMethod {
    pub type_: VerificationMethodType,

    /// Verification method identifier.
    pub id: DIDURLBuf,

    // Key controller.
    pub controller: DIDBuf,

    /// Public key.
    pub public_key: PublicKey,
}

impl VerificationMethod {
    pub fn new(
        type_: VerificationMethodType,
        id: DIDURLBuf,
        controller: DIDBuf,
        public_key: PublicKey,
    ) -> Self {
        Self {
            type_,
            id,
            controller,
            public_key,
        }
    }
}

impl From<VerificationMethod> for DIDVerificationMethod {
    fn from(value: VerificationMethod) -> Self {
        DIDVerificationMethod::new(
            value.id,
            value.type_.name().to_owned(),
            value.controller,
            [(
                value.public_key.property().to_owned(),
                value.public_key.into_json(),
            )]
            .into_iter()
            .collect(),
        )
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

    let vm_type = match options.parameters.public_key_format {
        Some(name) => VerificationMethodType::from_name(&name).ok_or_else(|| {
            Error::Internal(format!(
                "verification method type `{name}` unsupported by did:jwk"
            ))
        })?,
        None => VerificationMethodType::Multikey,
    };

    let public_key = vm_type.encode_public_key(jwk)?;

    let document = Document {
        verification_method: vec![VerificationMethod::new(
            vm_type,
            DIDURLBuf::new(format!("did:jwk:{method_specific_id}#0").into_bytes()).unwrap(),
            did.clone(),
            public_key,
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
                vec![vm_type.context_entry()],
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
    use ssi_dids_core::{resolution, DIDResolver, DIDURL};

    #[async_std::test]
    async fn p256_roundtrip() {
        let jwk = JWK::generate_p256();

        let expected_public_key = VerificationMethodType::Multikey
            .encode_public_key(jwk.clone())
            .unwrap()
            .into_json();

        let did_url = DIDJWK::generate_url(&jwk);
        let resolved = DIDJWK.dereference(&did_url).await.unwrap();

        let vm = resolved.content.as_verification_method().unwrap();

        let public_key = vm.properties.get("publicKeyMultibase").unwrap();

        assert_eq!(*public_key, expected_public_key);
    }

    #[async_std::test]
    async fn from_p256() {
        let did_url = DIDURL::new(b"did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9#0").unwrap();
        let resolved = DIDJWK.dereference(did_url).await.unwrap();

        let vm = resolved.content.as_verification_method().unwrap();

        let public_key = vm.properties.get("publicKeyMultibase").unwrap();

        assert_eq!(vm.id, did_url);
        assert_eq!(vm.controller, did_url.did());

        let jwk = serde_json::from_value(serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "acbIQiuMs3i8_uszEjJ2tpTtRM4EU3yz91PH6CdH2V0",
            "y": "_KcyLj9vWMptnmKtm46GqDz8wf74I5LKgrl2GzH3nSE"
        }))
        .unwrap();

        let expected_public_key = VerificationMethodType::Multikey
            .encode_public_key(jwk)
            .unwrap()
            .into_json();

        assert_eq!(*public_key, expected_public_key);
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

        let expected_public_key = VerificationMethodType::Multikey
            .encode_public_key(jwk.clone())
            .unwrap()
            .into_json();

        let expected = "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9";
        let did = DIDJWK::generate(&jwk);
        assert_eq!(did, expected);

        let resolved = DIDJWK
            .resolve_with(&did, resolution::Options::default())
            .await
            .unwrap();

        let vm = resolved.document.verification_method.first().unwrap();

        let public_key = vm.properties.get("publicKeyMultibase").unwrap();

        assert_eq!(*public_key, expected_public_key);
    }

    #[async_std::test]
    async fn from_x25519() {
        let did_url = DIDURL::new(b"did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJYMjU1MTkiLCJ1c2UiOiJlbmMiLCJ4IjoiM3A3YmZYdDl3YlRUVzJIQzdPUTFOei1EUThoYmVHZE5yZngtRkctSUswOCJ9#0").unwrap();

        let mut options = resolution::Options::default();
        options.parameters.public_key_format = Some("JsonWebKey2020".to_owned());

        let resolved = DIDJWK.dereference_with(did_url, options).await.unwrap();

        let vm = resolved.content.as_verification_method().unwrap();

        let public_key = vm.properties.get("publicKeyJwk").unwrap();

        assert_eq!(vm.id, did_url);
        assert_eq!(vm.controller, did_url.did());

        let jwk = serde_json::from_value(serde_json::json!({
            "kty": "OKP",
            "crv": "X25519",
            "use": "enc",
            "x": "3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"
        }))
        .unwrap();

        let expected_public_key = VerificationMethodType::JsonWebKey2020
            .encode_public_key(jwk)
            .unwrap()
            .into_json();

        assert_eq!(*public_key, expected_public_key);
    }

    #[async_std::test]
    async fn to_x25519() {
        let jwk: JWK = serde_json::from_value(serde_json::json!({
            "kty": "OKP",
            "crv": "X25519",
            "use": "enc",
            "x": "3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"
        }))
        .unwrap();

        let expected_public_key = VerificationMethodType::JsonWebKey2020
            .encode_public_key(jwk.clone())
            .unwrap()
            .into_json();

        let expected = "did:jwk:eyJjcnYiOiJYMjU1MTkiLCJrdHkiOiJPS1AiLCJ1c2UiOiJlbmMiLCJ4IjoiM3A3YmZYdDl3YlRUVzJIQzdPUTFOei1EUThoYmVHZE5yZngtRkctSUswOCJ9";
        let did = DIDJWK::generate(&jwk);
        assert_eq!(did, expected);

        let mut options = resolution::Options::default();
        options.parameters.public_key_format = Some("JsonWebKey2020".to_owned());

        let resolved = DIDJWK.resolve_with(&did, options).await.unwrap();

        let vm = resolved.document.verification_method.first().unwrap();

        let public_key = vm.properties.get("publicKeyJwk").unwrap();

        assert_eq!(*public_key, expected_public_key);
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
