use async_trait::async_trait;
use static_iref::iref;

use ssi_dids::{
    did_resolve::{
        DIDResolver, DocumentMetadata, ResolutionInputMetadata, ResolutionMetadata,
        ERROR_INVALID_DID, ERROR_NOT_FOUND,
    },
    Context, Contexts, DIDMethod, Document, Source, VerificationMethod, VerificationMethodMap,
    DEFAULT_CONTEXT, DIDURL,
};
use ssi_jwk::JWK;

pub struct DIDJWK;

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl DIDResolver for DIDJWK {
    async fn resolve(
        &self,
        did: &str,
        _input_metadata: &ResolutionInputMetadata,
    ) -> (
        ResolutionMetadata,
        Option<Document>,
        Option<DocumentMetadata>,
    ) {
        if !did.starts_with("did:jwk:") {
            return (
                ResolutionMetadata {
                    error: Some(ERROR_INVALID_DID.to_string()),
                    content_type: None,
                    property_set: None,
                },
                None,
                None,
            );
        }
        let method_specific_id = &did[8..];
        let data = match multibase::Base::decode(&multibase::Base::Base64Url, method_specific_id) {
            Ok(data) => data,
            Err(_err) => {
                return (
                    ResolutionMetadata {
                        error: Some(ERROR_INVALID_DID.to_string()),
                        content_type: None,
                        property_set: None,
                    },
                    None,
                    None,
                );
            }
        };

        let jwk: JWK = if let Ok(jwk) = serde_json::from_slice(&data) {
            jwk
        } else {
            return (
                ResolutionMetadata {
                    error: Some(ERROR_NOT_FOUND.to_string()),
                    content_type: None,
                    property_set: None,
                },
                None,
                None,
            );
        };

        let public_jwk = jwk.to_public();

        if public_jwk != jwk {
            return (
                ResolutionMetadata {
                    error: Some(ERROR_INVALID_DID.to_string()),
                    content_type: None,
                    property_set: None,
                },
                None,
                None,
            );
        }

        let vm_didurl = DIDURL {
            did: did.to_string(),
            fragment: Some("0".to_string()),
            ..Default::default()
        };
        let doc = Document {
            context: Contexts::Many(vec![
                Context::URI(DEFAULT_CONTEXT.into()),
                Context::URI(iref!("https://w3id.org/security/suites/jws-2020/v1").to_owned()),
            ]),
            id: did.to_string(),
            verification_method: Some(vec![VerificationMethod::Map(VerificationMethodMap {
                id: vm_didurl.to_string(),
                type_: "JsonWebKey2020".to_string(),
                controller: did.to_string(),
                public_key_jwk: Some(jwk),
                ..Default::default()
            })]),
            assertion_method: Some(vec![VerificationMethod::DIDURL(vm_didurl.clone())]),
            authentication: Some(vec![VerificationMethod::DIDURL(vm_didurl.clone())]),
            capability_invocation: Some(vec![VerificationMethod::DIDURL(vm_didurl.clone())]),
            capability_delegation: Some(vec![VerificationMethod::DIDURL(vm_didurl.clone())]),
            key_agreement: Some(vec![VerificationMethod::DIDURL(vm_didurl)]),
            ..Default::default()
        };
        (
            ResolutionMetadata::default(),
            Some(doc),
            Some(DocumentMetadata::default()),
        )
    }
}

impl DIDMethod for DIDJWK {
    fn name(&self) -> &'static str {
        "jwk"
    }

    fn generate(&self, source: &Source) -> Option<String> {
        let jwk = match source {
            Source::Key(jwk) => jwk,
            Source::KeyAndPattern(jwk, pattern) => {
                if !pattern.is_empty() {
                    // pattern not supported
                    return None;
                }
                jwk
            }
            _ => return None,
        };
        let jwk = jwk.to_public();
        let jwk = if let Ok(jwk) = serde_jcs::to_string(&jwk) {
            jwk
        } else {
            return None;
        };

        let did = "did:jwk:".to_string() + &multibase::encode(multibase::Base::Base64Url, jwk)[1..];
        Some(did)
    }

    fn to_resolver(&self) -> &dyn DIDResolver {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssi_dids::did_resolve::{dereference, Content, DereferencingInputMetadata};
    use ssi_dids::Resource;

    #[async_std::test]
    #[cfg(feature = "secp256r1")]
    async fn from_p256() {
        let vm = "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9#0";
        let (res_meta, object, _meta) =
            dereference(&DIDJWK, vm, &DereferencingInputMetadata::default()).await;
        assert_eq!(res_meta.error, None);
        let vm = match object {
            Content::Object(Resource::VerificationMethod(vm)) => vm,
            _ => unreachable!(),
        };

        assert_eq!(vm.id,  "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9#0" );
        assert_eq!(vm.type_, "JsonWebKey2020");
        assert_eq!(vm.controller, "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9");

        assert!(vm.public_key_jwk.is_some());
        let jwk = serde_json::from_value(serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "acbIQiuMs3i8_uszEjJ2tpTtRM4EU3yz91PH6CdH2V0",
            "y": "_KcyLj9vWMptnmKtm46GqDz8wf74I5LKgrl2GzH3nSE"
        }))
        .unwrap();
        assert_eq!(vm.public_key_jwk.unwrap(), jwk);
    }

    #[async_std::test]
    #[cfg(feature = "secp256r1")]
    async fn to_p256() {
        let jwk: ssi_jwk::JWK = serde_json::from_value(serde_json::json!({
            "crv": "P-256",
            "kty": "EC",
            "x": "acbIQiuMs3i8_uszEjJ2tpTtRM4EU3yz91PH6CdH2V0",
            "y": "_KcyLj9vWMptnmKtm46GqDz8wf74I5LKgrl2GzH3nSE"
        }))
        .unwrap();
        let expected = "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9";
        let did = DIDJWK.generate(&Source::Key(&jwk)).unwrap();
        assert_eq!(expected, did);

        let (res_meta, object, _meta) =
            dereference(&DIDJWK, &did, &DereferencingInputMetadata::default()).await;
        assert_eq!(res_meta.error, None);

        let public_key_jwk = match object {
            Content::DIDDocument(document) => match document.verification_method.as_deref() {
                Some(
                    [VerificationMethod::Map(VerificationMethodMap {
                        ref public_key_jwk, ..
                    })],
                ) => public_key_jwk.to_owned().unwrap(),
                _ => unreachable!(),
            },
            _ => unreachable!(),
        };
        assert_eq!(public_key_jwk, jwk);
    }

    #[async_std::test]
    async fn from_x25519() {
        let vm = "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJYMjU1MTkiLCJ1c2UiOiJlbmMiLCJ4IjoiM3A3YmZYdDl3YlRUVzJIQzdPUTFOei1EUThoYmVHZE5yZngtRkctSUswOCJ9#0";
        let (res_meta, object, _meta) =
            dereference(&DIDJWK, vm, &DereferencingInputMetadata::default()).await;
        assert_eq!(res_meta.error, None);
        let vm = match object {
            Content::Object(Resource::VerificationMethod(vm)) => vm,
            _ => unreachable!(),
        };

        assert_eq!(vm.id,  "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJYMjU1MTkiLCJ1c2UiOiJlbmMiLCJ4IjoiM3A3YmZYdDl3YlRUVzJIQzdPUTFOei1EUThoYmVHZE5yZngtRkctSUswOCJ9#0" );
        assert_eq!(vm.type_, "JsonWebKey2020");
        assert_eq!(vm.controller, "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJYMjU1MTkiLCJ1c2UiOiJlbmMiLCJ4IjoiM3A3YmZYdDl3YlRUVzJIQzdPUTFOei1EUThoYmVHZE5yZngtRkctSUswOCJ9");

        assert!(vm.public_key_jwk.is_some());
        let jwk = serde_json::from_value(serde_json::json!({
            "kty": "OKP",
            "crv": "X25519",
            "use": "enc",
            "x": "3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"
        }))
        .unwrap();
        assert_eq!(vm.public_key_jwk.unwrap(), jwk);
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
        let did = DIDJWK.generate(&Source::Key(&jwk)).unwrap();
        assert_eq!(expected, did);

        let (res_meta, object, _meta) =
            dereference(&DIDJWK, &did, &DereferencingInputMetadata::default()).await;
        assert_eq!(res_meta.error, None);

        let public_key_jwk = match object {
            Content::DIDDocument(document) => match document.verification_method.as_deref() {
                Some(
                    [VerificationMethod::Map(VerificationMethodMap {
                        ref public_key_jwk, ..
                    })],
                ) => public_key_jwk.to_owned().unwrap(),
                _ => unreachable!(),
            },
            _ => unreachable!(),
        };
        assert_eq!(public_key_jwk, jwk);
    }

    #[async_std::test]
    #[cfg(feature = "ed25519")]
    async fn deny_private_key() {
        let jwk = JWK::generate_ed25519().unwrap();
        let json = serde_jcs::to_string(&jwk).unwrap();
        let did =
            "did:jwk:".to_string() + &multibase::encode(multibase::Base::Base64Url, &json)[1..];

        let (res_meta, _object, _meta) =
            dereference(&DIDJWK, &did, &DereferencingInputMetadata::default()).await;
        assert!(res_meta.error.is_some());
    }
}
