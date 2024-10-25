//! The did:key Method v0.7.
//!
//! See: <https://w3c-ccg.github.io/did-method-key>
use multibase::Base;
use ssi_dids_core::{
    document::{
        self,
        representation::{self, MediaType},
        verification_method::ValueOrReference,
        DIDVerificationMethod,
    },
    resolution::{self, DIDMethodResolver, Error},
    DIDBuf, DIDMethod, DIDURLBuf, Document,
};
use ssi_jwk::JWK;
use ssi_multicodec::MultiEncodedBuf;
use static_iref::{iri, iri_ref};
use std::collections::BTreeMap;

/// The did:key Method v0.7.
///
/// See: <https://w3c-ccg.github.io/did-method-key>
pub struct DIDKey;

impl DIDKey {
    pub fn generate(jwk: &JWK) -> Result<DIDBuf, GenerateError> {
        let multi_encoded = jwk.to_multicodec()?;
        let id = multibase::encode(multibase::Base::Base58Btc, multi_encoded.into_bytes());

        Ok(DIDBuf::from_string(format!("did:key:{id}")).unwrap())
    }

    pub fn generate_url(jwk: &JWK) -> Result<DIDURLBuf, GenerateError> {
        let multi_encoded = jwk.to_multicodec()?;
        let id = multibase::encode(multibase::Base::Base58Btc, multi_encoded.into_bytes());

        Ok(DIDURLBuf::from_string(format!("did:key:{id}#{id}")).unwrap())
    }
}

pub type GenerateError = ssi_jwk::ToMulticodecError;

impl DIDMethod for DIDKey {
    const DID_METHOD_NAME: &'static str = "key";
}

impl DIDMethodResolver for DIDKey {
    async fn resolve_method_representation<'a>(
        &'a self,
        id: &'a str,
        options: resolution::Options,
    ) -> Result<resolution::Output<Vec<u8>>, Error> {
        let did = DIDBuf::from_string(format!("did:key:{id}")).unwrap();

        let (_base, data) =
            multibase::decode(id).map_err(|_| Error::InvalidMethodSpecificId(id.to_owned()))?;

        let multi_encoded = MultiEncodedBuf::new(data)
            .map_err(|_| Error::InvalidMethodSpecificId(id.to_owned()))?;

        let vm_type = match options.parameters.public_key_format {
            Some(name) => VerificationMethodType::from_name(&name).ok_or_else(|| {
                Error::Internal(format!(
                    "verification method type `{name}` unsupported by did:key"
                ))
            })?,
            None => VerificationMethodType::Multikey,
        };

        let public_key = vm_type.decode(id, multi_encoded)?;

        let vm_didurl = DIDURLBuf::from_string(format!("{did}#{id}")).unwrap();

        let mut doc = Document::new(did.to_owned());
        doc.verification_method.push(
            VerificationMethod {
                id: vm_didurl.clone(),
                type_: vm_type,
                controller: did,
                public_key,
            }
            .into(),
        );
        doc.verification_relationships
            .authentication
            .push(ValueOrReference::Reference(vm_didurl.clone().into()));
        doc.verification_relationships
            .assertion_method
            .push(ValueOrReference::Reference(vm_didurl.into()));

        let mut json_ld_context = Vec::new();
        if let Some(context) = vm_type.context_entry() {
            json_ld_context.push(context)
        }

        let content_type = options.accept.unwrap_or(MediaType::JsonLd);
        let represented = doc.into_representation(representation::Options::from_media_type(
            content_type,
            move || representation::json_ld::Options {
                context: representation::json_ld::Context::array(
                    representation::json_ld::DIDContext::V1,
                    json_ld_context,
                ),
            },
        ));

        Ok(resolution::Output::new(
            represented.to_bytes(),
            document::Metadata::default(),
            resolution::Metadata::from_content_type(Some(content_type.to_string())),
        ))
    }
}

#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum VerificationMethodType {
    Multikey,
    Ed25519VerificationKey2020,
    Ed25519VerificationKey2018,
    #[cfg(feature = "secp256k1")]
    EcdsaSecp256k1VerificationKey2019,
    EcdsaSecp256r1VerificationKey2019,
    JsonWebKey2020,
    #[cfg(feature = "bbs")]
    Bls12381G2Key2020,
}

impl VerificationMethodType {
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "Multikey" => Some(Self::Multikey),
            "Ed25519VerificationKey2020" => Some(Self::Ed25519VerificationKey2020),
            "Ed25519VerificationKey2018" => Some(Self::Ed25519VerificationKey2018),
            #[cfg(feature = "secp256k1")]
            "EcdsaSecp256k1VerificationKey2019" => Some(Self::EcdsaSecp256k1VerificationKey2019),
            "EcdsaSecp256r1VerificationKey2019" => Some(Self::EcdsaSecp256r1VerificationKey2019),
            "JsonWebKey2020" => Some(Self::JsonWebKey2020),
            #[cfg(feature = "bbs")]
            "Bls12381G2Key2020" => Some(Self::Bls12381G2Key2020),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Multikey => "Multikey",
            Self::Ed25519VerificationKey2020 => "Ed25519VerificationKey2020",
            Self::Ed25519VerificationKey2018 => "Ed25519VerificationKey2018",
            #[cfg(feature = "secp256k1")]
            Self::EcdsaSecp256k1VerificationKey2019 => "EcdsaSecp256k1VerificationKey2019",
            Self::EcdsaSecp256r1VerificationKey2019 => "EcdsaSecp256r1VerificationKey2019",
            Self::JsonWebKey2020 => "JsonWebKey2020",
            #[cfg(feature = "bbs")]
            Self::Bls12381G2Key2020 => "Bls12381G2Key2020",
        }
    }

    #[allow(unused_variables)]
    pub fn decode(&self, id: &str, encoded: MultiEncodedBuf) -> Result<PublicKey, Error> {
        match self {
            Self::Multikey => {
                let multibase_encoded = multibase::encode(Base::Base58Btc, encoded.as_bytes());
                Ok(PublicKey::Multibase(multibase_encoded))
            }
            Self::Ed25519VerificationKey2020 => match encoded.codec() {
                ssi_multicodec::ED25519_PUB => {
                    let multibase_encoded = multibase::encode(Base::Base58Btc, encoded.as_bytes());
                    Ok(PublicKey::Multibase(multibase_encoded))
                }
                _ => Err(Error::internal("did:key is not ED25519 as required by method type `Ed25519VerificationKey2020`")),
            }
            Self::Ed25519VerificationKey2018 => match encoded.codec() {
                ssi_multicodec::ED25519_PUB => {
                    let key = bs58::encode(encoded.data()).into_string();
                    Ok(PublicKey::Base58(key))
                }
                _ => Err(Error::internal("did:key is not ED25519 as required by method type `Ed25519VerificationKey2018`")),
            }
            #[cfg(feature = "secp256k1")]
            Self::EcdsaSecp256k1VerificationKey2019 => match encoded.codec() {
                ssi_multicodec::SECP256K1_PUB => {
                    match ssi_jwk::secp256k1_parse(encoded.data()) {
                        Ok(jwk) => Ok(PublicKey::Jwk(Box::new(jwk))),
                        Err(_) => Err(Error::InvalidMethodSpecificId(id.to_owned())),
                    }
                }
                _ => Err(Error::internal("did:key is not SECP256K1 as required by method type `EcdsaSecp256k1VerificationKey2019`")),
            }
            Self::EcdsaSecp256r1VerificationKey2019 => match encoded.codec() {
                ssi_multicodec::P256_PUB => {
                    let multibase_encoded = multibase::encode(Base::Base58Btc, encoded.as_bytes());
                    Ok(PublicKey::Multibase(multibase_encoded))
                }
                _ => Err(Error::internal("did:key is not P256 as required by method type `EcdsaSecp256r1VerificationKey2019`")),
            }
            Self::JsonWebKey2020 => {
                let key = JWK::from_multicodec(&encoded)
                    .map_err(Error::internal)?;
                Ok(PublicKey::Jwk(Box::new(key)))
            }
            #[cfg(feature = "bbs")]
            Self::Bls12381G2Key2020 => match encoded.codec() {
                ssi_multicodec::BLS12_381_G2_PUB => {
                    let jwk = ssi_jwk::bls12381g2_parse(encoded.data()).map_err(Error::internal)?;
                    // https://datatracker.ietf.org/doc/html/draft-denhartog-pairing-curves-jose-cose-00#section-3.1.3
                    // FIXME: This should be a base 58 key according to the spec.
                    Ok(PublicKey::Jwk(Box::new(jwk)))
                }
                _ => Err(Error::internal("did:key is not BLS12_381_G2 as required by method type `Bls12381G2Key2020`")),
            }
        }
    }

    pub fn context_entry(&self) -> Option<ssi_json_ld::syntax::ContextEntry> {
        use ssi_json_ld::syntax::{
            context::{
                term_definition::{Expanded, Id, Type, TypeKeyword},
                Definition, TermDefinition,
            },
            ContextEntry, Nullable,
        };
        match self {
            Self::Multikey => Some(ContextEntry::IriRef(
                iri_ref!("https://w3id.org/security/multikey/v1").to_owned(),
            )),
            Self::Ed25519VerificationKey2020 => Some(ContextEntry::IriRef(
                iri_ref!("https://w3id.org/security/suites/ed25519-2020/v1").to_owned(),
            )),
            Self::Ed25519VerificationKey2018 => Some(ContextEntry::IriRef(
                iri_ref!("https://w3id.org/security/suites/ed25519-2018/v1").to_owned(),
            )),
            #[cfg(feature = "secp256k1")]
            Self::EcdsaSecp256k1VerificationKey2019 => {
                let mut definition = Definition::new();
                definition.bindings.insert(
                    "EcdsaSecp256k1VerificationKey2019".into(),
                    TermDefinition::Simple(
                        iri!("https://w3id.org/security#EcdsaSecp256k1VerificationKey2019")
                            .to_owned()
                            .into(),
                    )
                    .into(),
                );
                definition.bindings.insert(
                    "publicKeyJwk".into(),
                    TermDefinition::Expanded(Box::new(Expanded {
                        id: Some(Nullable::Some(Id::Term(
                            iri!("https://w3id.org/security#publicKeyJwk")
                                .to_owned()
                                .into_string(),
                        ))),
                        type_: Some(Nullable::Some(Type::Keyword(TypeKeyword::Json))),
                        ..Default::default()
                    }))
                    .into(),
                );
                Some(ContextEntry::Definition(definition))
            }
            Self::EcdsaSecp256r1VerificationKey2019 => {
                let mut definition = Definition::new();
                definition.bindings.insert(
                    "EcdsaSecp256r1VerificationKey2019".into(),
                    TermDefinition::Simple(
                        iri!("https://w3id.org/security#EcdsaSecp256r1VerificationKey2019")
                            .to_owned()
                            .into(),
                    )
                    .into(),
                );
                definition.bindings.insert(
                    "publicKeyMultibase".into(),
                    TermDefinition::Expanded(Box::new(Expanded {
                        id: Some(Nullable::Some(Id::Term(
                            iri!("https://w3id.org/security#publicMultibase")
                                .to_owned()
                                .into_string(),
                        ))),
                        type_: Some(Nullable::Some(Type::Keyword(TypeKeyword::Json))),
                        ..Default::default()
                    }))
                    .into(),
                );
                Some(ContextEntry::Definition(definition))
            }
            Self::JsonWebKey2020 => Some(ContextEntry::IriRef(
                iri_ref!("https://w3id.org/security/suites/jws-2020/v1").to_owned(),
            )),
            #[cfg(feature = "bbs")]
            Self::Bls12381G2Key2020 => {
                let mut definition = Definition::new();
                definition.bindings.insert(
                    "Bls12381G2Key2020".into(),
                    TermDefinition::Simple(
                        iri!("https://w3id.org/security#Bls12381G2Key2020")
                            .to_owned()
                            .into(),
                    )
                    .into(),
                );
                definition.bindings.insert(
                    "publicKeyJwk".into(),
                    TermDefinition::Expanded(Box::new(Expanded {
                        id: Some(Nullable::Some(Id::Term(
                            iri!("https://w3id.org/security#publicKeyJwk")
                                .to_owned()
                                .into_string(),
                        ))),
                        type_: Some(Nullable::Some(Type::Keyword(TypeKeyword::Json))),
                        ..Default::default()
                    }))
                    .into(),
                );
                Some(ContextEntry::Definition(definition))
            }
        }
    }
}

pub struct VerificationMethod {
    id: DIDURLBuf,
    type_: VerificationMethodType,
    controller: DIDBuf,
    public_key: PublicKey,
}

impl From<VerificationMethod> for DIDVerificationMethod {
    fn from(value: VerificationMethod) -> Self {
        let mut properties = BTreeMap::new();

        match value.public_key {
            PublicKey::Jwk(jwk) => {
                properties.insert(
                    "publicKeyJwk".to_owned(),
                    serde_json::to_value(jwk).unwrap(),
                );
            }
            PublicKey::Base58(key) => {
                properties.insert("publicKeyBase58".to_owned(), key.into());
            }
            PublicKey::Multibase(key) => {
                properties.insert("publicKeyMultibase".to_owned(), key.into());
            }
        }

        Self {
            id: value.id,
            type_: value.type_.name().to_owned(),
            controller: value.controller,
            properties,
        }
    }
}

pub enum PublicKey {
    Jwk(Box<JWK>),
    Base58(String),
    Multibase(String),
}

#[cfg(test)]
mod tests {
    use rand_chacha::rand_core::SeedableRng;
    use resolution::Parameters;
    use ssi_claims::{
        data_integrity::{AnyInputSuiteOptions, AnySuite},
        vc::{syntax::NonEmptyVec, v1::JsonCredential},
        VerificationParameters,
    };
    use ssi_data_integrity::{CryptographicSuite, ProofOptions as SuiteOptions};
    use ssi_dids_core::{
        did, resolution::Options, DIDResolver, VerificationMethodDIDResolver, DIDURL,
    };
    use ssi_jwk::JWKResolver;
    use ssi_verification_methods::AnyMethod;
    use ssi_verification_methods_core::{ProofPurpose, ReferenceOrOwned, SingleSecretSigner};
    use static_iref::uri;

    use super::*;

    #[async_std::test]
    async fn from_did_key() {
        let did_url = DIDURL::new(b"did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH").unwrap();
        let output = DIDKey.dereference(did_url).await.unwrap();
        let vm = output.content.into_verification_method().unwrap();
        eprintln!("vm = {}", serde_json::to_string_pretty(&vm).unwrap());
        vm.properties.get("publicKeyMultibase").unwrap();
    }

    #[async_std::test]
    async fn from_did_key_with_format() {
        let did_url = DIDURL::new(b"did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH").unwrap();
        let output = DIDKey
            .dereference_with(
                did_url,
                Options {
                    accept: None,
                    parameters: Parameters {
                        public_key_format: Some("Ed25519VerificationKey2018".to_string()),
                        ..Default::default()
                    },
                },
            )
            .await
            .unwrap();
        let vm = output.content.into_verification_method().unwrap();
        vm.properties.get("publicKeyBase58").unwrap();
    }

    #[async_std::test]
    #[cfg(feature = "secp256k1")]
    async fn from_did_key_secp256k1() {
        let did = did!("did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme");
        DIDKey.resolve(did).await.unwrap();

        let did_url = DIDURL::new(b"did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme#zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme").unwrap();
        let output = DIDKey
            .dereference_with(
                did_url,
                Options {
                    accept: None,
                    parameters: Parameters {
                        public_key_format: Some("EcdsaSecp256k1VerificationKey2019".to_string()),
                        ..Default::default()
                    },
                },
            )
            .await
            .unwrap();
        let mut vm = output.content.into_verification_method().unwrap();
        let key: JWK =
            serde_json::from_value(vm.properties.remove("publicKeyJwk").unwrap()).unwrap();

        // convert back to DID from JWK
        let did1 = DIDKey::generate(&key).unwrap();
        assert_eq!(did1, did);
    }

    #[cfg(feature = "secp256r1")]
    #[async_std::test]
    async fn from_did_key_p256() {
        // https://w3c-ccg.github.io/did-method-key/#p-256
        let did = did!("did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169");
        DIDKey.resolve(did).await.unwrap();

        let did_url = DIDURL::new(b"did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169#zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169").unwrap();
        let output = DIDKey
            .dereference_with(
                did_url,
                Options {
                    accept: None,
                    parameters: Parameters {
                        public_key_format: Some("EcdsaSecp256r1VerificationKey2019".to_string()),
                        ..Default::default()
                    },
                },
            )
            .await
            .unwrap();
        let vm = output.content.into_verification_method().unwrap();
        let multibase_key = vm
            .properties
            .get("publicKeyMultibase")
            .unwrap()
            .as_str()
            .unwrap();
        let (base, encoded_key) = multibase::decode(multibase_key).unwrap();
        assert_eq!(base, multibase::Base::Base58Btc);
        let encoded_key = ssi_multicodec::MultiEncodedBuf::new(encoded_key).unwrap();
        assert_eq!(encoded_key.codec(), ssi_multicodec::P256_PUB);
        let key = ssi_jwk::JWK::from_multicodec(&encoded_key).unwrap();
        eprintln!("key {}", serde_json::to_string_pretty(&key).unwrap());

        // https://github.com/w3c-ccg/did-method-key/blob/master/test-vectors/nist-curves.json#L64-L69
        let key_expected: JWK = serde_json::from_value(serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "fyNYMN0976ci7xqiSdag3buk-ZCwgXU4kz9XNkBlNUI",
            "y": "hW2ojTNfH7Jbi8--CJUo3OCbH3y5n91g-IMA9MLMbTU"
        }))
        .unwrap();
        assert_eq!(key, key_expected);

        let did1 = DIDKey::generate(&key).unwrap();
        assert_eq!(did1, did);
    }

    #[cfg(feature = "bbs")]
    #[async_std::test]
    async fn from_did_key_bls() {
        // https://w3c-ccg.github.io/did-method-key/#bls-12381
        let did = did!("did:key:zUC7K4ndUaGZgV7Cp2yJy6JtMoUHY6u7tkcSYUvPrEidqBmLCTLmi6d5WvwnUqejscAkERJ3bfjEiSYtdPkRSE8kSa11hFBr4sTgnbZ95SJj19PN2jdvJjyzpSZgxkyyxNnBNnY");
        DIDKey.resolve(did).await.unwrap();

        let did_url = DIDURL::new(b"did:key:zUC7K4ndUaGZgV7Cp2yJy6JtMoUHY6u7tkcSYUvPrEidqBmLCTLmi6d5WvwnUqejscAkERJ3bfjEiSYtdPkRSE8kSa11hFBr4sTgnbZ95SJj19PN2jdvJjyzpSZgxkyyxNnBNnY#zUC7K4ndUaGZgV7Cp2yJy6JtMoUHY6u7tkcSYUvPrEidqBmLCTLmi6d5WvwnUqejscAkERJ3bfjEiSYtdPkRSE8kSa11hFBr4sTgnbZ95SJj19PN2jdvJjyzpSZgxkyyxNnBNnY").unwrap();
        let output = DIDKey
            .dereference_with(
                did_url,
                Options {
                    accept: None,
                    parameters: Parameters {
                        public_key_format: Some("Bls12381G2Key2020".to_string()),
                        ..Default::default()
                    },
                },
            )
            .await
            .unwrap();
        let mut vm = output.content.into_verification_method().unwrap();
        let key: JWK =
            serde_json::from_value(vm.properties.remove("publicKeyJwk").unwrap()).unwrap();
        eprintln!("key {}", serde_json::to_string_pretty(&key).unwrap());

        // Note: this "x" value is generated by this implementation - not yet confirmed with other
        // implementations.
        // Related issue: https://github.com/mattrglobal/bls12381-jwk-draft/issues/5
        let key_expected: JWK = serde_json::from_value(serde_json::json!({
            "kty": "EC",
            "crv": "BLS12381G2",
            "x": "FKWJu0SOY7onl4tEyOOH11XBriQN2JgzV-UmjgBMSsNkcAx3_l97SVYViSDBouTVBkBfrLh33C5icDD-4UEDxNO3Wn1ijMHvn2N63DU4pkezA3kGN81jGbwbrsMPpiOF",
            "y": "DxwQn0pJ1DsBB8esxf3JvxFzS8BlyJVYvY_-HkYUxI-u6GdOHnMvNVSXKlEGjHw3DyTPeGOZ8KNbh62CaqWGE-4XAm23nzoD5dWg61Nvs5DGV4S4tLPmOXRYgHIPfRdq"
        }))
        .unwrap();
        assert_eq!(key, key_expected);

        let did1 = DIDKey::generate(&key).unwrap();
        assert_eq!(did1, did);
    }

    #[async_std::test]
    async fn from_did_key_rsa() {
        let did = did!("did:key:z4MXj1wBzi9jUstyPMS4jQqB6KdJaiatPkAtVtGc6bQEQEEsKTic4G7Rou3iBf9vPmT5dbkm9qsZsuVNjq8HCuW1w24nhBFGkRE4cd2Uf2tfrB3N7h4mnyPp1BF3ZttHTYv3DLUPi1zMdkULiow3M1GfXkoC6DoxDUm1jmN6GBj22SjVsr6dxezRVQc7aj9TxE7JLbMH1wh5X3kA58H3DFW8rnYMakFGbca5CB2Jf6CnGQZmL7o5uJAdTwXfy2iiiyPxXEGerMhHwhjTA1mKYobyk2CpeEcmvynADfNZ5MBvcCS7m3XkFCMNUYBS9NQ3fze6vMSUPsNa6GVYmKx2x6JrdEjCk3qRMMmyjnjCMfR4pXbRMZa3i");
        DIDKey.resolve(did).await.unwrap();

        let vm = DIDURL::new(b"did:key:z4MXj1wBzi9jUstyPMS4jQqB6KdJaiatPkAtVtGc6bQEQEEsKTic4G7Rou3iBf9vPmT5dbkm9qsZsuVNjq8HCuW1w24nhBFGkRE4cd2Uf2tfrB3N7h4mnyPp1BF3ZttHTYv3DLUPi1zMdkULiow3M1GfXkoC6DoxDUm1jmN6GBj22SjVsr6dxezRVQc7aj9TxE7JLbMH1wh5X3kA58H3DFW8rnYMakFGbca5CB2Jf6CnGQZmL7o5uJAdTwXfy2iiiyPxXEGerMhHwhjTA1mKYobyk2CpeEcmvynADfNZ5MBvcCS7m3XkFCMNUYBS9NQ3fze6vMSUPsNa6GVYmKx2x6JrdEjCk3qRMMmyjnjCMfR4pXbRMZa3i#z4MXj1wBzi9jUstyPMS4jQqB6KdJaiatPkAtVtGc6bQEQEEsKTic4G7Rou3iBf9vPmT5dbkm9qsZsuVNjq8HCuW1w24nhBFGkRE4cd2Uf2tfrB3N7h4mnyPp1BF3ZttHTYv3DLUPi1zMdkULiow3M1GfXkoC6DoxDUm1jmN6GBj22SjVsr6dxezRVQc7aj9TxE7JLbMH1wh5X3kA58H3DFW8rnYMakFGbca5CB2Jf6CnGQZmL7o5uJAdTwXfy2iiiyPxXEGerMhHwhjTA1mKYobyk2CpeEcmvynADfNZ5MBvcCS7m3XkFCMNUYBS9NQ3fze6vMSUPsNa6GVYmKx2x6JrdEjCk3qRMMmyjnjCMfR4pXbRMZa3i").unwrap();
        let output = DIDKey
            .dereference_with(
                vm,
                Options {
                    accept: None,
                    parameters: Parameters {
                        public_key_format: Some("JsonWebKey2020".to_string()),
                        ..Default::default()
                    },
                },
            )
            .await
            .unwrap();
        let mut vm = output.content.into_verification_method().unwrap();
        let key: JWK =
            serde_json::from_value(vm.properties.remove("publicKeyJwk").unwrap()).unwrap();
        eprintln!("key {}", serde_json::to_string_pretty(&key).unwrap());

        let key_expected: JWK = serde_json::from_value(serde_json::json!({
            "kty": "RSA",
            "e": "AQAB",
            "n": "sbX82NTV6IylxCh7MfV4hlyvaniCajuP97GyOqSvTmoEdBOflFvZ06kR_9D6ctt45Fk6hskfnag2GG69NALVH2o4RCR6tQiLRpKcMRtDYE_thEmfBvDzm_VVkOIYfxu-Ipuo9J_S5XDNDjczx2v-3oDh5-CIHkU46hvFeCvpUS-L8TJSbgX0kjVk_m4eIb9wh63rtmD6Uz_KBtCo5mmR4TEtcLZKYdqMp3wCjN-TlgHiz_4oVXWbHUefCEe8rFnX1iQnpDHU49_SaXQoud1jCaexFn25n-Aa8f8bc5Vm-5SeRwidHa6ErvEhTvf1dz6GoNPp2iRvm-wJ1gxwWJEYPQ"
        }))
        .unwrap();
        assert_eq!(key, key_expected);

        let did1 = DIDKey::generate(&key).unwrap();
        assert_eq!(did1, did);
    }

    #[async_std::test]
    async fn credential_prove_verify_did_key_ed25519() {
        let didkey = VerificationMethodDIDResolver::new(DIDKey);
        let params = VerificationParameters::from_resolver(&didkey);

        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(2);
        let key = JWK::generate_ed25519_from(&mut rng).unwrap();
        let did = DIDKey::generate(&key).unwrap();

        let cred = JsonCredential::new(
            Some(uri!("http://example.org/credentials/3731").to_owned()),
            did.clone().into_uri().into(),
            "2020-08-19T21:41:50Z".parse().unwrap(),
            NonEmptyVec::new(json_syntax::json!({
                "id": "did:example:d23dd687a7dc6787646f2eb98d0"
            })),
        );

        let verification_method = DIDKey
            .resolve_into_any_verification_method(&did)
            .await
            .unwrap()
            .unwrap();
        let verification_method_ref = ReferenceOrOwned::Reference(verification_method.id.into());
        // issue_options.verification_method = Some(URI::String(verification_method));
        let suite = AnySuite::pick(&key, Some(&verification_method_ref)).unwrap();

        let issue_options = SuiteOptions::new(
            "2020-08-19T21:41:50Z".parse().unwrap(),
            verification_method_ref,
            ProofPurpose::Assertion,
            AnyInputSuiteOptions::default(),
        );
        let signer = SingleSecretSigner::new(key).into_local();
        let vc = suite
            .sign(cred, &didkey, &signer, issue_options)
            .await
            .unwrap();
        println!(
            "proof: {}",
            serde_json::to_string_pretty(&vc.proofs).unwrap()
        );
        assert_eq!(vc.proofs.first().unwrap().signature.as_ref(), "eyJhbGciOiJFZERTQSIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..o4SzDo1RBQqdK49OPdmfVRVh68xCTNEmb7hq39IVqISkelld6t6Aatg4PCXKpopIXmX8RCCF4BwrO8ERg1YFBg");
        assert!(vc.verify(&params).await.unwrap().is_ok());

        // test that issuer is verified
        let mut vc_bad_issuer = vc.clone();
        vc_bad_issuer.issuer = uri!("did:pkh:example:bad").to_owned().into();

        // It should fail.
        assert!(vc_bad_issuer.verify(&params).await.unwrap().is_err());
    }

    #[async_std::test]
    #[cfg(feature = "secp256k1")]
    async fn credential_prove_verify_did_key_secp256k1() {
        let didkey = VerificationMethodDIDResolver::new(DIDKey);
        let params = VerificationParameters::from_resolver(&didkey);

        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(2);
        let key = JWK::generate_secp256k1_from(&mut rng);
        let did = DIDKey::generate(&key).unwrap();

        let cred = JsonCredential::new(
            None,
            did.clone().into_uri().into(),
            "2021-02-18T20:17:46Z".parse().unwrap(),
            NonEmptyVec::new(json_syntax::json!({
                "id": "did:example:d23dd687a7dc6787646f2eb98d0"
            })),
        );

        let verification_method = DIDKey
            .resolve_into_any_verification_method(&did)
            .await
            .unwrap()
            .unwrap();
        let verification_method_ref = ReferenceOrOwned::Reference(verification_method.id.into());
        // issue_options.verification_method = Some(URI::String(verification_method));
        let suite = AnySuite::pick(&key, Some(&verification_method_ref)).unwrap();
        eprintln!("suite: {suite:?}");
        let issue_options = SuiteOptions::new(
            "2021-02-18T20:17:46Z".parse().unwrap(),
            verification_method_ref,
            ProofPurpose::Assertion,
            AnyInputSuiteOptions::default(),
        );
        let signer = SingleSecretSigner::new(key).into_local();
        let vc = suite
            .sign(cred, &didkey, &signer, issue_options)
            .await
            .unwrap();
        println!(
            "proof: {}",
            serde_json::to_string_pretty(&vc.proofs).unwrap()
        );
        assert_eq!(vc.proofs.first().unwrap().signature.as_ref(), "eyJhbGciOiJFUzI1NksiLCJjcml0IjpbImI2NCJdLCJiNjQiOmZhbHNlfQ..jTUkFd_eYI72Y8j2OS5LRLhlc3gZn-gVsb76soi3FuJ5gWrbOb0W2CW6D-sjEsCuLkvSOfYd8Y8hB9pyeeZ2TQ");
        assert!(vc.verify(&params).await.unwrap().is_ok());

        // test that issuer is verified
        let mut vc_bad_issuer = vc.clone();
        vc_bad_issuer.issuer = uri!("did:pkh:example:bad").to_owned().into();

        // It should fail.
        assert!(vc_bad_issuer.verify(params).await.unwrap().is_err());
    }

    #[async_std::test]
    #[cfg(feature = "secp256r1")]
    async fn credential_prove_verify_did_key_p256() {
        let didkey = VerificationMethodDIDResolver::new(DIDKey);
        let params = VerificationParameters::from_resolver(&didkey);

        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(2);
        let key = JWK::generate_p256_from(&mut rng);
        let did = DIDKey::generate(&key).unwrap();

        let cred = JsonCredential::new(
            None,
            did.clone().into_uri().into(),
            "2021-02-18T20:17:46Z".parse().unwrap(),
            NonEmptyVec::new(json_syntax::json!({
                "id": "did:example:d23dd687a7dc6787646f2eb98d0"
            })),
        );

        let verification_method = DIDKey
            .resolve_into_any_verification_method(&did)
            .await
            .unwrap()
            .unwrap();
        let verification_method_ref = ReferenceOrOwned::Reference(verification_method.id.into());
        // issue_options.verification_method = Some(URI::String(verification_method));
        let suite = AnySuite::pick(&key, Some(&verification_method_ref)).unwrap();
        eprintln!("suite: {suite:?}");
        let issue_options = SuiteOptions::new(
            "2021-02-18T20:17:46Z".parse().unwrap(),
            verification_method_ref,
            ProofPurpose::Assertion,
            AnyInputSuiteOptions::default(),
        );
        let signer = SingleSecretSigner::new(key).into_local();
        let vc = suite
            .sign(cred, &didkey, &signer, issue_options)
            .await
            .unwrap();
        println!(
            "proof: {}",
            serde_json::to_string_pretty(&vc.proofs).unwrap()
        );
        assert!(vc.verify(&params).await.unwrap().is_ok());

        // test that issuer is verified
        let mut vc_bad_issuer = vc.clone();
        vc_bad_issuer.issuer = uri!("did:pkh:example:bad").to_owned().into();

        // It should fail.
        assert!(vc_bad_issuer.verify(params).await.unwrap().is_err());
    }

    async fn fetch_jwk(jwk: JWK) {
        let did = DIDKey::generate(&jwk).unwrap();
        let resolver: VerificationMethodDIDResolver<_, AnyMethod> =
            VerificationMethodDIDResolver::new(DIDKey);
        let vm = DIDKey
            .resolve_into_any_verification_method(&did)
            .await
            .unwrap()
            .unwrap();
        let public_jwk = resolver.fetch_public_jwk(Some(&vm.id)).await.unwrap();
        assert_eq!(*public_jwk, jwk.to_public());
    }

    #[async_std::test]
    async fn fetch_jwk_ed25519() {
        let jwk = JWK::generate_ed25519().unwrap();
        fetch_jwk(jwk).await;
    }

    #[async_std::test]
    #[cfg(feature = "secp256k1")]
    async fn fetch_jwk_secp256k1() {
        let jwk = JWK::generate_secp256k1();
        fetch_jwk(jwk).await;
    }

    #[async_std::test]
    #[cfg(feature = "secp256r1")]
    async fn fetch_jwk_secp256r1() {
        let jwk = JWK::generate_p256();
        fetch_jwk(jwk).await;
    }

    #[async_std::test]
    #[cfg(feature = "secp384r1")]
    async fn fetch_jwk_secp384r1() {
        let jwk = JWK::generate_p384();
        fetch_jwk(jwk).await;
    }
}
