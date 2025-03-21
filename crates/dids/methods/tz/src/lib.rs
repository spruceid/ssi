use iref::{Iri, Uri, UriBuf};
use json_patch::patch;
use serde::Deserialize;
use ssi_dids_core::{
    document::{
        self,
        representation::{self, MediaType},
        verification_method::ValueOrReference,
        DIDVerificationMethod, Resource, Service,
    },
    resolution::Error,
    resolution::{self, Content, DIDMethodResolver, DerefError, Output, Parameter},
    DIDBuf, DIDMethod, DIDResolver, DIDURLBuf, Document, DID, DIDURL,
};
use ssi_jwk::{p256_parse, secp256k1_parse, Base64urlUInt, OctetParams, Params, JWK};
use ssi_jws::{decode_unverified, decode_verify};
use static_iref::iri;
use std::{collections::BTreeMap, future::Future};

mod explorer;
mod prefix;

pub use prefix::*;

#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    #[error("missing key id in patch")]
    MissingPatchKeyId,

    #[error("key id `{0}` in patch is not a DID URL")]
    InvalidPatchKeyId(String),

    #[error("invalid public key `{0}`")]
    InvalidPublicKey(String, ssi_jwk::Error),

    #[error("invalid public key `{0}`: not base58")]
    InvalidPublicKeyEncoding(String),

    #[error("{0} support not enabled")]
    PrefixNotEnabled(Prefix),

    #[error("dereference failed: {0}")]
    DereferenceFailed(DerefError),

    #[error("expected a DID document")]
    NotADocument,

    #[error("missing public key for patch")]
    MissingPublicKey,

    #[error("invalid JWS: {0}")]
    InvalidJws(ssi_jws::Error),

    #[error("invalid patch: {0}")]
    InvalidPatch(serde_json::Error),

    #[error(transparent)]
    Patch(json_patch::PatchError),

    #[error("invalid patched document: {0}")]
    InvalidPatchedDocument(serde_json::Error),
}

/// `did:tz` DID Method
///
/// [Specification](https://github.com/spruceid/did-tezos/)
///
/// # Resolution options
///
/// ## `tzkt_url`
/// Custom indexer endpoint URL.
///
/// ## `updates`
/// [Off-Chain DID Document Updates](https://did-tezos.spruceid.com/#off-chain-did-document-updates), as specified in the Tezos DID Method Specification.
///
/// ## `public_key`
/// Public key in Base58 format ([publicKeyBase58](https://w3c-ccg.github.io/security-vocab/#publicKeyBase58)) to add to a [derived DID document (implicit resolution)](https://did-tezos.spruceid.com/#deriving-did-documents).
#[derive(Default, Clone)]
pub struct DIDTz {
    tzkt_url: Option<UriBuf>,
}

impl DIDTz {
    pub const fn new(tzkt_url: Option<UriBuf>) -> Self {
        Self { tzkt_url }
    }
}

impl DIDMethod for DIDTz {
    const DID_METHOD_NAME: &'static str = "tz";
}

impl DIDMethodResolver for DIDTz {
    async fn resolve_method_representation<'a>(
        &'a self,
        id: &'a str,
        options: ssi_dids_core::resolution::Options,
    ) -> Result<Output<Vec<u8>>, Error> {
        let did = DIDBuf::new(format!("did:tz:{id}").into_bytes()).unwrap();
        let (network, address) = id.split_once(':').unwrap_or(("mainnet", id));

        if address.len() != 36 {
            return Err(Error::InvalidMethodSpecificId(id.to_owned()));
        }

        // https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-26.md
        let genesis_block_hash = match network {
            "mainnet" => "NetXdQprcVkpaWU",
            "delphinet" => "NetXm8tYqnMWky1",
            "granadanet" => "NetXz969SFaFn8k",
            "edonet" => "NetXSgo1ZT2DRUG",
            "florencenet" => "NetXxkAx4woPLyu",
            _ => return Err(Error::InvalidMethodSpecificId(id.to_owned())),
        };

        let prefix = Prefix::from_address(address)
            .map_err(|_| Error::InvalidMethodSpecificId(id.to_owned()))?;

        let vm = TezosVerificationMethod {
            id: DIDURLBuf::new(format!("{did}#blockchainAccountId").into_bytes()).unwrap(),
            type_: VerificationMethodType::from_prefix(prefix),
            controller: did.clone(),
            blockchain_account_id: Some(format!("tezos:{}:{}", genesis_block_hash, address)),
            public_key: None,
        };

        let authentication_vm = options
            .parameters
            .additional
            .get("public_key")
            .map(|value| {
                value
                    .as_string()
                    .ok_or_else(|| Error::InvalidMethodSpecificId(id.to_owned()))
            })
            .transpose()?
            .map(|public_key| TezosVerificationMethod {
                id: vm.id.clone(),
                type_: vm.type_,
                controller: vm.controller.clone(),
                blockchain_account_id: None,
                public_key: Some(public_key.to_owned()),
            });

        let mut json_ld_context = JsonLdContext::default();
        json_ld_context.add_verification_method(&vm);
        if let Some(vm) = &authentication_vm {
            json_ld_context.add_verification_method(vm);
        }

        let mut doc = DIDTz::tier1_derivation(&did, vm, authentication_vm);

        let tzkt_url = match options.parameters.additional.get("tzkt_url") {
            Some(value) => match value {
                Parameter::String(v) => match UriBuf::new(v.as_bytes().to_vec()) {
                    Ok(url) => url,
                    Err(_) => return Err(Error::InvalidOptions),
                },
                _ => return Err(Error::InvalidOptions),
            },
            None => match &self.tzkt_url {
                Some(u) => u.clone(),
                None => UriBuf::new(format!("https://api.{network}.tzkt.io").into_bytes()).unwrap(),
            },
        };

        if let (Some(service), Some(vm_url)) =
            DIDTz::tier2_resolution(prefix, &tzkt_url, &did, address).await?
        {
            doc.service.push(service);
            doc.verification_relationships
                .authentication
                .push(ValueOrReference::Reference(vm_url.into()));
        }

        if let Some(updates_metadata) = options.parameters.additional.get("updates") {
            let conversion: String = match updates_metadata {
                Parameter::String(s) => s.clone(),
                // Parameter::Map(m) => match serde_json::to_string(m) {
                //     Ok(s) => s.clone(),
                //     Err(e) => {
                //         return (
                //             ResolutionMetadata {
                //                 error: Some(e.to_string()),
                //                 ..Default::default()
                //             },
                //             Some(doc),
                //             None,
                //         )
                //     }
                // },
                _ => return Err(Error::InvalidOptions),
            };

            let updates: Updates = match serde_json::from_str(&conversion) {
                Ok(uu) => uu,
                Err(_) => return Err(Error::InvalidOptions),
            };

            self.tier3_updates(prefix, &mut doc, updates)
                .await
                .map_err(Error::internal)?;
        }

        let content_type = options.accept.unwrap_or(MediaType::JsonLd);
        let represented = doc.into_representation(representation::Options::from_media_type(
            content_type,
            move || representation::json_ld::Options {
                context: representation::json_ld::Context::array(
                    representation::json_ld::DIDContext::V1,
                    vec![json_ld_context.into()],
                ),
            },
        ));

        Ok(Output::new(
            represented.to_bytes(),
            document::Metadata::default(),
            resolution::Metadata::from_content_type(Some(content_type.to_string())),
        ))
    }
}

fn get_public_key_from_doc<'a>(doc: &'a Document, auth_vm_id: &DIDURL) -> Option<&'a str> {
    let mut is_authentication_method = false;
    for vm in &doc.verification_relationships.authentication {
        #[allow(clippy::single_match)]
        match vm {
            ValueOrReference::Value(vm) => {
                if vm.id == auth_vm_id {
                    return vm
                        .properties
                        .get("publicKeyBase58")
                        .and_then(serde_json::Value::as_str);
                }
            }
            ValueOrReference::Reference(_) => is_authentication_method = true,
        }
    }

    if is_authentication_method {
        for vm in &doc.verification_method {
            if vm.id == auth_vm_id {
                return vm
                    .properties
                    .get("publicKeyBase58")
                    .and_then(serde_json::Value::as_str);
            }
        }
    }

    None
}

pub struct TezosVerificationMethod {
    id: DIDURLBuf,
    type_: VerificationMethodType,
    controller: DIDBuf,
    blockchain_account_id: Option<String>,
    public_key: Option<String>,
}

impl From<TezosVerificationMethod> for DIDVerificationMethod {
    fn from(value: TezosVerificationMethod) -> Self {
        let mut properties = BTreeMap::new();

        if let Some(v) = value.blockchain_account_id {
            properties.insert(
                "blockchainAccountId".to_string(),
                serde_json::Value::String(v),
            );
        }

        if let Some(v) = value.public_key {
            properties.insert("publicKeyBase58".to_string(), serde_json::Value::String(v));
        }

        DIDVerificationMethod::new(
            value.id,
            value.type_.name().to_string(),
            value.controller,
            properties,
        )
    }
}

#[derive(Debug, Clone, Copy)]
pub enum VerificationMethodType {
    Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021,
    EcdsaSecp256k1RecoveryMethod2020,
    P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021,
}

impl VerificationMethodType {
    pub fn from_prefix(prefix: Prefix) -> Self {
        match prefix {
            Prefix::TZ1 | Prefix::KT1 => {
                Self::Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021
            }
            Prefix::TZ2 => VerificationMethodType::EcdsaSecp256k1RecoveryMethod2020,
            Prefix::TZ3 => {
                VerificationMethodType::P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021
            }
        }
    }

    pub fn curve(&self) -> &'static str {
        match self {
            Self::Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021 => "Ed25519",
            Self::EcdsaSecp256k1RecoveryMethod2020 => "secp256k1",
            Self::P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021 => "P-256",
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021 => {
                "Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021"
            }
            Self::EcdsaSecp256k1RecoveryMethod2020 => "EcdsaSecp256k1RecoveryMethod2020",
            Self::P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021 => {
                "P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021"
            }
        }
    }

    pub fn as_iri(&self) -> &'static Iri {
        match self {
            Self::Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021 => iri!("https://w3id.org/security#Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021"),
            Self::EcdsaSecp256k1RecoveryMethod2020 => iri!("https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#EcdsaSecp256k1RecoveryMethod2020"),
            Self::P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021 => iri!("https://w3id.org/security#P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021")
        }
    }
}

fn decode_public_key(public_key: &str) -> Result<Vec<u8>, UpdateError> {
    Ok(bs58::decode(public_key)
        .with_check(None)
        .into_vec()
        .map_err(|_| {
            // Couldn't decode public key
            UpdateError::InvalidPublicKeyEncoding(public_key.to_owned())
        })?[4..]
        .to_vec())
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
struct SignedIetfJsonPatchPayload {
    ietf_json_patch: serde_json::Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
#[serde(tag = "type", content = "value")]
enum Updates {
    SignedIetfJsonPatch(Vec<String>),
}

#[derive(Debug, Default)]
struct JsonLdContext {
    ecdsa_secp256k1_recovery_method_2020: bool,
    ed_25519_public_key_blake2b_digest_size_20_base58_check_encoded2021: bool,
    p256_public_key_blake2b_digest_size_20_base58_check_encoded2021: bool,
    blockchain_account_id: bool,
    public_key_base58: bool,
}

impl JsonLdContext {
    pub fn add_verification_method(&mut self, m: &TezosVerificationMethod) {
        self.blockchain_account_id |= m.blockchain_account_id.is_some();
        self.public_key_base58 |= m.public_key.is_some();
        self.add_verification_method_type(m.type_);
    }

    pub fn add_verification_method_type(&mut self, ty: VerificationMethodType) {
        match ty {
            VerificationMethodType::EcdsaSecp256k1RecoveryMethod2020 => {
                self.ecdsa_secp256k1_recovery_method_2020 = true
            }
            VerificationMethodType::Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021 => {
                self.ed_25519_public_key_blake2b_digest_size_20_base58_check_encoded2021 = true
            }
            VerificationMethodType::P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021 => {
                self.p256_public_key_blake2b_digest_size_20_base58_check_encoded2021 = true
            }
        }
    }
}

impl From<JsonLdContext> for representation::json_ld::ContextEntry {
    fn from(value: JsonLdContext) -> Self {
        use representation::json_ld::context::{Definition, TermDefinition};
        let mut def = Definition::new();

        if value.ecdsa_secp256k1_recovery_method_2020 {
            let ty = VerificationMethodType::EcdsaSecp256k1RecoveryMethod2020;
            def.bindings.insert(
                ty.name().into(),
                TermDefinition::Simple(ty.as_iri().to_owned().into()).into(),
            );
        }

        if value.ed_25519_public_key_blake2b_digest_size_20_base58_check_encoded2021 {
            let ty =
                VerificationMethodType::Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021;
            def.bindings.insert(
                ty.name().into(),
                TermDefinition::Simple(ty.as_iri().to_owned().into()).into(),
            );
        }

        if value.p256_public_key_blake2b_digest_size_20_base58_check_encoded2021 {
            let ty = VerificationMethodType::P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021;
            def.bindings.insert(
                ty.name().into(),
                TermDefinition::Simple(ty.as_iri().to_owned().into()).into(),
            );
        }

        if value.blockchain_account_id {
            def.bindings.insert(
                "blockchainAccountId".into(),
                TermDefinition::Simple(
                    iri!("https://w3id.org/security#blockchainAccountId")
                        .to_owned()
                        .into(),
                )
                .into(),
            );
        }

        Self::Definition(def)
    }
}

impl DIDTz {
    // TODO need to handle different networks
    pub fn generate(&self, jwk: &JWK) -> Result<DIDBuf, ssi_jwk::Error> {
        let hash = ssi_jwk::blakesig::hash_public_key(jwk)?;
        Ok(DIDBuf::from_string(format!("did:tz:{hash}")).unwrap())
    }

    fn tier1_derivation(
        did: &DID,
        verification_method: TezosVerificationMethod,
        authentication_verification_method: Option<TezosVerificationMethod>,
    ) -> Document {
        // let mut context = BTreeMap::new();

        // context.insert(
        //     "blockchainAccountId".to_string(),
        //     Value::String("https://w3id.org/security#blockchainAccountId".to_string()),
        // );

        // context.insert(
        //     proof_type.to_string(),
        //     Value::String(proof_type_iri.to_string()),
        // );

        // if public_key.is_some() {
        //     context.insert(
        //         "publicKeyBase58".to_string(),
        //         Value::String("https://w3id.org/security#publicKeyBase58".to_string()),
        //     );
        // }

        let mut document = Document::new(did.to_owned());

        let authentication_verification_method = match authentication_verification_method {
            Some(vm) => ValueOrReference::Value(vm.into()),
            None => ValueOrReference::Reference(verification_method.id.clone().into()),
        };

        document
            .verification_relationships
            .assertion_method
            .push(ValueOrReference::Reference(
                verification_method.id.clone().into(),
            ));
        document
            .verification_relationships
            .authentication
            .push(authentication_verification_method);
        document
            .verification_method
            .push(verification_method.into());

        document
    }

    async fn tier2_resolution(
        prefix: Prefix,
        tzkt_url: &Uri,
        did: &DID,
        address: &str,
    ) -> Result<(Option<Service>, Option<DIDURLBuf>), Error> {
        if let Some(did_manager) = match prefix {
            Prefix::KT1 => Some(address.to_string()),
            _ => explorer::retrieve_did_manager(tzkt_url, address).await?,
        } {
            Ok((
                Some(explorer::execute_service_view(tzkt_url, did, &did_manager).await?),
                Some(explorer::execute_auth_view(tzkt_url, &did_manager).await?),
            ))
        } else {
            Ok((None, None))
        }
    }

    fn tier3_updates<'a>(
        &'a self,
        prefix: Prefix,
        doc: &'a mut Document,
        updates: Updates,
    ) -> impl 'a + Future<Output = Result<(), UpdateError>> {
        Box::pin(async move {
            match updates {
                Updates::SignedIetfJsonPatch(patches) => {
                    for jws in patches {
                        let mut doc_json = serde_json::to_value(&*doc).unwrap();
                        let (patch_metadata, _) =
                            decode_unverified(&jws).map_err(UpdateError::InvalidJws)?;
                        let curve = VerificationMethodType::from_prefix(prefix)
                            .curve()
                            .to_string();

                        let kid = match patch_metadata.key_id {
                            Some(k) => DIDURLBuf::from_string(k)
                                .map_err(|e| UpdateError::InvalidPatchKeyId(e.0)),
                            None => {
                                // No kid in JWS JSON patch.
                                Err(UpdateError::MissingPatchKeyId)
                            }
                        }?;

                        // TODO need to compare address + network instead of the String
                        // did:tz:tz1blahblah == did:tz:mainnet:tz1blahblah
                        let kid_doc = if kid.did() == &doc.id {
                            doc.clone()
                        } else {
                            let deref = self
                                .dereference(&kid)
                                .await
                                .map_err(UpdateError::DereferenceFailed)?;
                            match deref.content {
                                Content::Resource(Resource::Document(d)) => d,
                                _ => {
                                    // Dereferenced content not a DID document.
                                    return Err(UpdateError::NotADocument);
                                }
                            }
                        };

                        if let Some(public_key) = get_public_key_from_doc(&kid_doc, &kid) {
                            let jwk = match prefix {
                                Prefix::TZ1 | Prefix::KT1 => {
                                    let pk = decode_public_key(public_key)?;

                                    JWK {
                                        params: Params::OKP(OctetParams {
                                            curve,
                                            public_key: Base64urlUInt(pk),
                                            private_key: None,
                                        }),
                                        public_key_use: None,
                                        key_operations: None,
                                        algorithm: None,
                                        key_id: None,
                                        x509_url: None,
                                        x509_thumbprint_sha1: None,
                                        x509_certificate_chain: None,
                                        x509_thumbprint_sha256: None,
                                    }
                                }
                                Prefix::TZ2 => {
                                    let pk = decode_public_key(public_key)?;
                                    secp256k1_parse(&pk).map_err(|e| {
                                        // Couldn't create JWK from secp256k1 public key: {e}
                                        UpdateError::InvalidPublicKey(public_key.to_owned(), e)
                                    })?
                                }
                                Prefix::TZ3 => {
                                    let pk = decode_public_key(public_key)?;
                                    p256_parse(&pk).map_err(|e| {
                                        // Couldn't create JWK from P-256 public key: {e}
                                        UpdateError::InvalidPublicKey(public_key.to_owned(), e)
                                    })?
                                }
                                #[allow(unreachable_patterns)]
                                p => {
                                    // {p} support not enabled.
                                    return Err(UpdateError::PrefixNotEnabled(p));
                                }
                            };
                            let (_, patch_) =
                                decode_verify(&jws, &jwk).map_err(UpdateError::InvalidJws)?;
                            patch(
                                &mut doc_json,
                                &serde_json::from_slice(
                                    serde_json::from_slice::<SignedIetfJsonPatchPayload>(&patch_)
                                        .map_err(UpdateError::InvalidPatch)?
                                        .ietf_json_patch
                                        .to_string()
                                        .as_bytes(),
                                )
                                .map_err(UpdateError::InvalidPatch)?,
                            )
                            .map_err(UpdateError::Patch)?;

                            *doc = serde_json::from_value(doc_json)
                                .map_err(UpdateError::InvalidPatchedDocument)?;
                        } else {
                            // Need public key for signed patches
                            return Err(UpdateError::MissingPublicKey);
                        }
                    }
                }
            }

            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use ssi_core::one_or_many::OneOrMany;
    use ssi_dids_core::document::service;
    use ssi_jws::encode_sign;
    use static_iref::uri;

    const DIDTZ: DIDTz = DIDTz { tzkt_url: None };

    const JSON_PATCH: &str = r#"{"ietf-json-patch": [
                                {
                                    "op": "add",
                                    "path": "/service/1",
                                    "value": {
                                        "id": "http://example.org/test_service_id",
                                        "type": "test_service",
                                        "serviceEndpoint": "http://example.org/test_service_endpoint"
                                    }
                                }
                            ]}"#;

    #[tokio::test]
    async fn test_json_patch_tz1() {
        let address = "tz1VSUr8wwNhLAzempoch5d6hLRiTh8Cjcjb";
        let pk = "edpkvGfYw3LyB1UcCahKQk4rF2tvbMUk8GFiTuMjL75uGXrpvKXhjn";
        let sk = "edsk3QoqBuvdamxouPhin7swCvkQNgq4jP5KZPbwWNnwdZpSpJiEbq";
        let did = format!("did:tz:{}:{}", "sandbox", address);
        let mut doc: Document = serde_json::from_value(json!({
            "@context": "https://www.w3.org/ns/did/v1",
            "id": did,
            "authentication": [{
                "id": format!("{did}#blockchainAccountId"),
                "type": "Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021",
                "controller": did,
                "blockchainAccountId": format!("tezos:sandbox:{address}"),
                "publicKeyBase58": pk
            }],
            "service": [{
                "id": format!("{did}#discovery"),
                "type": "TezosDiscoveryService",
                "serviceEndpoint": "test_service"
            }]
        }))
        .unwrap();
        let key = JWK {
            key_id: Some(format!("{}#blockchainAccountId", did)),
            ..ssi_tzkey::jwk_from_tezos_key(sk).unwrap()
        };
        let jws = encode_sign(ssi_jwk::Algorithm::EdDSA, JSON_PATCH, &key).unwrap();
        let json_update = Updates::SignedIetfJsonPatch(vec![jws.clone()]);
        DIDTZ
            .tier3_updates(Prefix::TZ1, &mut doc, json_update)
            .await
            .unwrap();
        assert_eq!(
            doc.service[1],
            Service {
                id: uri!("http://example.org/test_service_id").to_owned(),
                type_: OneOrMany::One("test_service".to_string()),
                service_endpoint: Some(OneOrMany::One(service::Endpoint::Uri(
                    uri!("http://example.org/test_service_endpoint").to_owned()
                ))),
                property_set: BTreeMap::new()
            }
        );
    }

    #[tokio::test]
    async fn test_json_patch_tz2() {
        let address = "tz2RZoj9oqoA8bDeUoAKLjf8nLPQKmYjaj6Q";
        let pk = "sppk7bRNbJ2n9PNQo295UJiYQ8iMma8ysRH9mCRFB14yhzLCwdGay9y";
        let sk = "spsk1Uc5MDutpZmwPVeSLL2BbtCAqfrG8zbMs6dwoaeXX8kw35S474";
        let did = format!("did:tz:{}:{}", "sandbox", address);
        let mut doc: Document = serde_json::from_value(json!({
            "@context": "https://www.w3.org/ns/did/v1",
            "id": did,
            "authentication": [{
            "id": format!("{}#blockchainAccountId", did),
            "type": "EcdsaSecp256k1RecoveryMethod2020",
            "controller": did,
            "blockchainAccountId": format!("tezos:sandbox:{}", address),
            "publicKeyBase58": pk
            }],
            "service": [{
            "id": format!("{}#discovery", did),
            "type": "TezosDiscoveryService",
            "serviceEndpoint": "test_service"
            }]
        }))
        .unwrap();
        // let public_key = pk.from_base58check().unwrap()[4..].to_vec();
        let private_key = bs58::decode(&sk).with_check(None).into_vec().unwrap()[4..].to_owned();
        use ssi_jwk::ECParams;
        let key = JWK {
            params: ssi_jwk::Params::EC(ECParams {
                curve: Some("secp256k1".to_string()),
                x_coordinate: None,
                y_coordinate: None,
                ecc_private_key: Some(Base64urlUInt(private_key)),
            }),
            public_key_use: None,
            key_operations: None,
            algorithm: None,
            key_id: Some(format!("{}#blockchainAccountId", did)),
            x509_url: None,
            x509_certificate_chain: None,
            x509_thumbprint_sha1: None,
            x509_thumbprint_sha256: None,
        };
        let jws = encode_sign(ssi_jwk::Algorithm::ES256KR, JSON_PATCH, &key).unwrap();
        let json_update = Updates::SignedIetfJsonPatch(vec![jws.clone()]);
        DIDTZ
            .tier3_updates(Prefix::TZ2, &mut doc, json_update)
            .await
            .unwrap();
        assert_eq!(
            doc.service[1],
            Service {
                id: uri!("http://example.org/test_service_id").to_owned(),
                type_: OneOrMany::One("test_service".to_string()),
                service_endpoint: Some(OneOrMany::One(service::Endpoint::Uri(
                    uri!("http://example.org/test_service_endpoint").to_owned()
                ))),
                property_set: BTreeMap::new()
            }
        );
    }

    #[tokio::test]
    async fn test_json_patch_tz3() {
        let address = "tz3agP9LGe2cXmKQyYn6T68BHKjjktDbbSWX";
        let pk = "p2pk679D18uQNkdjpRxuBXL5CqcDKTKzsiXVtc9oCUT6xb82zQmgUks";
        let sk = "p2sk3PM77YMR99AvD3fSSxeLChMdiQ6kkEzqoPuSwQqhPsh29irGLC";
        let did = format!("did:tz:{}:{}", "sandbox", address);
        let mut doc: Document = serde_json::from_value(json!({
            "@context": "https://www.w3.org/ns/did/v1",
            "id": did,
            "authentication": [{
            "id": format!("{}#blockchainAccountId", did),
            "type": "JsonWebKey2020",
            "controller": did,
            "blockchainAccountId": format!("tezos:sandbox:{}", address),
            "publicKeyBase58": pk
            }],
            "service": [{
            "id": format!("{}#discovery", did),
            "type": "TezosDiscoveryService",
            "serviceEndpoint": "test_service"
            }]
        }))
        .unwrap();
        // let public_key = pk.from_base58check().unwrap()[4..].to_vec();
        let private_key = bs58::decode(&sk).with_check(None).into_vec().unwrap()[4..].to_owned();
        let key = JWK {
            params: ssi_jwk::Params::EC(ssi_jwk::ECParams {
                curve: Some("P-256".to_string()),
                x_coordinate: None,
                y_coordinate: None,
                ecc_private_key: Some(Base64urlUInt(private_key)),
            }),
            public_key_use: None,
            key_operations: None,
            algorithm: None,
            key_id: Some(format!("{}#blockchainAccountId", did)),
            x509_url: None,
            x509_certificate_chain: None,
            x509_thumbprint_sha1: None,
            x509_thumbprint_sha256: None,
        };
        let jws = encode_sign(ssi_jwk::Algorithm::ES256, JSON_PATCH, &key).unwrap();
        let json_update = Updates::SignedIetfJsonPatch(vec![jws.clone()]);
        DIDTZ
            .tier3_updates(Prefix::TZ3, &mut doc, json_update)
            .await
            .unwrap();
        assert_eq!(
            doc.service[1],
            Service {
                id: uri!("http://example.org/test_service_id").to_owned(),
                type_: OneOrMany::One("test_service".to_string()),
                service_endpoint: Some(OneOrMany::One(service::Endpoint::Uri(
                    uri!("http://example.org/test_service_endpoint").to_owned()
                ))),
                property_set: BTreeMap::new()
            }
        );
    }
}
