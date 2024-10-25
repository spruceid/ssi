use iref::Iri;
use ssi_caips::caip10::BlockchainAccountId;
use ssi_caips::caip2::ChainId;
use ssi_dids_core::{
    document::{
        self,
        representation::{self, MediaType},
        DIDVerificationMethod,
    },
    resolution::{self, DIDMethodResolver, Error, Output},
    DIDBuf, DIDMethod, DIDURLBuf, Document, DIDURL,
};
use static_iref::iri;
use std::str::FromStr;

mod json_ld_context;
use json_ld_context::JsonLdContext;
use ssi_jwk::JWK;

/// did:ethr DID Method
///
/// [Specification](https://github.com/decentralized-identity/ethr-did-resolver/)
pub struct DIDEthr;

impl DIDEthr {
    pub fn generate(jwk: &JWK) -> Result<DIDBuf, ssi_jwk::Error> {
        let hash = ssi_jwk::eip155::hash_public_key(jwk)?;
        Ok(DIDBuf::from_string(format!("did:ethr:{}", hash)).unwrap())
    }
}

impl DIDMethod for DIDEthr {
    const DID_METHOD_NAME: &'static str = "ethr";
}

impl DIDMethodResolver for DIDEthr {
    async fn resolve_method_representation<'a>(
        &'a self,
        method_specific_id: &'a str,
        options: resolution::Options,
    ) -> Result<Output<Vec<u8>>, Error> {
        let decoded_id = DecodedMethodSpecificId::from_str(method_specific_id)
            .map_err(|_| Error::InvalidMethodSpecificId(method_specific_id.to_owned()))?;

        let mut json_ld_context = JsonLdContext::default();

        let doc = match decoded_id.address_or_public_key.len() {
            42 => resolve_address(
                &mut json_ld_context,
                method_specific_id,
                decoded_id.network_chain,
                decoded_id.address_or_public_key,
            ),
            68 => resolve_public_key(
                &mut json_ld_context,
                method_specific_id,
                decoded_id.network_chain,
                &decoded_id.address_or_public_key,
            ),
            _ => Err(Error::InvalidMethodSpecificId(
                method_specific_id.to_owned(),
            )),
        }?;

        let content_type = options.accept.unwrap_or(MediaType::JsonLd);
        let represented = doc.into_representation(representation::Options::from_media_type(
            content_type,
            move || representation::json_ld::Options {
                context: representation::json_ld::Context::array(
                    representation::json_ld::DIDContext::V1,
                    json_ld_context.into_entries(),
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

struct DecodedMethodSpecificId {
    network_chain: NetworkChain,
    address_or_public_key: String,
}

impl FromStr for DecodedMethodSpecificId {
    type Err = InvalidNetwork;

    fn from_str(method_specific_id: &str) -> Result<Self, Self::Err> {
        // https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md#method-specific-identifier
        let (network_name, address_or_public_key) = match method_specific_id.split_once(':') {
            None => ("mainnet".to_string(), method_specific_id.to_string()),
            Some((network, address_or_public_key)) => {
                (network.to_string(), address_or_public_key.to_string())
            }
        };

        Ok(DecodedMethodSpecificId {
            network_chain: network_name.parse()?,
            address_or_public_key,
        })
    }
}

#[derive(Debug, thiserror::Error)]
#[error("invalid network `{0}`")]
struct InvalidNetwork(String);

enum NetworkChain {
    Mainnet,
    Morden,
    Ropsten,
    Rinkeby,
    Georli,
    Kovan,
    Other(u64),
}

impl NetworkChain {
    pub fn id(&self) -> u64 {
        match self {
            Self::Mainnet => 1,
            Self::Morden => 2,
            Self::Ropsten => 3,
            Self::Rinkeby => 4,
            Self::Georli => 5,
            Self::Kovan => 42,
            Self::Other(i) => *i,
        }
    }
}

impl FromStr for NetworkChain {
    type Err = InvalidNetwork;

    fn from_str(network_name: &str) -> Result<Self, Self::Err> {
        match network_name {
            "mainnet" => Ok(Self::Mainnet),
            "morden" => Ok(Self::Morden),
            "ropsten" => Ok(Self::Ropsten),
            "rinkeby" => Ok(Self::Rinkeby),
            "goerli" => Ok(Self::Georli),
            "kovan" => Ok(Self::Kovan),
            network_chain_id if network_chain_id.starts_with("0x") => {
                match u64::from_str_radix(&network_chain_id[2..], 16) {
                    Ok(chain_id) => Ok(Self::Other(chain_id)),
                    Err(_) => Err(InvalidNetwork(network_name.to_owned())),
                }
            }
            _ => Err(InvalidNetwork(network_name.to_owned())),
        }
    }
}

fn resolve_address(
    json_ld_context: &mut JsonLdContext,
    method_specific_id: &str,
    network_chain: NetworkChain,
    account_address: String,
) -> Result<Document, Error> {
    let blockchain_account_id = BlockchainAccountId {
        account_address,
        chain_id: ChainId {
            namespace: "eip155".to_string(),
            reference: network_chain.id().to_string(),
        },
    };

    let did = DIDBuf::from_string(format!("did:ethr:{method_specific_id}")).unwrap();

    let vm = VerificationMethod::EcdsaSecp256k1RecoveryMethod2020 {
        id: DIDURLBuf::from_string(format!("{did}#controller")).unwrap(),
        controller: did.to_owned(),
        blockchain_account_id: blockchain_account_id.clone(),
    };

    let eip712_vm = VerificationMethod::Eip712Method2021 {
        id: DIDURLBuf::from_string(format!("{did}#Eip712Method2021")).unwrap(),
        controller: did.to_owned(),
        blockchain_account_id,
    };

    json_ld_context.add_verification_method_type(vm.type_());
    json_ld_context.add_verification_method_type(eip712_vm.type_());

    let mut doc = Document::new(did);
    doc.verification_relationships.assertion_method =
        vec![vm.id().to_owned().into(), eip712_vm.id().to_owned().into()];
    doc.verification_relationships.authentication =
        vec![vm.id().to_owned().into(), eip712_vm.id().to_owned().into()];
    doc.verification_method = vec![vm.into(), eip712_vm.into()];

    Ok(doc)
}

/// Resolve an Ethr DID that uses a public key hex string instead of an account address
fn resolve_public_key(
    json_ld_context: &mut JsonLdContext,
    method_specific_id: &str,
    network_chain: NetworkChain,
    public_key_hex: &str,
) -> Result<Document, Error> {
    if !public_key_hex.starts_with("0x") {
        return Err(Error::InvalidMethodSpecificId(
            method_specific_id.to_owned(),
        ));
    }

    let pk_bytes = hex::decode(&public_key_hex[2..])
        .map_err(|_| Error::InvalidMethodSpecificId(method_specific_id.to_owned()))?;

    let pk_jwk = ssi_jwk::secp256k1_parse(&pk_bytes)
        .map_err(|_| Error::InvalidMethodSpecificId(method_specific_id.to_owned()))?;

    let account_address = ssi_jwk::eip155::hash_public_key_eip55(&pk_jwk)
        .map_err(|_| Error::InvalidMethodSpecificId(method_specific_id.to_owned()))?;

    let blockchain_account_id = BlockchainAccountId {
        account_address,
        chain_id: ChainId {
            namespace: "eip155".to_string(),
            reference: network_chain.id().to_string(),
        },
    };

    let did = DIDBuf::from_string(format!("did:ethr:{method_specific_id}")).unwrap();

    let vm = VerificationMethod::EcdsaSecp256k1RecoveryMethod2020 {
        id: DIDURLBuf::from_string(format!("{did}#controller")).unwrap(),
        controller: did.to_owned(),
        blockchain_account_id,
    };

    let key_vm = VerificationMethod::EcdsaSecp256k1VerificationKey2019 {
        id: DIDURLBuf::from_string(format!("{did}#controllerKey")).unwrap(),
        controller: did.to_owned(),
        public_key_jwk: pk_jwk,
    };

    json_ld_context.add_verification_method_type(vm.type_());
    json_ld_context.add_verification_method_type(key_vm.type_());

    let mut doc = Document::new(did);
    doc.verification_relationships.assertion_method =
        vec![vm.id().to_owned().into(), key_vm.id().to_owned().into()];
    doc.verification_relationships.authentication =
        vec![vm.id().to_owned().into(), key_vm.id().to_owned().into()];
    doc.verification_method = vec![vm.into(), key_vm.into()];

    Ok(doc)
}

#[allow(clippy::large_enum_variant)]
pub enum VerificationMethod {
    EcdsaSecp256k1VerificationKey2019 {
        id: DIDURLBuf,
        controller: DIDBuf,
        public_key_jwk: JWK,
    },
    EcdsaSecp256k1RecoveryMethod2020 {
        id: DIDURLBuf,
        controller: DIDBuf,
        blockchain_account_id: BlockchainAccountId,
    },
    Eip712Method2021 {
        id: DIDURLBuf,
        controller: DIDBuf,
        blockchain_account_id: BlockchainAccountId,
    },
}

impl VerificationMethod {
    pub fn id(&self) -> &DIDURL {
        match self {
            Self::EcdsaSecp256k1VerificationKey2019 { id, .. } => id,
            Self::EcdsaSecp256k1RecoveryMethod2020 { id, .. } => id,
            Self::Eip712Method2021 { id, .. } => id,
        }
    }

    pub fn type_(&self) -> VerificationMethodType {
        match self {
            Self::EcdsaSecp256k1VerificationKey2019 { .. } => {
                VerificationMethodType::EcdsaSecp256k1VerificationKey2019
            }
            Self::EcdsaSecp256k1RecoveryMethod2020 { .. } => {
                VerificationMethodType::EcdsaSecp256k1RecoveryMethod2020
            }
            Self::Eip712Method2021 { .. } => VerificationMethodType::Eip712Method2021,
        }
    }
}

pub enum VerificationMethodType {
    EcdsaSecp256k1VerificationKey2019,
    EcdsaSecp256k1RecoveryMethod2020,
    Eip712Method2021,
}

impl VerificationMethodType {
    pub fn name(&self) -> &'static str {
        match self {
            Self::EcdsaSecp256k1VerificationKey2019 => "EcdsaSecp256k1VerificationKey2019",
            Self::EcdsaSecp256k1RecoveryMethod2020 => "EcdsaSecp256k1RecoveryMethod2020",
            Self::Eip712Method2021 => "Eip712Method2021",
        }
    }

    pub fn iri(&self) -> &'static Iri {
        match self {
            Self::EcdsaSecp256k1VerificationKey2019 => iri!("https://w3id.org/security#EcdsaSecp256k1VerificationKey2019"),
            Self::EcdsaSecp256k1RecoveryMethod2020 => iri!("https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#EcdsaSecp256k1RecoveryMethod2020"),
            Self::Eip712Method2021 => iri!("https://w3id.org/security#Eip712Method2021")
        }
    }
}

impl From<VerificationMethod> for DIDVerificationMethod {
    fn from(value: VerificationMethod) -> Self {
        match value {
            VerificationMethod::EcdsaSecp256k1VerificationKey2019 {
                id,
                controller,
                public_key_jwk,
            } => Self {
                id,
                type_: "EcdsaSecp256k1VerificationKey2019".to_owned(),
                controller,
                properties: [(
                    "publicKeyJwk".into(),
                    serde_json::to_value(&public_key_jwk).unwrap(),
                )]
                .into_iter()
                .collect(),
            },
            VerificationMethod::EcdsaSecp256k1RecoveryMethod2020 {
                id,
                controller,
                blockchain_account_id,
            } => Self {
                id,
                type_: "EcdsaSecp256k1RecoveryMethod2020".to_owned(),
                controller,
                properties: [(
                    "blockchainAccountId".into(),
                    blockchain_account_id.to_string().into(),
                )]
                .into_iter()
                .collect(),
            },
            VerificationMethod::Eip712Method2021 {
                id,
                controller,
                blockchain_account_id,
            } => Self {
                id,
                type_: "Eip712Method2021".to_owned(),
                controller,
                properties: [(
                    "blockchainAccountId".into(),
                    blockchain_account_id.to_string().into(),
                )]
                .into_iter()
                .collect(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iref::IriBuf;
    use serde_json::json;
    use ssi_claims::{
        data_integrity::{
            signing::AlterSignature, AnyInputSuiteOptions, AnySuite, CryptographicSuite,
            ProofOptions,
        },
        vc::{
            syntax::NonEmptyVec,
            v1::{JsonCredential, JsonPresentation},
        },
        VerificationParameters,
    };
    use ssi_dids_core::{did, DIDResolver};
    use ssi_jwk::JWK;
    use ssi_verification_methods_core::{ProofPurpose, ReferenceOrOwned, SingleSecretSigner};
    use static_iref::uri;

    #[test]
    fn jwk_to_did_ethr() {
        let jwk: JWK = serde_json::from_value(json!({
            "alg": "ES256K-R",
            "kty": "EC",
            "crv": "secp256k1",
            "x": "yclqMZ0MtyVkKm1eBh2AyaUtsqT0l5RJM3g4SzRT96A",
            "y": "yQzUwKnftWCJPGs-faGaHiYi1sxA6fGJVw2Px_LCNe8",
        }))
        .unwrap();
        let did = DIDEthr::generate(&jwk).unwrap();
        assert_eq!(did, "did:ethr:0x2fbf1be19d90a29aea9363f4ef0b6bf1c4ff0758");
    }

    #[tokio::test]
    async fn resolve_did_ethr_addr() {
        // https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md#create-register
        let doc = DIDEthr
            .resolve(did!("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a"))
            .await
            .unwrap()
            .document;
        eprintln!("{}", serde_json::to_string_pretty(&doc).unwrap());
        assert_eq!(
            serde_json::to_value(doc).unwrap(),
            json!({
              "@context": [
                "https://www.w3.org/ns/did/v1",
                {
                  "blockchainAccountId": "https://w3id.org/security#blockchainAccountId",
                  "EcdsaSecp256k1RecoveryMethod2020": "https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#EcdsaSecp256k1RecoveryMethod2020",
                  "Eip712Method2021": "https://w3id.org/security#Eip712Method2021"
                }
              ],
              "id": "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a",
              "verificationMethod": [{
                "id": "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a#controller",
                "type": "EcdsaSecp256k1RecoveryMethod2020",
                "controller": "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a",
                "blockchainAccountId": "eip155:1:0xb9c5714089478a327f09197987f16f9e5d936e8a"
              }, {
                "id": "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a#Eip712Method2021",
                "type": "Eip712Method2021",
                "controller": "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a",
                "blockchainAccountId": "eip155:1:0xb9c5714089478a327f09197987f16f9e5d936e8a"
              }],
              "authentication": [
                "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a#controller",
                "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a#Eip712Method2021"
              ],
              "assertionMethod": [
                "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a#controller",
                "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a#Eip712Method2021"
              ]
            })
        );
    }

    #[tokio::test]
    async fn resolve_did_ethr_pk() {
        let doc = DIDEthr
            .resolve(did!(
                "did:ethr:0x03fdd57adec3d438ea237fe46b33ee1e016eda6b585c3e27ea66686c2ea5358479"
            ))
            .await
            .unwrap()
            .document;
        eprintln!("{}", serde_json::to_string_pretty(&doc).unwrap());
        let doc_expected: serde_json::Value =
            serde_json::from_str(include_str!("../tests/did-pk.jsonld")).unwrap();
        assert_eq!(
            serde_json::to_value(doc).unwrap(),
            serde_json::to_value(doc_expected).unwrap()
        );
    }

    #[tokio::test]
    async fn credential_prove_verify_did_ethr() {
        eprintln!("with EcdsaSecp256k1RecoveryMethod2020...");
        credential_prove_verify_did_ethr2(false).await;
        eprintln!("with Eip712Method2021...");
        credential_prove_verify_did_ethr2(true).await;
    }

    async fn credential_prove_verify_did_ethr2(eip712: bool) {
        let didethr = DIDEthr.into_vm_resolver();
        let verifier = VerificationParameters::from_resolver(&didethr);
        let key: JWK = serde_json::from_value(json!({
            "alg": "ES256K-R",
            "kty": "EC",
            "crv": "secp256k1",
            "x": "yclqMZ0MtyVkKm1eBh2AyaUtsqT0l5RJM3g4SzRT96A",
            "y": "yQzUwKnftWCJPGs-faGaHiYi1sxA6fGJVw2Px_LCNe8",
            "d": "meTmccmR_6ZsOa2YuTTkKkJ4ZPYsKdAH1Wx_RRf2j_E"
        }))
        .unwrap();

        let did = DIDEthr::generate(&key).unwrap();
        eprintln!("did: {}", did);

        let cred = JsonCredential::new(
            None,
            did.clone().into_uri().into(),
            "2021-02-18T20:23:13Z".parse().unwrap(),
            NonEmptyVec::new(json_syntax::json!({
                "id": "did:example:foo"
            })),
        );

        let verification_method = if eip712 {
            ReferenceOrOwned::Reference(IriBuf::new(format!("{did}#Eip712Method2021")).unwrap())
        } else {
            ReferenceOrOwned::Reference(IriBuf::new(format!("{did}#controller")).unwrap())
        };

        let suite = AnySuite::pick(&key, Some(&verification_method)).unwrap();
        let issue_options = ProofOptions::new(
            "2021-02-18T20:23:13Z".parse().unwrap(),
            verification_method,
            ProofPurpose::Assertion,
            AnyInputSuiteOptions::default(),
        );

        eprintln!("vm {:?}", issue_options.verification_method);
        let signer = SingleSecretSigner::new(key).into_local();
        let vc = suite
            .sign(cred.clone(), &didethr, &signer, issue_options.clone())
            .await
            .unwrap();
        println!(
            "proof: {}",
            serde_json::to_string_pretty(&vc.proofs).unwrap()
        );
        if eip712 {
            assert_eq!(vc.proofs.first().unwrap().signature.as_ref(), "0xd3f4a049551fd25c7fb0789c7303be63265e8ade2630747de3807710382bbb7a25b0407e9f858a771782c35b4f487f4337341e9a4375a073730bda643895964e1b")
        } else {
            assert_eq!(vc.proofs.first().unwrap().signature.as_ref(), "eyJhbGciOiJFUzI1NkstUiIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..nwNfIHhCQlI-j58zgqwJgX2irGJNP8hqLis-xS16hMwzs3OuvjqzZIHlwvdzDMPopUA_Oq7M7Iql2LNe0B22oQE");
        }
        assert!(vc.verify(&verifier).await.unwrap().is_ok());

        // test that issuer property is used for verification
        let mut vc_bad_issuer = vc.clone();
        vc_bad_issuer.issuer = uri!("did:pkh:example:bad").to_owned().into();

        // It should fail.
        assert!(vc_bad_issuer.verify(&verifier).await.unwrap().is_err());

        // Check that proof JWK must match proof verificationMethod
        let wrong_key = JWK::generate_secp256k1();
        let wrong_signer = SingleSecretSigner::new(wrong_key.clone()).into_local();
        let vc_wrong_key = suite
            .sign(
                cred,
                &didethr,
                &wrong_signer,
                ProofOptions {
                    options: AnyInputSuiteOptions::default()
                        .with_public_key(wrong_key.to_public())
                        .unwrap(),
                    ..issue_options
                },
            )
            .await
            .unwrap();
        assert!(vc_wrong_key.verify(&verifier).await.unwrap().is_err());

        // Make it into a VP
        let presentation = JsonPresentation::new(
            Some(uri!("http://example.org/presentations/3731").to_owned()),
            None,
            vec![vc],
        );

        let vp_issue_options = ProofOptions::new(
            "2021-02-18T20:23:13Z".parse().unwrap(),
            IriBuf::new(format!("{did}#controller")).unwrap().into(),
            ProofPurpose::Authentication,
            AnyInputSuiteOptions::default(),
        );

        let vp = suite
            .sign(presentation, &didethr, &signer, vp_issue_options)
            .await
            .unwrap();

        println!("VP: {}", serde_json::to_string_pretty(&vp).unwrap());
        assert!(vp.verify(&verifier).await.unwrap().is_ok());

        // Mess with proof signature to make verify fail.
        let mut vp_fuzzed = vp.clone();
        vp_fuzzed.proofs.first_mut().unwrap().signature.alter();
        let vp_fuzzed_result = vp_fuzzed.verify(&verifier).await;
        assert!(vp_fuzzed_result.is_err() || vp_fuzzed_result.is_ok_and(|v| v.is_err()));

        // test that holder is verified
        let mut vp_bad_holder = vp;
        vp_bad_holder.holder = Some(uri!("did:pkh:example:bad").to_owned().into());

        // It should fail.
        assert!(vp_bad_holder.verify(&verifier).await.unwrap().is_err());
    }

    #[tokio::test]
    async fn credential_verify_eip712vm() {
        let didethr = DIDEthr.into_vm_resolver();
        let vc = ssi_claims::vc::v1::data_integrity::any_credential_from_json_str(include_str!(
            "../tests/vc.jsonld"
        ))
        .unwrap();
        // eprintln!("vc {:?}", vc);
        assert!(vc
            .verify(VerificationParameters::from_resolver(didethr))
            .await
            .unwrap()
            .is_ok())
    }
}
