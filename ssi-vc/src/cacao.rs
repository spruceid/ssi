use crate::one_or_many::OneOrMany;
use crate::vc::{CredentialOrJWT, URI};

use cacaos::{
    siwe_cacao::{
        siwe, SIWEPayloadConversionError, SiweCacao, VerificationError as SiweVerificationError,
    },
    CACAO,
};
use capgrok::{extract_capabilities, verify_statement, Error as CapGrokError, RESOURCE_PREFIX};
use libipld::{cbor::DagCborCodec, codec::Decode};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use thiserror::Error;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum HolderBindingDelegation {
    // TODO
    // IRIRef(crate::rdf::IRIRef),
    Base64Block(String),
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid Base64 Block")]
    InvalidBase64Block,
    #[error("JWT VCs not supported")]
    UnsupportedJwtVc,
    #[error(transparent)]
    Base64(#[from] base64::DecodeError),
    #[error(transparent)]
    SiweVerification(#[from] SiweVerificationError),
    #[error(transparent)]
    Ipld(#[from] libipld::error::Error),
    #[error(transparent)]
    CapGrok(#[from] CapGrokError),
}

impl From<SIWEPayloadConversionError> for Error {
    fn from(e: SIWEPayloadConversionError) -> Error {
        SiweVerificationError::from(e).into()
    }
}

impl HolderBindingDelegation {
    /// Given a presentation id, presented credentials and a holder, return authorised holders
    pub async fn validate(
        &self,
        id: Option<&URI>,
        credentials: Option<&OneOrMany<CredentialOrJWT>>,
        holder: Option<&URI>,
    ) -> Result<Option<String>, Error> {
        let HolderBindingDelegation::Base64Block(base64_cacao) = self;
        let cbor_cacao = if let Some(b) = base64_cacao.strip_prefix("data:;base64,") {
            base64::decode(b)?
        } else {
            return Err(Error::InvalidBase64Block);
        };
        let cacao: SiweCacao = CACAO::decode(DagCborCodec, &mut std::io::Cursor::new(cbor_cacao))?;
        cacao.verify().await?;
        let payload = cacao.payload();
        let delegator = &payload.iss;
        let delegee = &payload.aud;

        if let Some(h) = holder {
            if *delegee != h.to_string() {
                return Ok(None);
            }
        } else {
            return Ok(None);
        }

        let siwe: siwe::Message = payload.clone().try_into()?;
        if !verify_statement(&siwe)? {
            return Ok(None);
        }
        let capability = extract_capabilities(&siwe)?.remove(&"credentials".parse()?);

        match (credentials, capability) {
            (Some(credentials), Some(cap)) if !credentials.is_empty() => {
                for credential in credentials.into_iter() {
                    let (id, subjects) = match credential {
                        CredentialOrJWT::Credential(c) => (c.id.as_ref(), &c.credential_subject),
                        _ => return Err(Error::UnsupportedJwtVc),
                    };
                    println!("{:?}", subjects);
                    if let Some(i) = id {
                        // if the credential isnt presentable according to the siwe cap
                        if !cap.can(i.as_str(), "present") {
                            return Ok(None);
                        }
                    } else {
                        return Ok(None);
                    };
                    // if the delegator is not the subject of any of the credentials (?)
                    if !subjects.into_iter().all(|subject| {
                        subject
                            .id
                            .as_ref()
                            .map(|i| i.as_str() == delegator.as_str())
                            .unwrap_or(false)
                    }) {
                        return Ok(None);
                    }
                }
            }
            // creds with no cap is not allowed
            (Some(credentials), None) if !credentials.is_empty() => return Ok(None),
            // if there's no caps and no creds, that's ok
            // if there's caps and no creds, that's ok
            _ => {}
        };

        Ok(Some(delegee.to_string()))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::did::example::DIDExample;
    use crate::jwk::JWK;
    use crate::vc::*;

    const VC_ID: &str = "http://example.edu/credentials/1872";
    const JWK_JSON: &str = include_str!("../tests/rsa2048-2020-08-25.json");

    #[cfg(all(feature = "k256", feature = "keccak-hash"))]
    async fn test_holder_binding_vp(
        resource_id: &str,
        holder: &str,
        holder_binding: &str,
    ) -> Vec<String> {
        use cacaos::{siwe, siwe_cacao::SiweCacao};
        use capgrok::{Builder, Namespace};
        use k256::{ecdsa::signature::Signer, elliptic_curve::sec1::ToEncodedPoint};
        use keccak_hash::keccak;
        use libipld::{cbor::DagCborCodec, multihash::Code, store::DefaultParams, Block};
        use std::convert::{TryFrom, TryInto};

        let key = JWK::generate_secp256k1().unwrap();
        let ec_params = match &key.params {
            crate::jwk::Params::EC(ec) => ec,
            _ => panic!(),
        };
        let secret_key = k256::SecretKey::try_from(ec_params).unwrap();
        let signing_key = k256::ecdsa::SigningKey::from(secret_key);

        let vc_namespace: Namespace = "credentials".parse().unwrap();
        let pk_hash: [u8; 20] = {
            let pk = k256::PublicKey::try_from(ec_params).unwrap();
            let pk_ec = pk.to_encoded_point(false);
            let pk_bytes = pk_ec.as_bytes();
            let hash = keccak(&pk_bytes[1..65]).to_fixed_bytes();
            hash[12..32].try_into().unwrap()
        };
        let delegation_message = Builder::new()
            .with_action(&vc_namespace, resource_id, "present")
            .build(siwe::Message {
                domain: "example.com".parse().unwrap(),
                address: pk_hash,
                statement: None,
                uri: "did:example:foo".parse().unwrap(),
                version: siwe::Version::V1,
                chain_id: 1,
                nonce: "mynonce1".into(),
                issued_at: "2022-06-21T12:00:00.000Z".parse().unwrap(),
                expiration_time: None,
                not_before: None,
                request_id: None,
                resources: vec![],
            })
            .unwrap();
        println!("{}", delegation_message);

        let hash = crate::keccak_hash::prefix_personal_message(&delegation_message.to_string());
        let sig: k256::ecdsa::recoverable::Signature = signing_key.try_sign(&hash).unwrap();
        let mut delegation_sig = sig.as_ref().to_vec();
        delegation_sig[64] += 27;

        let delegation_cacao = SiweCacao::new(
            delegation_message.try_into().unwrap(),
            delegation_sig.try_into().unwrap(),
            None,
        );
        let delegation_block =
            Block::<DefaultParams>::encode(DagCborCodec, Code::Blake3_256, &delegation_cacao)
                .unwrap();
        let delegation_base64 = base64::encode(delegation_block.data());

        let mut vp: Presentation = serde_json::from_value(serde_json::json!({
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                {
                    "@vocab": "https://example.org/example-holder-binding#"
                }
            ],
            "id": VC_ID,
            "type": ["VerifiablePresentation"],
            "holderBinding": {
                "type": "CacaoDelegationHolderBinding2022",
                "cacaoDelegation": format!("data:;base64,{}", delegation_base64)
            },
            "holder": holder
        }))
        .unwrap();

        // let authorized_holders = vp.get_authorized_holders().await.unwrap();
        // assert!(authorized_holders.contains(&holder.to_string()));

        let mut context_loader = crate::jsonld::ContextLoader::default();
        let key: JWK = serde_json::from_str(JWK_JSON).unwrap();
        let mut vp_issue_options = LinkedDataProofOptions::default();
        let vp_proof_vm = format!("{}#key1", holder_binding);
        vp_issue_options.verification_method = Some(URI::String(vp_proof_vm));
        vp_issue_options.proof_purpose = Some(ProofPurpose::Authentication);
        vp_issue_options.checks = None;
        let vp_proof = match vp
            .generate_proof(&key, &vp_issue_options, &DIDExample, &mut context_loader)
            .await
        {
            Ok(p) => p,
            Err(e) => {
                println!("{:?}", e);
                return vec!["Failed signing".to_string()];
            }
        };
        vp.add_proof(vp_proof);
        println!("VP: {}", serde_json::to_string_pretty(&vp).unwrap());
        vp.validate().unwrap();
        let vp_verification_result = vp.verify(None, &DIDExample, &mut context_loader).await;
        println!("{:#?}", vp_verification_result);
        vp_verification_result.errors
    }

    #[cfg(all(feature = "k256", feature = "keccak-hash"))]
    #[async_std::test]
    async fn present_with_siwecacao_holder_binding() {
        assert!(
            test_holder_binding_vp(VC_ID, "did:example:foo", "did:example:foo")
                .await
                .is_empty()
        );

        assert!(
            test_holder_binding_vp(VC_ID, "did:example:bar", "did:example:foo")
                .await
                .contains(&"Failed signing".to_string())
        );

        assert!(test_holder_binding_vp(
            "http://example.edu/credentials/000",
            "did:example:foo",
            "did:example:foo"
        )
        .await
        .contains(&"No applicable proof".to_string()));

        // todo!();

        // TODO factor out the checks for every kind of holder binding
    }
}
