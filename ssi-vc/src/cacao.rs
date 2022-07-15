use crate::one_or_many::OneOrMany;
use crate::vc::{CredentialOrJWT, URI};

use cacaos::{siwe_cacao::SiweCacao, CACAO};
use libipld::{cbor::DagCborCodec, codec::Decode};
use serde::{Deserialize, Serialize};
use siwe_capability_delegation::{verify_statement_matches_delegations, RESOURCE_PREFIX};
use std::convert::TryInto;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum HolderBindingDelegation {
    // TODO
    // IRIRef(crate::rdf::IRIRef),
    Base64Block(String),
}

impl HolderBindingDelegation {
    pub async fn validate(
        &self,
        id: Option<&URI>,
        credentials: Option<&OneOrMany<CredentialOrJWT>>,
        holder: Option<&URI>,
    ) -> Result<Option<String>, String> {
        #[warn(clippy::infallible_destructuring_match)]
        let base64_cacao = match self {
            HolderBindingDelegation::Base64Block(b) => b,
        };
        let cbor_cacao = if let Some(b) = base64_cacao.strip_prefix("data:;base64,") {
            base64::decode(b)
                .map_err(|_| "Invalid base 64 encoding for the cacao delegation".to_string())?
        } else {
            return Err(String::from("Invalid cacao delegation"));
        };
        let cacao: SiweCacao = CACAO::decode(DagCborCodec, &mut std::io::Cursor::new(cbor_cacao))
            .map_err(|e| format!("Could not decode cacao delegation: {}", e))?;
        if let Err(e) = cacao.verify().await {
            return Err(format!("Verification of CACAO failed: {}", e));
        }
        let payload = cacao.payload();
        let delegator = &payload.iss;
        let delegee = &payload.aud;
        if let Some(credentials) = credentials {
            // TODO remove clone
            let credentials = match credentials.clone() {
                OneOrMany::One(c) => vec![c],
                OneOrMany::Many(cs) => cs,
            };
            for credential in credentials {
                let subjects = match credential {
                    CredentialOrJWT::Credential(c) => c.credential_subject,
                    _ => return Err("JWT VCs not handled".to_string()),
                };
                let subjects = match subjects {
                    OneOrMany::Many(ss) => ss,
                    OneOrMany::One(s) => vec![s],
                };
                println!("{:?}", subjects);
                if !subjects.iter().any(|subject| {
                    if let Some(i) = &subject.id {
                        i.to_string() == *delegator
                    } else {
                        false
                    }
                }) {
                    return Ok(None);
                }
            }
        }
        // TODO Do we want to support VPs without VCs?
        // else {
        //     return Ok(None);
        // }
        if let Some(h) = holder {
            if *delegee != h.to_string() {
                return Ok(None);
            }
        } else {
            return Ok(None);
        }
        if payload.resources.is_empty() {
            return Ok(None);
        }

        // TODO if any of the fully-qualified array items in type prepended with the String type: in the verifiable credential matches the resource of the targeted action
        if !payload.resources.iter().any(|resource| {
            *resource
                == format!(
                    // TODO Should probably go through the siwe_capability_delegation crate
                    "{}{}:eyJkZWZhdWx0QWN0aW9ucyI6WyJwcmVzZW50Il19",
                    RESOURCE_PREFIX,
                    id.unwrap()
                )
        }) {
            return Ok(None);
        };

        if !verify_statement_matches_delegations(
            &payload
                .clone()
                .try_into()
                .map_err(|e: cacaos::siwe_cacao::SIWEPayloadConversionError| e.to_string())?,
        )
        .map_err(|e| e.to_string())?
        {
            return Ok(None);
        }

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

    async fn test_holder_binding_vp(
        resource_id: &str,
        holder: &str,
        holder_binding: &str,
    ) -> Vec<String> {
        use cacaos::{siwe, siwe_cacao::SiweCacao};
        use k256::{ecdsa::signature::Signer, elliptic_curve::sec1::ToEncodedPoint};
        use keccak_hash::keccak;
        use libipld::{cbor::DagCborCodec, multihash::Code, store::DefaultParams, Block};
        use siwe_capability_delegation::{Builder, Namespace};
        use std::convert::{TryFrom, TryInto};

        let key = JWK::generate_secp256k1().unwrap();
        let ec_params = match &key.params {
            crate::jwk::Params::EC(ec) => ec,
            _ => panic!(),
        };
        let secret_key = k256::SecretKey::try_from(ec_params).unwrap();
        let signing_key = k256::ecdsa::SigningKey::from(secret_key);

        let vc_namespace: Namespace = resource_id.parse().unwrap();
        let pk_hash: [u8; 20] = {
            let pk = k256::PublicKey::try_from(ec_params).unwrap();
            let pk_ec = pk.to_encoded_point(false);
            let pk_bytes = pk_ec.as_bytes();
            let hash = keccak(&pk_bytes[1..65]).to_fixed_bytes();
            hash[12..32].try_into().unwrap()
        };
        let delegation_message = Builder::new()
            .with_default_actions(&vc_namespace, vec!["present".into()])
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
        let vp_proof = if let Ok(p) = vp
            .generate_proof(&key, &vp_issue_options, &DIDExample, &mut context_loader)
            .await
        {
            p
        } else {
            return vec!["Failed signing".to_string()];
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
