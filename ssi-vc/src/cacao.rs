use crate::{CredentialOrJWT, URI};
use ssi_core::one_or_many::OneOrMany;

use cacaos::{
    siwe_cacao::{
        siwe, SIWEPayloadConversionError, SiweCacao, VerificationError as SiweVerificationError,
    },
    CACAO,
};
use libipld::{cbor::DagCborCodec, codec::Decode};
use serde::{Deserialize, Serialize};
use siwe_recap::{extract_capabilities, verify_statement, Error as ReCapError};
use std::convert::TryInto;
use thiserror::Error;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(untagged)]
pub enum BindingDelegation {
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
    ReCap(#[from] ReCapError),
}

impl From<SIWEPayloadConversionError> for Error {
    fn from(e: SIWEPayloadConversionError) -> Error {
        SiweVerificationError::from(e).into()
    }
}

impl BindingDelegation {
    /// presented credentials and a holder, return authorised holders
    pub async fn validate_presentation(
        &self,
        credentials: Option<&OneOrMany<CredentialOrJWT>>,
        holder: Option<&URI>,
    ) -> Result<Option<String>, Error> {
        let BindingDelegation::Base64Block(base64_cacao) = self;
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
    use crate::*;
    use ssi_dids::example::DIDExample;
    use ssi_jwk::JWK;

    use sha3::Digest;

    const VC_ID_1: &str = "http://example.edu/credentials/1872";
    const VC_ID_2: &str = "http://example.edu/credentials/0000";
    const VP_ID: &str = "uuid:my_vp";

    const DID_FOO: &str = "did:example:foo";
    const VM_FOO: &str = "did:example:foo#key1";
    const JWK_JSON_FOO: &str = include_str!("../../tests/rsa2048-2020-08-25.json");

    const DID_BAR: &str = "did:example:bar";
    const VM_BAR: &str = "did:example:bar#key1";
    const JWK_JSON_BAR: &str = include_str!("../../tests/ed25519-2021-06-16.json");

    async fn test_holder_binding_vp(
        bound_vc_id: Option<&str>,
        bound_holder: &str,
        presenter: (&str, &str, &JWK),
        credential: Option<(&str, (&str, &str, &JWK))>,
    ) -> Vec<String> {
        use cacaos::{siwe, siwe_cacao::SiweCacao};
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        use keccak_hash::keccak;
        use libipld::{cbor::DagCborCodec, multihash::Code, store::DefaultParams, Block};
        use siwe_recap::{Builder, Namespace};

        // generate eth account kp/id
        let key = JWK::generate_secp256k1().unwrap();
        let ec_params = match &key.params {
            ssi_jwk::Params::EC(ec) => ec,
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

        // delegate presentation of `bound_vc_id` to `bound_holder`
        let delegation_message = bound_vc_id
            .map(|r| Builder::new().with_action(&vc_namespace, r, "present"))
            .unwrap_or_else(Builder::new)
            .build(siwe::Message {
                domain: "example.com".parse().unwrap(),
                address: pk_hash,
                statement: None,
                uri: bound_holder.parse().unwrap(),
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

        let vc = if let Some((id, (iss, iss_vm, iss_key))) = credential {
            // issue cred to kp
            let did = format!(
                "did:pkh:eip155:1:{}",
                ssi_crypto::hashes::keccak::eip55_checksum_addr(
                    &ssi_crypto::hashes::keccak::bytes_to_lowerhex(&pk_hash)
                )
                .unwrap()
            );

            let mut credential: Credential = serde_json::from_value(serde_json::json!({
                "@context": "https://www.w3.org/2018/credentials/v1",
                "id": id,
                "type": ["VerifiableCredential"],
                "issuer": iss,
                "issuanceDate": "2020-08-19T21:41:50Z",
                "credentialSubject": {
                    "id": did,
                }
            }))
            .unwrap();
            let vc_issue_options = LinkedDataProofOptions {
                verification_method: Some(URI::String(iss_vm.to_string())),
                proof_purpose: Some(ProofPurpose::AssertionMethod),
                ..Default::default()
            };
            let mut context_loader = ssi_json_ld::ContextLoader::default();
            let proof = credential
                .generate_proof(iss_key, &vc_issue_options, &DIDExample, &mut context_loader)
                .await
                .unwrap();
            credential.add_proof(proof);
            Some(credential)
        } else {
            None
        };

        let data =
            ssi_crypto::hashes::keccak::prefix_personal_message(&delegation_message.to_string());
        let (sig, rec_id) = signing_key
            .sign_digest_recoverable(sha3::Keccak256::new_with_prefix(data))
            .unwrap();
        let mut delegation_sig = sig.to_vec();
        // Recovery ID starts at 27 instead of 0.
        delegation_sig.push(rec_id.to_byte() + 27);

        let delegation_cacao = SiweCacao::new(
            delegation_message.try_into().unwrap(),
            delegation_sig.try_into().unwrap(),
            None,
        );
        let delegation_block =
            Block::<DefaultParams>::encode(DagCborCodec, Code::Blake3_256, &delegation_cacao)
                .unwrap();
        let delegation_base64 = base64::encode(delegation_block.data());

        // `presenter` presents cred
        let mut vp: Presentation = serde_json::from_value(serde_json::json!({
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                {
                    "@vocab": "https://example.org/example-holder-binding#"
                }
            ],
            "id": VP_ID,
            "type": ["VerifiablePresentation"],
            "holderBinding": {
                "type": "CacaoDelegationHolderBinding2022",
                "cacaoDelegation": format!("data:;base64,{}", delegation_base64)
            },
            "holder": presenter.0
        }))
        .unwrap();

        vp.verifiable_credential =
            vc.map(|v| ssi_core::one_or_many::OneOrMany::One(CredentialOrJWT::Credential(v)));

        let mut context_loader = ssi_json_ld::ContextLoader::default();
        let vp_issue_options = LinkedDataProofOptions {
            verification_method: Some(URI::String(presenter.1.to_string())),
            proof_purpose: Some(ProofPurpose::Authentication),
            checks: None,
            ..Default::default()
        };
        let vp_proof = match vp
            .generate_proof(
                presenter.2,
                &vp_issue_options,
                &DIDExample,
                &mut context_loader,
            )
            .await
        {
            Ok(p) => p,
            Err(e) => {
                println!("{:?}", e);
                return vec!["Failed signing".to_string()];
            }
        };
        vp.add_proof(vp_proof);
        vp.validate().unwrap();
        let vp_verification_result = vp.verify(None, &DIDExample, &mut context_loader).await;
        println!("{:#?}", vp_verification_result);
        vp_verification_result.errors
    }

    #[async_std::test]
    async fn present_with_siwecacao_holder_binding() {
        let foo = (
            DID_FOO,
            VM_FOO,
            &serde_json::from_str(JWK_JSON_FOO).unwrap(),
        );
        let bar = (
            DID_BAR,
            VM_BAR,
            &serde_json::from_str(JWK_JSON_BAR).unwrap(),
        );

        // foo can present an empty pres on behalf of eth account, given empty siwe
        assert!(test_holder_binding_vp(None, foo.0, foo, None)
            .await
            .is_empty());

        // foo can present an empty pres on behalf of eth account, given non-empty siwe
        assert!(test_holder_binding_vp(Some(VC_ID_1), foo.0, foo, None)
            .await
            .is_empty());

        // foo can present a cred on behalf of eth account, given proper non-empty siwe
        assert!(
            test_holder_binding_vp(Some(VC_ID_1), foo.0, foo, Some((VC_ID_1, bar)))
                .await
                .is_empty()
        );

        // foo cannot present an empty pres on behalf of eth account, bar is the holder
        assert!(test_holder_binding_vp(None, bar.0, foo, None)
            .await
            .contains(&"No applicable proof".to_string()));

        // foo cannot present an empty pres on behalf of eth account, bar is the holder
        assert!(test_holder_binding_vp(Some(VC_ID_1), bar.0, foo, None)
            .await
            .contains(&"No applicable proof".to_string()));

        // foo cannot present a cred on behalf of eth account, bar is the holder
        assert!(
            test_holder_binding_vp(Some(VC_ID_1), bar.0, foo, Some((VC_ID_1, foo)))
                .await
                .contains(&"No applicable proof".to_string())
        );

        // foo cannot present a cred on behalf of eth account, wrong vc ID
        assert!(
            test_holder_binding_vp(Some(VC_ID_2), foo.0, foo, Some((VC_ID_1, bar)))
                .await
                .contains(&"No applicable proof".to_string())
        );
    }
}
