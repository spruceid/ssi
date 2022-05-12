//! [CACAO-ZCAP](https://demo.didkit.dev/2022/cacao-zcap/) implementation

mod core;
pub use crate::core::*;
#[cfg(feature = "verify")]
pub mod proof;
pub mod translation;

pub use cacaos;

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use cacaos::siwe::Message;
    use cacaos::siwe_cacao::SignInWithEthereum;
    use cacaos::{BasicSignature, Payload, CACAO};
    use pretty_assertions::assert_eq;

    pub struct ExampleDIDPKH;
    use async_trait::async_trait;
    use serde_json::Value;
    use ssi::did::{DIDMethod, Document};
    use ssi::did_resolve::{
        DIDResolver, DocumentMetadata, ResolutionInputMetadata, ResolutionMetadata, ERROR_NOT_FOUND,
    };

    use crate::translation::cacao_to_zcap::cacao_to_zcap;
    use crate::translation::zcap_to_cacao::zcap_to_cacao;
    use crate::CapabilityChainItem;
    const EXAMPLE_DID: &str = "did:pkh:eip155:1:0x6da01670d8fc844e736095918bbe11fe8d564163";
    const DOC_JSON: &str = r#"
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    {
      "EcdsaSecp256k1RecoveryMethod2020": "https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#EcdsaSecp256k1RecoveryMethod2020",
      "blockchainAccountId": "https://w3id.org/security#blockchainAccountId"
    }
  ],
  "id": "did:pkh:eip155:1:0x6da01670d8fc844e736095918bbe11fe8d564163",
  "verificationMethod": [
    {
      "id": "did:pkh:eip155:1:0x6da01670d8fc844e736095918bbe11fe8d564163#blockchainAccountId",
      "type": "EcdsaSecp256k1RecoveryMethod2020",
      "controller": "did:pkh:eip155:1:0x6da01670d8fc844e736095918bbe11fe8d564163",
      "blockchainAccountId": "eip155:1:0x6da01670d8fc844e736095918bbe11fe8d564163"
    }
  ],
  "authentication": [
    "did:pkh:eip155:1:0x6da01670d8fc844e736095918bbe11fe8d564163#blockchainAccountId"
  ],
  "assertionMethod": [
    "did:pkh:eip155:1:0x6da01670d8fc844e736095918bbe11fe8d564163#blockchainAccountId"
  ]
}
    "#;
    #[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
    #[cfg_attr(not(target_arch = "wasm32"), async_trait)]
    impl DIDMethod for ExampleDIDPKH {
        fn name(&self) -> &'static str {
            return "pkh";
        }
        fn to_resolver(&self) -> &dyn DIDResolver {
            self
        }
    }
    #[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
    #[cfg_attr(not(target_arch = "wasm32"), async_trait)]
    impl DIDResolver for ExampleDIDPKH {
        async fn resolve(
            &self,
            did: &str,
            _input_metadata: &ResolutionInputMetadata,
        ) -> (
            ResolutionMetadata,
            Option<Document>,
            Option<DocumentMetadata>,
        ) {
            if did != EXAMPLE_DID {
                return (ResolutionMetadata::from_error(ERROR_NOT_FOUND), None, None);
            }
            let doc: Document = match serde_json::from_str(DOC_JSON) {
                Ok(doc) => doc,
                Err(err) => {
                    return (ResolutionMetadata::from_error(&err.to_string()), None, None);
                }
            };
            (
                Default::default(),
                Some(doc),
                Some(DocumentMetadata::default()),
            )
        }
    }

    #[async_std::test]
    async fn siwe_verify() {
        let message = Message::from_str(
            r#"localhost:4361 wants you to sign in with your Ethereum account:
0x6Da01670d8fc844e736095918bbE11fE8D564163

SIWE Notepad Example

URI: http://localhost:4361
Version: 1
Chain ID: 1
Nonce: kEWepMt9knR6lWJ6A
Issued At: 2021-12-07T18:28:18.807Z"#,
        )
        .unwrap();
        let payload = Payload::from(message);
        // Sanity check: verify signature
        let sig_mb = r#"f6228b3ecd7bf2df018183aeab6b6f1db1e9f4e3cbe24560404112e25363540eb679934908143224d746bbb5e1aa65ab435684081f4dbb74a0fec57f98f40f5051c"#;
        let (_base, sig) = multibase::decode(&sig_mb).unwrap();
        let sig = BasicSignature {
            s: sig.try_into().unwrap(),
        };
        let cacao = CACAO::<SignInWithEthereum>::new(payload, sig);
        cacao.verify().await.unwrap();
        // This SIWE is not expected to be valid as a CACAO Zcap, but is here as an example that is
        // verifiable.
    }

    #[async_std::test]
    async fn zcap_cacao_kepler_session() {
        let siwe_msg_str = include_str!("../tests/delegation0.siwe");
        let siwe_msg_sig_hex = include_str!("../tests/delegation0.siwe.sig");
        let siwe_msg = Message::from_str(siwe_msg_str).unwrap();
        let payload = Payload::from(siwe_msg);
        let (_base, sig) = multibase::decode(&format!("f{}", siwe_msg_sig_hex)).unwrap();
        let sig = BasicSignature {
            s: sig.try_into().unwrap(),
        };
        let cacao = CACAO::<SignInWithEthereum>::new(payload, sig);
        let zcap = cacao_to_zcap(&cacao).unwrap();
        let zcap_json = serde_json::to_value(&zcap).unwrap();
        let zcap_json_expected: Value =
            serde_json::from_str(include_str!("../tests/delegation0-zcap.jsonld")).unwrap();
        assert_eq!(zcap_json, zcap_json_expected);

        let _resolver = ExampleDIDPKH;
        // Verify cacao as zcap
        /* Can't call zcap.verify yet because that depends on ssi
         * having this proof type.
        use ssi::vc::Check;
        let res = zcap.verify(None, &resolver).await;
        assert_eq!(res.errors, Vec::<String>::new());
        assert!(res.checks.iter().any(|c| c == &Check::Proof));
        */

        /* Can't verify because signature is not real
        let proof = zcap.proof.as_ref().unwrap();
        let warnings = CacaoZcapProof2022
            .verify(proof, &zcap, &resolver)
            .await
            .unwrap();
        dbg!(warnings);
        */

        // Convert back
        let cacao = zcap_to_cacao::<SignInWithEthereum>(&zcap).unwrap();
        let msg: Message = cacao.payload().clone().try_into().unwrap();
        assert_eq!(msg.to_string(), siwe_msg_str);
    }

    #[async_std::test]
    async fn zcap_cacao_kepler_session_subdelegation() {
        // Note: the delegation change is not verified currently. To make sense, it should be
        // updated here so that the invoker in the first delegation is a PKH DID matches issuer of the
        // second delegation.
        let siwe_msg_str = include_str!("../tests/delegation1.siwe");
        let siwe_msg_sig_hex = include_str!("../tests/delegation1.siwe.sig");
        let siwe_msg = Message::from_str(siwe_msg_str).unwrap();
        let message: Payload = siwe_msg.into();
        let (_base, sig) = multibase::decode(&format!("f{}", siwe_msg_sig_hex)).unwrap();
        let sig = BasicSignature {
            s: sig.try_into().unwrap(),
        };
        let cacao = CACAO::<SignInWithEthereum>::new(message, sig);
        let zcap = cacao_to_zcap(&cacao).unwrap();
        let zcap_json = serde_json::to_value(&zcap).unwrap();

        // Ensure last resource matches parent
        let parent_expected_str = include_str!("../tests/delegation0-zcap.jsonld");
        let parent_expected_json: Value = serde_json::from_str(parent_expected_str).unwrap();
        let last_resource = cacao.payload().resources.iter().next_back().unwrap();
        let parent_capability = CapabilityChainItem::from_resource_uri(&last_resource).unwrap();
        let parent_zcap_json = serde_json::to_value(parent_capability).unwrap();
        assert_eq!(parent_zcap_json, parent_expected_json);

        let zcap_json_expected: Value =
            serde_json::from_str(include_str!("../tests/delegation1-zcap.jsonld")).unwrap();
        assert_eq!(zcap_json, zcap_json_expected);

        // Convert back
        let cacao = zcap_to_cacao::<SignInWithEthereum>(&zcap).unwrap();
        let msg: Message = cacao.payload().clone().try_into().unwrap();
        assert_eq!(msg.to_string(), siwe_msg_str);
    }
}
