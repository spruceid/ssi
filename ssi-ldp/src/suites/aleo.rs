use super::super::*;
use serde_json::Value;
use ssi_caips::caip10::BlockchainAccountId;
use ssi_dids::did_resolve::{resolve_vm, DIDResolver};
use ssi_json_ld::ContextLoader;
use ssi_jwk::{Base64urlUInt, JWK};
use std::collections::HashMap as Map;

/// Aleo Signature 2021
///
/// Linked data signature suite using [Aleo](crate::aleo).
///
/// # Suite definition
///
/// Aleo Signature 2021 is a [Linked Data Proofs][ld-proofs] signature suite consisting of the
/// following algorithms:
///
/// |         Parameter          |               Value               |        Specification       |
/// |----------------------------|-----------------------------------|----------------------------|
/// |id                          |https://w3id.org/security#AleoSignature2021|[this document](#)  |
/// |[canonicalization algorithm]|https://w3id.org/security#URDNA2015|[RDF Dataset Normalization 1.0][URDNA2015]|
/// |[message digest algorithm]  |[SHA-256]                          |[RFC4634]                   |
/// |[signature algorithm]       |Schnorr signature with [Edwards BLS12] curve|[Aleo Documentation - Accounts][aleo-accounts]|
///
/// The proof object must contain a [proofValue] property encoding the signature in
/// [Multibase] format.
///
/// ## Verification method
///
/// Aleo Signature 2021 may be used with the following verification method types:
///
/// |            Name            |                IRI                |        Specification       |
/// |----------------------------|-----------------------------------|----------------------------|
/// |       AleoMethod2021       |https://w3id.org/security#AleoMethod2021|   [this document](#)  |
/// |BlockchainVerificationMethod2021|https://w3id.org/security#BlockchainVerificationMethod2021|[Blockchain Vocabulary v1][blockchainvm2021]
///
/// The verification method object must have a [blockchainAccountId] property, identifying the
/// signer's Aleo
/// account address and network id for verification purposes. The chain id part of the account address
/// identifies an Aleo network as specified in the proposed [CAIP for Aleo Blockchain
/// Reference][caip-aleo-chain-ref]. Signatures use parameters defined per network. Currently only
/// network id "1" (CAIP-2 "aleo:1" / [Aleo Testnet I][testnet1]) is supported. The account
/// address format is documented in [Aleo
/// documentation](https://developer.aleo.org/aleo/concepts/accounts#account-address).
///
/// [message digest algorithm]: https://w3id.org/security#digestAlgorithm
/// [signature algorithm]: https://w3id.org/security#signatureAlgorithm
/// [canonicalization algorithm]: https://w3id.org/security#canonicalizationAlgorithm
/// [ld-proofs]: https://w3c-ccg.github.io/ld-proofs/
/// [proofValue]: https://w3id.org/security#proofValue
/// [Multibase]: https://datatracker.ietf.org/doc/html/draft-multiformats-multibase
/// [URDNA2015]: https://json-ld.github.io/rdf-dataset-canonicalization/spec/
/// [RFC4634]: https://www.rfc-editor.org/rfc/rfc4634 "US Secure Hash Algorithms (SHA and HMAC-SHA)"
/// [SHA-256]: http://www.w3.org/2001/04/xmlenc#sha256
/// [Edwards BLS12]: https://developer.aleo.org/autogen/advanced/the_aleo_curves/edwards_bls12
/// [aleo-accounts]: https://developer.aleo.org/aleo/concepts/accounts
/// [blockchainvm2021]: https://w3id.org/security/suites/blockchain-2021#BlockchainVerificationMethod2021
/// [blockchainAccountId]: https://w3c-ccg.github.io/security-vocab/#blockchainAccountId
/// [caip-aleo-chain-ref]: https://github.com/ChainAgnostic/CAIPs/pull/84
/// [testnet1]: https://developer.aleo.org/testnet/getting_started/overview/
pub struct AleoSignature2021;
impl AleoSignature2021 {
    pub(crate) async fn sign(
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        context_loader: &mut ContextLoader,
        key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<Proof, Error> {
        let has_context =
            document_has_context(document, iri!("TODO:uploadAleoVMContextSomewhere"))?;
        let mut proof = Proof {
            context: if has_context {
                Value::Null
            } else {
                serde_json::json!([ALEOVM_CONTEXT.clone()])
            },
            ..Proof::new(ProofSuiteType::AleoSignature2021)
                .with_options(options)
                .with_properties(extra_proof_properties)
        };
        let message = to_jws_payload(document, &proof, context_loader).await?;
        let sig = ssi_jwk::aleo::sign(&message, key)?;
        let sig_mb = multibase::encode(multibase::Base::Base58Btc, sig);
        proof.proof_value = Some(sig_mb);
        Ok(proof)
    }

    pub(crate) async fn prepare(
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        context_loader: &mut ContextLoader,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<ProofPreparation, Error> {
        let proof = Proof {
            context: serde_json::json!([SOLVM_CONTEXT.clone()]),
            ..Proof::new(ProofSuiteType::AleoSignature2021)
                .with_options(options)
                .with_properties(extra_proof_properties)
        };
        let message = to_jws_payload(document, &proof, context_loader).await?;
        Ok(ProofPreparation {
            proof,
            jws_header: None,
            signing_input: SigningInput::Bytes(Base64urlUInt(message)),
        })
    }

    pub(crate) async fn verify(
        proof: &Proof,
        document: &(dyn LinkedDataDocument + Sync),
        resolver: &dyn DIDResolver,
        context_loader: &mut ContextLoader,
    ) -> Result<VerificationWarnings, Error> {
        const NETWORK_ID: &str = "1";
        const NAMESPACE: &str = "aleo";
        let sig_mb = proof
            .proof_value
            .as_ref()
            .ok_or(Error::MissingProofSignature)?;
        let (_base, sig) = multibase::decode(sig_mb)?;
        let verification_method = proof
            .verification_method
            .as_ref()
            .ok_or(Error::MissingVerificationMethod)?;
        let vm = resolve_vm(verification_method, resolver).await?;
        if vm.type_ != "AleoMethod2021" && vm.type_ != "BlockchainVerificationMethod2021" {
            return Err(Error::VerificationMethodMismatch);
        }
        let account_id: BlockchainAccountId =
            vm.blockchain_account_id.ok_or(Error::MissingKey)?.parse()?;
        if account_id.chain_id.namespace != NAMESPACE {
            return Err(Error::UnexpectedCAIP2Namespace(
                NAMESPACE.to_string(),
                account_id.chain_id.namespace.to_string(),
            ));
        }
        if account_id.chain_id.reference != NETWORK_ID {
            return Err(Error::UnexpectedAleoNetwork(
                NETWORK_ID.to_string(),
                account_id.chain_id.namespace.to_string(),
            ));
        }
        let message = to_jws_payload(document, proof, context_loader).await?;
        ssi_jwk::aleo::verify(&message, &account_id.account_address, &sig)?;
        Ok(Default::default())
    }
}
