use ssi_claims_core::SignatureError;
use ssi_data_integrity_core::{
    suite::standard::{SignatureAlgorithm, SignatureAndVerificationAlgorithm},
    ProofConfigurationRef,
};
use ssi_rdf::IntoNQuads;
use ssi_verification_methods::{Multikey, SigningMethod};

use crate::Bbs2023;

use super::{Bbs2023Signature, FeatureOption, HashData};

pub enum Bbs {
    Baseline {
        header: [u8; 64],
    },
    Blind {
        header: [u8; 64],
        signer_blind: Option<u32>,
    },
    Pseudonym1 {
        header: [u8; 64],
        pid: u32,
    },
    Pseudonym2 {
        header: [u8; 64],
        commitment_with_proof: String,
        signer_blind: Option<u32>,
    },
}

pub trait MultiSigner<M, A> {
    type MessageSigner: MultiMessageSigner<A>;

    async fn for_verification_method(
        &self,
        method: &M,
    ) -> Result<Self::MessageSigner, SignatureError>;
}

pub trait MultiMessageSigner<A> {
    async fn multi_sign(
        self,
        algorithm: A,
        messages: &[Vec<u8>],
    ) -> Result<Vec<u8>, SignatureError>;
}

pub struct Bbs2023SignatureAlgorithm;

impl SignatureAndVerificationAlgorithm for Bbs2023SignatureAlgorithm {
    type Signature = Bbs2023Signature;
}

impl<T> SignatureAlgorithm<Bbs2023, T> for Bbs2023SignatureAlgorithm
where
    T: MultiSigner<Multikey, Bbs>,
{
    async fn sign(
        verification_method: &Multikey,
        signer: T,
        prepared_claims: HashData,
        proof_configuration: ProofConfigurationRef<'_, Bbs2023>,
    ) -> Result<Self::Signature, SignatureError> {
        match prepared_claims {
            HashData::Base(hash_data) => {
                // See: <https://www.w3.org/TR/vc-di-bbs/#base-proof-serialization-bbs-2023>
                let feature_option = hash_data.transformed_document.feature_option;
                let proof_hash = &hash_data.proof_hash;
                let mandatory_pointers = &hash_data.transformed_document.mandatory_pointers;
                let mandatory_hash = &hash_data.mandatory_hash;
                let non_mandatory = &hash_data.transformed_document.non_mandatory;
                let hmap_key = hash_data.transformed_document.hmac_key;

                let mut bbs_header = [0; 64];
                bbs_header[..32].copy_from_slice(proof_hash);
                bbs_header[32..].copy_from_slice(mandatory_hash);

                let mut bbs_messages: Vec<_> = non_mandatory
                    .into_nquads_lines()
                    .into_iter()
                    .map(String::into_bytes)
                    .collect();

                let message_signer = signer.for_verification_method(verification_method).await?;

                let bbs_signature = match feature_option {
                    FeatureOption::Baseline => {
                        message_signer
                            .multi_sign(Bbs::Baseline { header: bbs_header }, &bbs_messages)
                            .await?
                    }
                    FeatureOption::AnonymousHolderBinding => {
                        message_signer
                            .multi_sign(
                                Bbs::Blind {
                                    header: bbs_header,
                                    signer_blind: None,
                                },
                                &bbs_messages,
                            )
                            .await?
                    }
                    FeatureOption::PseudonymIssuerPid => {
                        let mut pid_buffer = [0u8; 4];
                        getrandom::getrandom(&mut pid_buffer);
                        let pid = u32::from_ne_bytes(pid_buffer);
                        message_signer
                            .multi_sign(
                                Bbs::Pseudonym1 {
                                    header: bbs_header,
                                    pid,
                                },
                                &bbs_messages,
                            )
                            .await?
                    }
                    FeatureOption::PseudonymHiddenPid => {
                        todo!()
                    }
                };

                // Ok(Bbs2023Signature::new(description))
                todo!()
            }
            HashData::Derived(_) => {
                todo!()
            }
        }
    }
}

struct BbsSecretKey;

impl SigningMethod<BbsSecretKey, Bbs> for Multikey {
    fn sign_bytes(
        &self,
        secret: &BbsSecretKey,
        algorithm: Bbs,
        bytes: &[u8],
    ) -> Result<Vec<u8>, ssi_verification_methods::MessageSignatureError> {
        todo!()
    }
}
