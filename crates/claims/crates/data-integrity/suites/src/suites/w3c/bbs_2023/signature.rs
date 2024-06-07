use ssi_bbs::{bbs_public_key_from_multikey, Bbs};
use ssi_claims_core::SignatureError;
use ssi_data_integrity_core::{
    suite::standard::{SignatureAlgorithm, SignatureAndVerificationAlgorithm},
    ProofConfigurationRef,
};
use ssi_rdf::IntoNQuads;
use ssi_verification_methods::{MultiMessageSigner, MultiSigner, Multikey};

use crate::{bbs_2023::Bbs2023SignatureDescription, Bbs2023};

use super::{Bbs2023Signature, FeatureOption, HashData};

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
        _proof_configuration: ProofConfigurationRef<'_, Bbs2023>,
    ) -> Result<Self::Signature, SignatureError> {
        match prepared_claims {
            HashData::Base(hash_data) => {
                // See: <https://www.w3.org/TR/vc-di-bbs/#base-proof-serialization-bbs-2023>
                let public_key = bbs_public_key_from_multikey(verification_method);
                let feature_option = hash_data.transformed_document.options.feature_option;
                let proof_hash = &hash_data.proof_hash;
                let mandatory_pointers = &hash_data.transformed_document.options.mandatory_pointers;
                let mandatory_hash = &hash_data.mandatory_hash;
                let non_mandatory = &hash_data.transformed_document.non_mandatory;
                let hmac_key = hash_data.transformed_document.hmac_key;

                let mut bbs_header = [0; 64];
                bbs_header[..32].copy_from_slice(proof_hash);
                bbs_header[32..].copy_from_slice(mandatory_hash);

                let mut messages: Vec<_> = non_mandatory
                    .into_nquads_lines()
                    .into_iter()
                    .map(String::into_bytes)
                    .collect();

                let message_signer = signer.for_verification_method(verification_method).await?;

                let (algorithm, description) = match feature_option {
                    FeatureOption::Baseline => (
                        Bbs::Baseline { header: bbs_header },
                        Bbs2023SignatureDescription::Baseline,
                    ),
                    FeatureOption::AnonymousHolderBinding => (
                        Bbs::Blind {
                            header: bbs_header,
                            commitment_with_proof: None,
                            signer_blind: None,
                        },
                        Bbs2023SignatureDescription::AnonymousHolderBinding { signer_blind: None },
                    ),
                    FeatureOption::PseudonymIssuerPid => {
                        // See: <https://www.ietf.org/archive/id/draft-vasilis-bbs-per-verifier-linkability-00.html#section-4.1>
                        let mut pid = [0u8; 32];
                        getrandom::getrandom(&mut pid).map_err(SignatureError::other)?;

                        messages.push(pid.to_vec());

                        (
                            Bbs::Baseline { header: bbs_header },
                            Bbs2023SignatureDescription::PseudonymIssuerPid { pid },
                        )
                    }
                    FeatureOption::PseudonymHiddenPid => {
                        // See: <https://www.ietf.org/archive/id/draft-vasilis-bbs-per-verifier-linkability-00.html#section-4.1>
                        let commitment_with_proof = hash_data
                            .transformed_document
                            .options
                            .commitment_with_proof
                            .clone()
                            .ok_or_else(|| {
                                SignatureError::missing_required_option("commitment_with_proof")
                            })?;

                        (
                            Bbs::Blind {
                                header: bbs_header,
                                commitment_with_proof: Some(commitment_with_proof),
                                signer_blind: None,
                            },
                            Bbs2023SignatureDescription::PseudonymHiddenPid { signer_blind: None },
                        )
                    }
                };

                let signature = message_signer.sign_multi(algorithm, &messages).await?;

                Ok(Bbs2023Signature::encode(
                    &signature,
                    bbs_header,
                    &public_key,
                    hmac_key,
                    &mandatory_pointers,
                    description,
                ))
            }
            HashData::Derived(_) => {
                todo!()
            }
        }
    }
}
