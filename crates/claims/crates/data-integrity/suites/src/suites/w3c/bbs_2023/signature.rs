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

#[cfg(test)]
mod tests {
    use lazy_static::lazy_static;
    use ssi_data_integrity_core::suite::standard::SignatureAlgorithm;
    use ssi_di_sd_primitives::JsonPointerBuf;

    use crate::bbs_2023::{
        hashing::BaseHashData, transformation::TransformedBase, Bbs2023InputOptions, FeatureOption,
        HashData, HmacKey,
    };

    use super::Bbs2023SignatureAlgorithm;

    lazy_static! {
        pub static ref MANDATORY_POINTERS: Vec<JsonPointerBuf> = vec![
            "/issuer".parse().unwrap(),
            "/credentialSubject/sailNumber".parse().unwrap(),
            "/credentialSubject/sails/1".parse().unwrap(),
            "/credentialSubject/boards/0/year".parse().unwrap(),
            "/credentialSubject/sails/2".parse().unwrap()
        ];
    }

    const PUBLIC_KEY_HEX: &str = "a4ef1afa3da575496f122b9b78b8c24761531a8a093206ae7c45b80759c168ba4f7a260f9c3367b6c019b4677841104b10665edbe70ba3ebe7d9cfbffbf71eb016f70abfbb163317f372697dc63efd21fc55764f63926a8f02eaea325a2a888f";
    const SECRET_KEY_HEX: &str = "66d36e118832af4c5e28b2dfe1b9577857e57b042a33e06bdea37b811ed09ee0";
    const HMAC_KEY_STRING: &str =
        "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF";

    fn test_base_proof_serialization() {
        let mut proof_hash = [0; 32];
        hex::decode_to_slice(
            b"3a5bbf25d34d90b18c35cd2357be6a6f42301e94fc9e52f77e93b773c5614bdf",
            &mut proof_hash,
        )
        .unwrap();

        let mut mandatory_hash = [0; 32];
        hex::decode_to_slice(
            b"555de05f898817e31301bac187d0c3ff2b03e2cbdb4adb4d568c17de961f9a18",
            &mut mandatory_hash,
        )
        .unwrap();

        let mut hmac_key = HmacKey::default();
        hex::decode_to_slice(HMAC_KEY_STRING.as_bytes(), &mut hmac_key).unwrap();

        let mandatory = Vec::new();
        let non_mandatory = Vec::new();

        Bbs2023SignatureAlgorithm::sign(
            verification_method,
            signer,
            &HashData::Base(BaseHashData {
                transformed_document: TransformedBase {
                    options: Bbs2023InputOptions {
                        mandatory_pointers: MANDATORY_POINTERS.clone(),
                        feature_option: FeatureOption::Baseline,
                        commitment_with_proof: None,
                        hmac_key: None,
                    },
                    mandatory,
                    non_mandatory,
                    hmac_key,
                    canonical_configuration,
                },
                proof_hash,
                mandatory_hash,
            }),
            proof_configuration,
        );

        todo!()
    }
}
