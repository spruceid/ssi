use std::borrow::Cow;

use ssi_bbs::Bbs;
use ssi_claims_core::SignatureError;
use ssi_data_integrity_core::{
    suite::standard::{SignatureAlgorithm, SignatureAndVerificationAlgorithm},
    ProofConfigurationRef,
};
use ssi_rdf::IntoNQuads;
use ssi_verification_methods::{multikey::DecodedMultikey, MultiMessageSigner, Multikey, Signer};

use crate::{bbs_2023::Bbs2023SignatureDescription, Bbs2023};

use super::{Bbs2023Signature, FeatureOption, HashData};

pub struct Bbs2023SignatureAlgorithm;

impl SignatureAndVerificationAlgorithm for Bbs2023SignatureAlgorithm {
    type Signature = Bbs2023Signature;
}

impl<T> SignatureAlgorithm<Bbs2023, T> for Bbs2023SignatureAlgorithm
where
    T: Signer<Multikey>,
    T::MessageSigner: MultiMessageSigner<Bbs>,
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
                let DecodedMultikey::Bls12_381(public_key) = verification_method.decode()? else {
                    return Err(SignatureError::InvalidPublicKey);
                };
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

                let message_signer = signer
                    .for_method(Cow::Borrowed(verification_method))
                    .await
                    .ok_or(SignatureError::MissingSigner)?;

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
    use iref::Iri;
    use lazy_static::lazy_static;
    use nquads_syntax::Parse;
    use ssi_bbs::{BBSplusPublicKey, BBSplusSecretKey};
    use ssi_data_integrity_core::{suite::standard::SignatureAlgorithm, ProofConfiguration};
    use ssi_di_sd_primitives::JsonPointerBuf;
    use ssi_verification_methods::{Multikey, ProofPurpose, ReferenceOrOwned, SingleSecretSigner};
    use static_iref::{iri, uri};

    use crate::{
        bbs_2023::{
            hashing::BaseHashData, transformation::TransformedBase, Bbs2023BaseInputOptions,
            FeatureOption, HashData, HmacKey,
        },
        Bbs2023,
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

    const DID: &Iri = iri!("did:key:zUC7DerdEmfZ8f4pFajXgGwJoMkV1ofMTmEG5UoNvnWiPiLuGKNeqgRpLH2TV4Xe5mJ2cXV76gRN7LFQwapF1VFu6x2yrr5ci1mXqC1WNUrnHnLgvfZfMH7h6xP6qsf9EKRQrPQ#zUC7DerdEmfZ8f4pFajXgGwJoMkV1ofMTmEG5UoNvnWiPiLuGKNeqgRpLH2TV4Xe5mJ2cXV76gRN7LFQwapF1VFu6x2yrr5ci1mXqC1WNUrnHnLgvfZfMH7h6xP6qsf9EKRQrPQ");

    const MANDATORY: &str =
"_:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
_:b0 <https://www.w3.org/2018/credentials#credentialSubject> _:b3 .
_:b0 <https://www.w3.org/2018/credentials#issuer> <https://vc.example/windsurf/racecommittee> .
_:b2 <https://windsurf.grotto-networking.com/selective#year> \"2022\"^^<http://www.w3.org/2001/XMLSchema#integer> .
_:b3 <https://windsurf.grotto-networking.com/selective#boards> _:b2 .
_:b3 <https://windsurf.grotto-networking.com/selective#sailNumber> \"Earth101\" .
_:b3 <https://windsurf.grotto-networking.com/selective#sails> _:b6 .
_:b3 <https://windsurf.grotto-networking.com/selective#sails> _:b7 .
_:b6 <https://windsurf.grotto-networking.com/selective#sailName> \"Lahaina\" .
_:b6 <https://windsurf.grotto-networking.com/selective#size> \"6.1E0\"^^<http://www.w3.org/2001/XMLSchema#double> .
_:b6 <https://windsurf.grotto-networking.com/selective#year> \"2023\"^^<http://www.w3.org/2001/XMLSchema#integer> .
_:b7 <https://windsurf.grotto-networking.com/selective#sailName> \"Lahaina\" .
_:b7 <https://windsurf.grotto-networking.com/selective#size> \"7\"^^<http://www.w3.org/2001/XMLSchema#integer> .
_:b7 <https://windsurf.grotto-networking.com/selective#year> \"2020\"^^<http://www.w3.org/2001/XMLSchema#integer> .
";

    const NON_MANDATORY: &str =
"_:b1 <https://windsurf.grotto-networking.com/selective#sailName> \"Lahaina\" .
_:b1 <https://windsurf.grotto-networking.com/selective#size> \"7.8E0\"^^<http://www.w3.org/2001/XMLSchema#double> .
_:b1 <https://windsurf.grotto-networking.com/selective#year> \"2023\"^^<http://www.w3.org/2001/XMLSchema#integer> .
_:b2 <https://windsurf.grotto-networking.com/selective#boardName> \"CompFoil170\" .
_:b2 <https://windsurf.grotto-networking.com/selective#brand> \"Wailea\" .
_:b3 <https://windsurf.grotto-networking.com/selective#boards> _:b4 .
_:b3 <https://windsurf.grotto-networking.com/selective#sails> _:b1 .
_:b3 <https://windsurf.grotto-networking.com/selective#sails> _:b5 .
_:b4 <https://windsurf.grotto-networking.com/selective#boardName> \"Kanaha Custom\" .
_:b4 <https://windsurf.grotto-networking.com/selective#brand> \"Wailea\" .
_:b4 <https://windsurf.grotto-networking.com/selective#year> \"2019\"^^<http://www.w3.org/2001/XMLSchema#integer> .
_:b5 <https://windsurf.grotto-networking.com/selective#sailName> \"Kihei\" .
_:b5 <https://windsurf.grotto-networking.com/selective#size> \"5.5E0\"^^<http://www.w3.org/2001/XMLSchema#double> .
_:b5 <https://windsurf.grotto-networking.com/selective#year> \"2023\"^^<http://www.w3.org/2001/XMLSchema#integer> .
";

    #[async_std::test]
    async fn test_base_proof_serialization() {
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

        let mandatory = nquads_syntax::Document::parse_str(MANDATORY)
            .unwrap()
            .0
            .into_iter()
            .map(|q| nquads_syntax::strip_quad(q.0))
            .collect();
        let non_mandatory = nquads_syntax::Document::parse_str(NON_MANDATORY)
            .unwrap()
            .0
            .into_iter()
            .map(|q| nquads_syntax::strip_quad(q.0))
            .collect();

        let (public_key, secret_key) = key_pair();

        let verification_method = Multikey::from_public_key(
            DID.to_owned(),
            uri!("did:method:test").to_owned(),
            &public_key,
        );

        let signer = SingleSecretSigner::new(secret_key);

        let canonical_configuration = vec![
            "_:c14n0 <http://purl.org/dc/terms/created> \"2023-08-15T23:36:38Z\"^^<http://www.w3.org/2001/XMLSchema#dateTime> .\n".to_string(),
            "_:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .\n".to_string(),
            "_:c14n0 <https://w3id.org/security#cryptosuite> \"bbs-2023\"^^<https://w3id.org/security#cryptosuiteString> .\n".to_string(),
            "_:c14n0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .\n".to_string(),
            "_:c14n0 <https://w3id.org/security#verificationMethod> <did:key:zUC7DerdEmfZ8f4pFajXgGwJoMkV1ofMTmEG5UoNvnWiPiLuGKNeqgRpLH2TV4Xe5mJ2cXV76gRN7LFQwapF1VFu6x2yrr5ci1mXqC1WNUrnHnLgvfZfMH7h6xP6qsf9EKRQrPQ#zUC7DerdEmfZ8f4pFajXgGwJoMkV1ofMTmEG5UoNvnWiPiLuGKNeqgRpLH2TV4Xe5mJ2cXV76gRN7LFQwapF1VFu6x2yrr5ci1mXqC1WNUrnHnLgvfZfMH7h6xP6qsf9EKRQrPQ> .\n".to_string()
        ];
        let proof_configuration = ProofConfiguration::new(
            Bbs2023,
            xsd_types::DateTime::now_ms(),
            ReferenceOrOwned::Reference("did:method:test".parse().unwrap()),
            ProofPurpose::Assertion,
            (),
        );

        let signature = Bbs2023SignatureAlgorithm::sign(
            &verification_method,
            signer,
            HashData::Base(BaseHashData {
                transformed_document: TransformedBase {
                    options: Bbs2023BaseInputOptions {
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
            proof_configuration.borrowed(),
        )
        .await
        .unwrap();

        assert_eq!(signature.proof_value.as_str(), "u2V0ChVhQhruAY3aNS3CPmmWCHub-Qms9T2_lwsXJpfgMqlc_2MIMvfF4Jv5OGmJAcLpfIB2SAqD861WELqnmGnKnqgSJFDf8Nfarnvi_jsMATMRslFhYQDpbvyXTTZCxjDXNI1e-am9CMB6U_J5S936Tt3PFYUvfVV3gX4mIF-MTAbrBh9DD_ysD4svbSttNVowX3pYfmhhYYKTvGvo9pXVJbxIrm3i4wkdhUxqKCTIGrnxFuAdZwWi6T3omD5wzZ7bAGbRneEEQSxBmXtvnC6Pr59nPv_v3HrAW9wq_uxYzF_NyaX3GPv0h_FV2T2OSao8C6uoyWiqIj1ggABEiM0RVZneImaq7zN3u_wARIjNEVWZ3iJmqu8zd7v-FZy9pc3N1ZXJ4HS9jcmVkZW50aWFsU3ViamVjdC9zYWlsTnVtYmVyeBovY3JlZGVudGlhbFN1YmplY3Qvc2FpbHMvMXggL2NyZWRlbnRpYWxTdWJqZWN0L2JvYXJkcy8wL3llYXJ4Gi9jcmVkZW50aWFsU3ViamVjdC9zYWlscy8y")
    }

    fn key_pair() -> (BBSplusPublicKey, BBSplusSecretKey) {
        (
            BBSplusPublicKey::from_bytes(&hex::decode(PUBLIC_KEY_HEX).unwrap()).unwrap(),
            BBSplusSecretKey::from_bytes(&hex::decode(SECRET_KEY_HEX).unwrap()).unwrap(),
        )
    }
}
