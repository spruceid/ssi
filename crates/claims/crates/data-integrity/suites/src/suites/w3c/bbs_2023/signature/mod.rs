use crate::Bbs2023;
use serde::{Deserialize, Serialize};
use ssi_bbs::Bbs;
use ssi_claims_core::{ProofValidationError, SignatureError};
use ssi_data_integrity_core::{
    signing::AlterSignature,
    suite::standard::{SignatureAlgorithm, SignatureAndVerificationAlgorithm},
    ProofConfigurationRef,
};
use ssi_security::MultibaseBuf;
use ssi_verification_methods::{MessageSigner, Multikey};

use super::HashData;

mod base;
mod derived;

pub struct InvalidBbs2023Signature;

impl From<InvalidBbs2023Signature> for ProofValidationError {
    fn from(_value: InvalidBbs2023Signature) -> Self {
        ProofValidationError::InvalidSignature
    }
}

#[derive(Debug, thiserror::Error)]
#[error("unsupported bbs-2023 signature type")]
pub struct UnsupportedBbs2023Signature;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Bbs2023Signature {
    pub proof_value: MultibaseBuf,
}

impl AsRef<str> for Bbs2023Signature {
    fn as_ref(&self) -> &str {
        self.proof_value.as_str()
    }
}

impl AlterSignature for Bbs2023Signature {
    fn alter(&mut self) {
        self.proof_value = MultibaseBuf::encode(multibase::Base::Base58Btc, [0])
    }
}

#[derive(Clone)]
pub enum Bbs2023SignatureDescription {
    Baseline,
    AnonymousHolderBinding { signer_blind: Option<[u8; 32]> },
    PseudonymIssuerPid { pid: [u8; 32] },
    PseudonymHiddenPid { signer_blind: Option<[u8; 32]> },
}

pub struct Bbs2023SignatureAlgorithm;

impl SignatureAndVerificationAlgorithm for Bbs2023SignatureAlgorithm {
    type Signature = Bbs2023Signature;
}

impl<T> SignatureAlgorithm<Bbs2023, T> for Bbs2023SignatureAlgorithm
where
    T: MessageSigner<Bbs>,
{
    async fn sign(
        verification_method: &Multikey,
        signer: T,
        prepared_claims: HashData,
        _proof_configuration: ProofConfigurationRef<'_, Bbs2023>,
    ) -> Result<Self::Signature, SignatureError> {
        match prepared_claims {
            HashData::Base(hash_data) => {
                base::generate_base_proof(verification_method, signer, hash_data).await
            }
            HashData::Derived(_) => Err(SignatureError::other(
                "unable to sign derived claims without a base proof",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use nquads_syntax::Parse;
    use ssi_data_integrity_core::{suite::standard::SignatureAlgorithm, ProofConfiguration};
    use ssi_di_sd_primitives::HmacSha256Key;
    use ssi_verification_methods::{
        Multikey, ProofPurpose, ReferenceOrOwned, Signer, SingleSecretSigner,
    };
    use static_iref::uri;

    use crate::{
        bbs_2023::{
            hashing::BaseHashData, transformation::TransformedBase, Bbs2023SignatureOptions,
            FeatureOption, HashData,
        },
        Bbs2023,
    };

    use super::{super::tests::*, Bbs2023SignatureAlgorithm};

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

        let mut hmac_key = HmacSha256Key::default();
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

        let verification_method = Multikey::from_public_key(
            VERIFICATION_METHOD_IRI.to_owned(),
            uri!("did:method:test").to_owned(),
            &*PUBLIC_KEY,
        );

        let signer = SingleSecretSigner::new(SECRET_KEY.clone());

        let canonical_configuration = vec![
            "_:c14n0 <http://purl.org/dc/terms/created> \"2023-08-15T23:36:38Z\"^^<http://www.w3.org/2001/XMLSchema#dateTime> .\n".to_string(),
            "_:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .\n".to_string(),
            "_:c14n0 <https://w3id.org/security#cryptosuite> \"bbs-2023\"^^<https://w3id.org/security#cryptosuiteString> .\n".to_string(),
            "_:c14n0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .\n".to_string(),
            "_:c14n0 <https://w3id.org/security#verificationMethod> <did:key:zUC7DerdEmfZ8f4pFajXgGwJoMkV1ofMTmEG5UoNvnWiPiLuGKNeqgRpLH2TV4Xe5mJ2cXV76gRN7LFQwapF1VFu6x2yrr5ci1mXqC1WNUrnHnLgvfZfMH7h6xP6qsf9EKRQrPQ#zUC7DerdEmfZ8f4pFajXgGwJoMkV1ofMTmEG5UoNvnWiPiLuGKNeqgRpLH2TV4Xe5mJ2cXV76gRN7LFQwapF1VFu6x2yrr5ci1mXqC1WNUrnHnLgvfZfMH7h6xP6qsf9EKRQrPQ> .\n".to_string()
        ];
        let proof_configuration = ProofConfiguration::new(
            Bbs2023,
            xsd_types::DateTimeStamp::now_ms(),
            ReferenceOrOwned::Reference("did:method:test".parse().unwrap()),
            ProofPurpose::Assertion,
            (),
        );

        let signature = Bbs2023SignatureAlgorithm::sign(
            &verification_method,
            signer
                .for_method(Cow::Borrowed(&verification_method))
                .await
                .unwrap()
                .unwrap(),
            HashData::Base(BaseHashData {
                transformed_document: TransformedBase {
                    options: Bbs2023SignatureOptions {
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
}
