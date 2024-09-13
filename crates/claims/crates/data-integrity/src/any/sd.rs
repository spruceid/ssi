use serde::{Deserialize, Serialize};
use ssi_claims_core::ResolverProvider;
use ssi_core::JsonPointerBuf;
use ssi_data_integrity_core::{
    suite::{CryptographicSuiteSelect, SelectionError, SelectiveCryptographicSuite},
    DataIntegrity, ProofRef,
};
use ssi_json_ld::{Expandable, ExpandedDocument, JsonLdLoaderProvider, JsonLdNodeObject};
use ssi_rdf::LexicalInterpretation;
use ssi_verification_methods::{AnyMethod, VerificationMethodResolver};

use crate::AnySuite;

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct AnySelectionOptions {
    pub selective_pointers: Vec<JsonPointerBuf>,
    pub presentation_header: Option<Vec<u8>>,
}

#[cfg(all(feature = "w3c", feature = "bbs"))]
impl From<AnySelectionOptions> for ssi_data_integrity_suites::bbs_2023::DeriveOptions {
    fn from(value: AnySelectionOptions) -> Self {
        Self {
            selective_pointers: value.selective_pointers,
            presentation_header: value.presentation_header,
            feature_option: Default::default(),
        }
    }
}

#[cfg(all(feature = "w3c", feature = "secp256r1"))]
impl From<AnySelectionOptions> for ssi_data_integrity_suites::ecdsa_sd_2023::DeriveOptions {
    fn from(value: AnySelectionOptions) -> Self {
        Self {
            selective_pointers: value.selective_pointers,
        }
    }
}

impl SelectiveCryptographicSuite for AnySuite {
    type SelectionOptions = AnySelectionOptions;
}

impl<T, P> CryptographicSuiteSelect<T, P> for AnySuite
where
    T: Serialize + JsonLdNodeObject + Expandable,
    T::Expanded<LexicalInterpretation, ()>: Into<ExpandedDocument>,
    P: JsonLdLoaderProvider + ResolverProvider,
    P::Resolver: VerificationMethodResolver<Method = AnyMethod>,
{
    #[allow(unused_variables)]
    async fn select(
        &self,
        unsecured_document: &T,
        proof: ProofRef<'_, Self>,
        params: P,
        options: Self::SelectionOptions,
    ) -> Result<DataIntegrity<ssi_json_ld::syntax::Object, Self>, SelectionError> {
        let params = crate::AnyVerifier {
            resolver: crate::AnyResolver::<_, ssi_verification_methods::Multikey>::new(
                params.resolver(),
            ),
            json_ld_loader: params.loader(),
            eip712_loader: (),
        };

        match self {
            #[cfg(all(feature = "w3c", feature = "secp256r1"))]
            Self::EcdsaSd2023 => {
                let DataIntegrity { claims, proofs } = ssi_data_integrity_suites::EcdsaSd2023
                    .select(
                        unsecured_document,
                        crate::Project::project_proof(proof),
                        params,
                        options.into(),
                    )
                    .await?;

                Ok(DataIntegrity {
                    claims,
                    proofs: proofs
                        .into_iter()
                        .map(|p| {
                            p.map_type(
                                |_| Self::EcdsaSd2023,
                                crate::AnySuiteVerificationMethod::EcdsaSd2023,
                                |_| crate::AnyProofOptions::EcdsaSd2023(()),
                                crate::AnySignature::EcdsaSd2023,
                            )
                        })
                        .collect(),
                })
            }
            #[cfg(all(feature = "w3c", feature = "bbs"))]
            Self::Bbs2023 => {
                let DataIntegrity { claims, proofs } = ssi_data_integrity_suites::Bbs2023
                    .select(
                        unsecured_document,
                        crate::Project::project_proof(proof),
                        params,
                        options.into(),
                    )
                    .await?;

                Ok(DataIntegrity {
                    claims,
                    proofs: proofs
                        .into_iter()
                        .map(|p| {
                            p.map_type(
                                |_| Self::Bbs2023,
                                crate::AnySuiteVerificationMethod::Bbs2023,
                                |_| crate::AnyProofOptions::Bbs2023(()),
                                crate::AnySignature::Bbs2023,
                            )
                        })
                        .collect(),
                })
            }
            _ => Err(SelectionError::NonSelectiveSuite),
        }
    }
}
