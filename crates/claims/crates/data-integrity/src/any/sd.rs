use serde::Serialize;
use ssi_claims_core::ResolverProvider;
use ssi_data_integrity_core::{
    suite::{CryptographicSuiteSelect, SelectionError, SelectiveCryptographicSuite},
    DataIntegrity, ProofRef,
};
use ssi_di_sd_primitives::JsonPointerBuf;
use ssi_json_ld::{Expandable, ExpandedDocument, JsonLdLoaderProvider, JsonLdNodeObject};
use ssi_rdf::LexicalInterpretation;
use ssi_verification_methods::{AnyMethod, VerificationMethodResolver};

use crate::AnySuite;

#[derive(Debug, Default)]
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
        match self {
            #[cfg(all(feature = "w3c", feature = "bbs"))]
            Self::Bbs2023 => {
                let params = crate::AnyVerifier {
                    resolver: crate::AnyResolver::<_, ssi_verification_methods::Multikey>::new(
                        params.resolver(),
                    ),
                    json_ld_loader: params.loader(),
                    eip712_loader: (),
                };

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
                        .map(|p| ssi_data_integrity_core::Proof {
                            context: p.context,
                            type_: Self::Bbs2023,
                            created: p.created,
                            verification_method: p
                                .verification_method
                                .map(crate::AnySuiteVerificationMethod::Bbs2023),
                            proof_purpose: p.proof_purpose,
                            expires: p.expires,
                            domains: p.domains,
                            challenge: p.challenge,
                            nonce: p.nonce,
                            options: crate::AnyProofOptions::Bbs2023(()),
                            signature: crate::AnySignature::Bbs2023(p.signature),
                            extra_properties: p.extra_properties,
                        })
                        .collect(),
                })
            }
            _ => Err(SelectionError::NonSelectiveSuite),
        }
    }
}
