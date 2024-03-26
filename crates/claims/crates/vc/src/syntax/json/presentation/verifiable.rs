use iref::{Uri, UriBuf};
use serde::{Deserialize, Serialize};
use ssi_claims_core::{ExtractProof, Validate, VerifiableClaims};

use crate::Credential;

use super::{value_or_array, JsonPresentation, SpecializedJsonCredential};

/// JSON Verifiable Presentation.
#[derive(Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C: serde::Serialize, P: serde::Serialize",
    deserialize = "C: serde::Deserialize<'de>, P: serde::Deserialize<'de>"
))]
pub struct JsonVerifiablePresentation<C = SpecializedJsonCredential, P = json_syntax::Value> {
    #[serde(flatten)]
    presentation: JsonPresentation<C>,

    /// Proofs.
    #[serde(rename = "proof")]
    #[serde(
        with = "value_or_array",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub proofs: Vec<P>,
}

impl<C, P> JsonVerifiablePresentation<C, P> {
    pub fn new(
        id: Option<UriBuf>,
        verifiable_credentials: Vec<C>,
        holders: Vec<UriBuf>,
        proofs: Vec<P>,
    ) -> Self {
        Self {
            presentation: JsonPresentation::new(id, holders, verifiable_credentials),
            proofs,
        }
    }
}

impl<C, P> Validate for JsonVerifiablePresentation<C, P> {
    fn is_valid(&self) -> bool {
        true
    }
}

impl<C: Credential, P> crate::Presentation for JsonVerifiablePresentation<C, P> {
    /// Verifiable credential type.
    type Credential = C;

    /// Identifier.
    fn id(&self) -> Option<&Uri> {
        self.presentation.id.as_deref()
    }

    /// Types, without the `VerifiablePresentation` type.
    fn additional_types(&self) -> &[String] {
        self.presentation.types.additional_types()
    }

    fn verifiable_credentials(&self) -> &[Self::Credential] {
        &self.presentation.verifiable_credentials
    }

    fn holders(&self) -> &[UriBuf] {
        &self.presentation.holders
    }
}

impl<C, P> VerifiableClaims for JsonVerifiablePresentation<C, P> {
    type Proof = Vec<P>;

    fn proof(&self) -> &Vec<P> {
        &self.proofs
    }
}

impl<C, P> ExtractProof for JsonVerifiablePresentation<C, P> {
    type Proofless = JsonPresentation<C>;

    fn extract_proof(self) -> (Self::Proofless, Vec<P>) {
        (self.presentation, self.proofs)
    }
}
