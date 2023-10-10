use iref::UriBuf;
use linked_data::{
    LinkedData, LinkedDataGraph, LinkedDataPredicateObjects, LinkedDataResource, LinkedDataSubject,
};
use rdf_types::{Interpretation, Vocabulary};
use ssi_verification_methods::{covariance_rule, Referencable, InvalidSignature};

use crate::suite::{AnySignature, AnySignatureRef};

/// Common signature format for EIP-712-based cryptographic suites.
/// 
/// See: <https://eips.ethereum.org/EIPS/eip-712>
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Eip712Signature {
    /// Hex encoded output of the EIP712 signature function according to
    /// [EIP712](https://eips.ethereum.org/EIPS/eip-712).
    pub proof_value: String,
}

impl Referencable for Eip712Signature {
    type Reference<'a> = Eip712SignatureRef<'a> where Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_> {
        Eip712SignatureRef {
            proof_value: &self.proof_value
        }
    }

    covariance_rule!();
}

impl From<Eip712Signature> for AnySignature {
    fn from(value: Eip712Signature) -> Self {
        Self {
            proof_value: Some(value.proof_value),
            ..Default::default()
        }
    }
}

impl TryFrom<AnySignature> for Eip712Signature {
    type Error = InvalidSignature;

    fn try_from(value: AnySignature) -> Result<Self, Self::Error> {
        Ok(Self {
            proof_value: value.proof_value.ok_or(InvalidSignature::MissingValue)?
        })
    }
}

/// Reference to [`Eip712Signature`].
#[derive(Debug, Clone, Copy)]
pub struct Eip712SignatureRef<'a> {
    /// Proof value
    pub proof_value: &'a str
}

impl<'a> From<Eip712SignatureRef<'a>> for AnySignatureRef<'a> {
    fn from(value: Eip712SignatureRef<'a>) -> Self {
        Self {
            proof_value: Some(value.proof_value),
            ..Default::default()
        }
    }
}

impl<'a> TryFrom<AnySignatureRef<'a>> for Eip712SignatureRef<'a> {
    type Error = InvalidSignature;

    fn try_from(value: AnySignatureRef<'a>) -> Result<Self, Self::Error> {
        Ok(Self {
            proof_value: value.proof_value.ok_or(InvalidSignature::MissingValue)?
        })
    }
}

/// Meta-information about the signature generation process.
///
/// See: <https://w3c-ccg.github.io/ethereum-eip712-signature-2021-spec/#ethereum-eip712-signature-2021>
#[derive(Debug, serde::Serialize, serde::Deserialize, Clone, LinkedData)]
#[ld(prefix("eip712" = "https://w3c-ccg.github.io/ethereum-eip712-signature-2021-spec/#"))]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct Eip712Metadata {
    /// URI to an object containing the JSON schema describing the message to
    /// be signed.
    ///
    // Allow messageSchema for backwards-compatibility since
    // changed in https://github.com/w3c-ccg/ethereum-eip712-signature-2021-spec/pull/32
    #[ld("eip712:types")]
    #[serde(rename = "types", alias = "messageSchema")]
    pub types_or_uri: TypesOrURI,

    /// Value of the `primaryType` property of the `TypedData` object.
    #[ld("eip712:primaryType")]
    pub primary_type: ssi_eip712::StructName,

    /// Value of the `domain` property of the `TypedData` object.
    #[ld("eip712:domain")]
    pub domain: ssi_eip712::Value,
}

/// Object containing EIP-712 types, or a URI for such.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum TypesOrURI {
    URI(UriBuf),
    Object(ssi_eip712::Types),
}

impl<V: Vocabulary, I: Interpretation> LinkedDataResource<V, I> for TypesOrURI {
    fn interpretation(
        &self,
        _vocabulary: &mut V,
        _interpretation: &mut I,
    ) -> linked_data::ResourceInterpretation<V, I> {
        linked_data::ResourceInterpretation::Uninterpreted(Some(linked_data::CowRdfTerm::Owned(
            rdf_types::Term::Literal(linked_data::RdfLiteral::Json(
                json_ld::syntax::to_value(self).unwrap(),
            )),
        )))
    }
}

impl<V: Vocabulary, I: Interpretation> LinkedDataSubject<V, I> for TypesOrURI {
    fn visit_subject<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: linked_data::SubjectVisitor<V, I>,
    {
        serializer.end()
    }
}

impl<V: Vocabulary, I: Interpretation> LinkedDataPredicateObjects<V, I> for TypesOrURI {
    fn visit_objects<S>(&self, mut visitor: S) -> Result<S::Ok, S::Error>
    where
        S: linked_data::PredicateObjectsVisitor<V, I>,
    {
        visitor.object(self)?;
        visitor.end()
    }
}

impl<V: Vocabulary, I: Interpretation> LinkedDataGraph<V, I> for TypesOrURI {
    fn visit_graph<S>(&self, mut visitor: S) -> Result<S::Ok, S::Error>
    where
        S: linked_data::GraphVisitor<V, I>,
    {
        visitor.subject(self)?;
        visitor.end()
    }
}

impl<V: Vocabulary, I: Interpretation> LinkedData<V, I> for TypesOrURI {
    fn visit<S>(&self, mut visitor: S) -> Result<S::Ok, S::Error>
    where
        S: linked_data::Visitor<V, I>,
    {
        visitor.default_graph(self)?;
        visitor.end()
    }
}
