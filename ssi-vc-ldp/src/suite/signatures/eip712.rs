use linked_data::{
    LinkedData, LinkedDataGraph, LinkedDataPredicateObjects, LinkedDataResource, LinkedDataSubject,
};
use rdf_types::{Interpretation, Vocabulary};
use ssi_verification_methods::{covariance_rule, Referencable};

/// Common signature format for EIP-712-based cryptographic suites.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Eip712Signature {
    /// Proof value
    pub proof_value: String,

    /// Meta-information about the signature generation process.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eip712: Option<Eip712Metadata>,
}

impl Referencable for Eip712Signature {
    type Reference<'a> = Eip712SignatureRef<'a> where Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_> {
        Eip712SignatureRef {
            proof_value: &self.proof_value,
            eip712: self.eip712.as_ref(),
        }
    }

    covariance_rule!();
}

/// Reference to [`Eip712Signature`].
#[derive(Debug, Clone, Copy)]
pub struct Eip712SignatureRef<'a> {
    /// Proof value
    pub proof_value: &'a str,

    /// Meta-information about the signature generation process.
    pub eip712: Option<&'a Eip712Metadata>,
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
#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
#[serde(untagged)]
pub enum TypesOrURI {
    URI(String),
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
