use serde::{Deserialize, Serialize};
use std::hash::Hash;

use iref::{Iri, IriBuf};
use json_ld::rdf::{RDF_TYPE, XSD_STRING};
use rdf_types::{
    interpretation::ReverseIriInterpretation, BlankIdBuf, Id, IriVocabulary, Literal, Object, Quad,
    Subject, VocabularyMut,
};
use ssi_security::{CRYPTOSUITE, PROOF_PURPOSE, VERIFICATION_METHOD};
use ssi_verification_methods::{
    json_ld::FlattenIntoJsonLdNode, signature,
    InvalidVerificationMethod, LinkedDataVerificationMethod, ProofPurpose, VerificationError
};
use static_iref::iri;
use treeldr_rust_prelude::{
    grdf::Graph,
    json_ld,
    locspan::{Meta, Stripped},
    FromRdf, FromRdfError,
};

use crate::CryptographicSuite;

/// Any proof type.
pub struct AnyType {
    pub iri: IriBuf,
    pub cryptographic_suite: Option<String>,
}

impl AnyType {
    pub fn new(iri: IriBuf, cryptographic_suite: Option<String>) -> Self {
        Self {
            iri,
            cryptographic_suite,
        }
    }
}

/// Data Integrity Proof.
///
/// # Type parameters
///
/// - `T`: proof type value type.
pub struct Proof<T: CryptographicSuite> {
    /// Proof type.
    ///
    /// Also includes the cryptographic suite variant.
    type_: T,

    /// Untyped proof.
    untyped: UntypedProof<T::VerificationMethod, T::Signature>,
}

impl<T: CryptographicSuite> Proof<T> {
    pub fn new(
        type_: T,
        created: ssi_vc::schema::xsd::layout::DateTime,
        verification_method: T::VerificationMethod,
        proof_purpose: ProofPurpose,
        signature: T::Signature
    ) -> Self {
        Self {
            type_,
            untyped: UntypedProof::new(
                created,
                verification_method,
                proof_purpose,
                signature
            ),
        }
    }

    pub fn suite(&self) -> &T {
        &self.type_
    }

    pub fn untyped(&self) -> &UntypedProof<T::VerificationMethod, T::Signature> {
        &self.untyped
    }
}

/// Untyped Data Integrity Proof.
pub struct UntypedProof<M, S> {
    /// Date and time of creation.
    pub created: ssi_vc::schema::xsd::layout::DateTime,

    /// Verification method.
    pub verification_method: M,

    /// Proof purpose.
    pub proof_purpose: ProofPurpose,

    /// Proof value.
    pub signature: S,
}

impl<M, S> UntypedProof<M, S> {
    pub fn from_options(
        options: ProofConfiguration<M>,
        signature: S
    ) -> Self {
        Self::new(
            options.created,
            options.verification_method,
            options.proof_purpose,
            signature
        )
    }

    pub fn new(
        created: ssi_vc::schema::xsd::layout::DateTime,
        verification_method: M,
        proof_purpose: ProofPurpose,
        signature: S
    ) -> Self {
        Self {
            created,
            verification_method,
            proof_purpose,
            signature
        }
    }

    pub fn try_map_verification_method<N, T, E>(
        self,
        f: impl FnOnce(
            M,
            S,
        ) -> Result<(N, T), E>,
    ) -> Result<UntypedProof<N, T>, E> {
        let (verification_method, signature) =
            f(self.verification_method, self.signature)?;

        Ok(UntypedProof::new(
            self.created,
            verification_method,
            self.proof_purpose,
            signature
        ))
    }

    pub fn map_verification_method<N, T>(
        self,
        f: impl FnOnce(M, S) -> (N, T),
    ) -> UntypedProof<N, T> {
        let (verification_method, signature) =
            f(self.verification_method, self.signature);

        UntypedProof::new(
            self.created,
            verification_method,
            self.proof_purpose,
            signature
        )
    }

    pub fn try_cast_verification_method<N, T>(
        self,
    ) -> Result<UntypedProof<N, T>, ProofCastError>
    where
        M: TryInto<N, Error = InvalidVerificationMethod>,
        S: TryInto<T>,
    {
        self.try_map_verification_method(|m, signature| {
            let n = m.try_into()?;
            let signature = signature
                .try_into()
                .map_err(|_| ProofCastError::Signature)?;
            Ok((n, signature))
        })
    }

    pub fn into_typed<T: CryptographicSuite<VerificationMethod = M, Signature = S>>(self, type_: T) -> Proof<T> {
        Proof {
            type_,
            untyped: self,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProofCastError {
    #[error("invalid verification method")]
    VerificationMethod(IriBuf),

    #[error("invalid signature")]
    Signature,
}

impl From<InvalidVerificationMethod> for ProofCastError {
    fn from(InvalidVerificationMethod(iri): InvalidVerificationMethod) -> Self {
        Self::VerificationMethod(iri)
    }
}

impl From<ProofCastError> for VerificationError {
    fn from(value: ProofCastError) -> Self {
        match value {
            ProofCastError::VerificationMethod(iri) => {
                VerificationError::InvalidVerificationMethod(iri)
            }
            ProofCastError::Signature => VerificationError::InvalidSignature,
        }
    }
}

pub const DC_CREATED_IRI: Iri<'static> = iri!("http://purl.org/dc/terms/created");

pub const XSD_DATETIME_IRI: Iri<'static> = iri!("http://www.w3.org/2001/XMLSchema#dateTime");

impl<M, S, V: VocabularyMut, I>
    ssi_verification_methods::json_ld::FlattenIntoJsonLdNode<V, I> for UntypedProof<M, S>
where
    V::Iri: Eq + Hash,
    V::BlankId: Eq + Hash,
    M: treeldr_rust_prelude::ld::IntoJsonLdObjectMeta<V, I>,
    S: ssi_verification_methods::json_ld::FlattenIntoJsonLdNode<V, I>,
{
    fn flatten_into_json_ld_node(
        self,
        vocabulary: &mut V,
        interpretation: &I,
        node: &mut json_ld::Node<V::Iri, V::BlankId>,
    ) {
        let properties = node.properties_mut();

        properties.insert(
            Meta(json_ld::Id::iri(vocabulary.insert(DC_CREATED_IRI)), ()),
            Meta(
                json_ld::Indexed::new(
                    json_ld::Object::Value(json_ld::Value::Literal(
                        json_ld::object::Literal::String(json_ld::object::LiteralString::Inferred(
                            self.created.format("%Y-%m-%dT%H:%M:%S%:z").to_string(),
                        )),
                        Some(vocabulary.insert(XSD_DATETIME_IRI)),
                    )),
                    None,
                ),
                (),
            ),
        );

        properties.insert(
            Meta(json_ld::Id::iri(vocabulary.insert(VERIFICATION_METHOD)), ()),
            self.verification_method
                .into_json_ld_object_meta(vocabulary, interpretation, ()),
        );

        properties.insert(
            Meta(json_ld::Id::iri(vocabulary.insert(PROOF_PURPOSE)), ()),
            Meta(
                json_ld::Indexed::new(
                    json_ld::Object::Node(Box::new(json_ld::Node::with_id(
                        json_ld::syntax::Entry::new(
                            (),
                            Meta(
                                json_ld::Id::iri(vocabulary.insert(self.proof_purpose.iri())),
                                (),
                            ),
                        ),
                    ))),
                    None,
                ),
                (),
            ),
        );

        self.signature
            .flatten_into_json_ld_node(vocabulary, interpretation, node);
    }
}

impl<T: CryptographicSuite, V: VocabularyMut, I>
    treeldr_rust_prelude::ld::IntoJsonLdObjectMeta<V, I> for Proof<T>
where
    V::Iri: Eq + Hash,
    V::BlankId: Eq + Hash,
    T::VerificationMethod: treeldr_rust_prelude::ld::IntoJsonLdObjectMeta<V, I>,
    T::Signature: ssi_verification_methods::json_ld::FlattenIntoJsonLdNode<V, I>
{
    fn into_json_ld_object_meta(
        self,
        vocabulary: &mut V,
        interpretation: &I,
        meta: (),
    ) -> json_ld::IndexedObject<V::Iri, V::BlankId, ()> {
        let mut node = json_ld::Node::new();

        node.type_entry_or_default((), ()).push(Meta(
            json_ld::Id::iri(vocabulary.insert(self.type_.iri())),
            (),
        ));

        let properties = node.properties_mut();

        if let Some(crypto_suite) = self.type_.cryptographic_suite() {
            properties.insert(
                Meta(json_ld::Id::iri(vocabulary.insert(CRYPTOSUITE)), ()),
                Meta(
                    json_ld::Indexed::new(
                        json_ld::Object::Value(json_ld::Value::Literal(
                            json_ld::object::Literal::String(
                                json_ld::object::LiteralString::Inferred(crypto_suite.to_string()),
                            ),
                            None,
                        )),
                        None,
                    ),
                    (),
                ),
            );
        }

        self.untyped
            .flatten_into_json_ld_node(vocabulary, interpretation, &mut node);

        let mut graph = json_ld::Node::new();
        graph.set_graph(Some(json_ld::syntax::Entry::new(
            (),
            Meta(
                [Stripped(Meta(
                    json_ld::Indexed::new(json_ld::Object::Node(Box::new(node)), None),
                    (),
                ))]
                .into_iter()
                .collect(),
                (),
            ),
        )));

        Meta(
            json_ld::Indexed::new(json_ld::Object::Node(Box::new(graph)), None),
            meta,
        )
    }
}

impl<T: CryptographicSuite + From<AnyType>, V: IriVocabulary, I> FromRdf<V, I> for Proof<T>
where
    I: ReverseIriInterpretation<Iri = V::Iri>,
    ssi_vc::schema::xsd::layout::String: FromRdf<V, I>,
    ssi_vc::schema::xsd::layout::DateTime: FromRdf<V, I>,
    ssi_vc::schema::sec::layout::Multibase: FromRdf<V, I>,
    T::VerificationMethod: FromRdf<V, I>,
    T::Signature: FromRdf<V, I>
{
    fn from_rdf<G>(
        vocabulary: &V,
        interpretation: &I,
        graph: &G,
        id: &I::Resource,
    ) -> Result<Self, treeldr_rust_prelude::FromRdfError>
    where
        G: Graph<Subject = I::Resource, Predicate = I::Resource, Object = I::Resource>,
    {
        let mut type_ = None;
        let mut crypto_suite = None;
        let mut created = None;
        let mut verification_method = None;
        let mut proof_purpose = None;
        // let mut proof_value = None;

        for (p, objects) in graph.predicates(id) {
            if let Some(p) = interpretation.iris_of(p).next() {
                let p = vocabulary.iri(p).unwrap();

                if p == RDF_TYPE {
                    for o in objects {
                        match interpretation.iris_of(o).next() {
                            Some(iri) => {
                                let ty = vocabulary.iri(iri).unwrap();
                                type_ = Some(ty.to_owned())
                            }
                            None => return Err(FromRdfError::UnexpectedLiteralValue),
                        }
                    }
                } else if p == CRYPTOSUITE {
                    for o in objects {
                        crypto_suite = Some(ssi_vc::schema::xsd::layout::String::from_rdf(
                            vocabulary,
                            interpretation,
                            graph,
                            o,
                        )?);
                    }
                } else if p == DC_CREATED_IRI {
                    for o in objects {
                        created = Some(ssi_vc::schema::xsd::layout::DateTime::from_rdf(
                            vocabulary,
                            interpretation,
                            graph,
                            o,
                        )?);
                    }
                } else if p == VERIFICATION_METHOD {
                    for o in objects {
                        verification_method = Some(T::VerificationMethod::from_rdf(
                            vocabulary,
                            interpretation,
                            graph,
                            o,
                        )?);
                    }
                } else if p == PROOF_PURPOSE {
                    for o in objects {
                        match interpretation.iris_of(o).next() {
                            Some(iri) => {
                                let ty = vocabulary.iri(iri).unwrap();
                                proof_purpose = Some(ty.to_owned())
                            }
                            None => return Err(FromRdfError::UnexpectedLiteralValue),
                        }
                    }
                }
            }
        }

        let type_ = type_.ok_or(FromRdfError::UnexpectedType)?;
        let created = created.ok_or(FromRdfError::MissingRequiredPropertyValue)?;
        let verification_method =
            verification_method.ok_or(FromRdfError::MissingRequiredPropertyValue)?;
        // let verification_parameters = FromRdf::from_rdf(vocabulary, interpretation, graph, id)?;
        let proof_purpose: ProofPurpose = proof_purpose
            .ok_or(FromRdfError::MissingRequiredPropertyValue)?
            .try_into()
            .map_err(|_| todo!("invalid proof purpose"))?;

        let signature = FromRdf::from_rdf(vocabulary, interpretation, graph, id)?;
        // let signature_parameters = FromRdf::from_rdf(vocabulary, interpretation, graph, id)?;

        Ok(Self::new(
            AnyType::new(type_, crypto_suite).into(),
            created,
            verification_method,
            proof_purpose,
            signature
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProofConfiguration<M> {
    pub created: ssi_vc::schema::xsd::layout::DateTime,
    pub verification_method: M,
    pub proof_purpose: ProofPurpose
}

impl<M> ProofConfiguration<M> {
    pub fn new(
        created: ssi_vc::schema::xsd::layout::DateTime,
        verification_method: M,
        proof_purpose: ProofPurpose
    ) -> Self {
        Self {
            created,
            verification_method,
            proof_purpose
        }
    }

    pub fn into_proof<S>(
        self,
        signature: S
    ) -> UntypedProof<M, S> {
        UntypedProof::from_options(self, signature)
    }
}

impl<M> ProofConfiguration<M> {
    /// Returns the quads of the proof configuration, in canonical form.
    pub fn quads<T: CryptographicSuite>(&self, suite: &T) -> Vec<Quad>
    where
        M: LinkedDataVerificationMethod
    {
        let mut result: Vec<Quad> = Vec::new();

        let subject = Subject::Blank(BlankIdBuf::from_suffix("proofConfiguration").unwrap());

        result.push(Quad(
            subject.clone(),
            RDF_TYPE.to_owned(),
            Object::Id(Id::Iri(suite.iri().to_owned())),
            None,
        ));

        if let Some(crypto_suite) = suite.cryptographic_suite() {
            result.push(Quad(
                subject.clone(),
                CRYPTOSUITE.to_owned(),
                Object::Literal(Literal::new(
                    crypto_suite.to_string(),
                    rdf_types::literal::Type::Any(XSD_STRING.to_owned()),
                )),
                None,
            ));
        }

        result.push(Quad(
            subject.clone(),
            DC_CREATED_IRI.to_owned(),
            Object::Literal(Literal::new(
                self.created.format("%Y-%m-%dT%H:%M:%S").to_string(),
                rdf_types::literal::Type::Any(XSD_DATETIME_IRI.to_owned()),
            )),
            None,
        ));

        let verification_method = self.verification_method.quads(&mut result);

        result.push(Quad(
            subject.clone(),
            VERIFICATION_METHOD.to_owned(),
            verification_method,
            None,
        ));

        result.push(Quad(
            subject,
            PROOF_PURPOSE.to_owned(),
            Object::Id(Id::Iri(self.proof_purpose.iri().to_owned())),
            None,
        ));

        ssi_rdf::urdna2015::normalize(result.iter().map(Quad::as_quad_ref)).collect()
    }
}