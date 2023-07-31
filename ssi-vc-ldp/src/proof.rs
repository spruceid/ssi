use serde::{Deserialize, Serialize};
use std::hash::Hash;

use iref::{Iri, IriBuf};
use json_ld::rdf::{RDF_TYPE, XSD_STRING};
use rdf_types::{
    interpretation::ReverseIriInterpretation, BlankIdBuf, Id, IriVocabulary, Literal, Object, Quad,
    Subject, VocabularyMut,
};
use ssi_crypto::{ProofPurpose, Referencable, VerificationError};
use ssi_security::{CRYPTOSUITE, PROOF_PURPOSE, VERIFICATION_METHOD};
use ssi_verification_methods::{
    json_ld::FlattenIntoJsonLdNode, signature, AnyContext, IntoAnyVerificationMethod,
    InvalidVerificationMethod, LinkedDataVerificationMethod, TryFromVerificationMethod,
    TryIntoVerificationMethod,
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
    untyped: UntypedProof<T::VerificationMethod>,
}

impl<T: CryptographicSuite> Proof<T> {
    pub fn new(
        type_: T,
        created: ssi_vc::schema::xsd::layout::DateTime,
        verification_method: T::VerificationMethod,
        proof_purpose: ProofPurpose,
        context: <T::VerificationMethod as ssi_crypto::VerificationMethod>::ProofContext,
        signature: <T::VerificationMethod as ssi_crypto::VerificationMethod>::Signature,
    ) -> Self {
        Self {
            type_,
            untyped: UntypedProof::new(
                created,
                verification_method,
                proof_purpose,
                context,
                signature,
            ),
        }
    }

    pub fn suite(&self) -> &T {
        &self.type_
    }

    pub fn untyped(&self) -> &UntypedProof<T::VerificationMethod> {
        &self.untyped
    }
}

/// Untyped Data Integrity Proof.
pub struct UntypedProof<M: ssi_crypto::VerificationMethod> {
    /// Date and time of creation.
    pub created: ssi_vc::schema::xsd::layout::DateTime,

    /// Verification method.
    pub verification_method: M,

    /// Proof purpose.
    pub proof_purpose: ProofPurpose,

    /// Proof context.
    pub context: M::ProofContext,

    /// Proof value.
    pub signature: M::Signature,
}

impl<M: ssi_crypto::VerificationMethod> UntypedProof<M> {
    pub fn from_options(
        options: ProofOptions<M>,
        context: M::ProofContext,
        signature: M::Signature,
    ) -> Self {
        Self::new(
            options.created,
            options.verification_method,
            options.proof_purpose,
            context,
            signature,
        )
    }

    pub fn new(
        created: ssi_vc::schema::xsd::layout::DateTime,
        verification_method: M,
        proof_purpose: ProofPurpose,
        context: M::ProofContext,
        signature: M::Signature,
    ) -> Self {
        Self {
            created,
            verification_method,
            proof_purpose,
            context,
            signature,
        }
    }

    pub fn try_map_verification_method<N: ssi_crypto::VerificationMethod, E>(
        self,
        f: impl FnOnce(
            M,
            M::ProofContext,
            M::Signature,
        ) -> Result<(N, N::ProofContext, N::Signature), E>,
    ) -> Result<UntypedProof<N>, E> {
        let (verification_method, context, signature) =
            f(self.verification_method, self.context, self.signature)?;

        Ok(UntypedProof::new(
            self.created,
            verification_method,
            self.proof_purpose,
            context,
            signature,
        ))
    }

    pub fn map_verification_method<N: ssi_crypto::VerificationMethod>(
        self,
        f: impl FnOnce(M, M::ProofContext, M::Signature) -> (N, N::ProofContext, N::Signature),
    ) -> UntypedProof<N> {
        let (verification_method, context, signature) =
            f(self.verification_method, self.context, self.signature);

        UntypedProof::new(
            self.created,
            verification_method,
            self.proof_purpose,
            context,
            signature,
        )
    }

    pub fn try_cast_verification_method<N: ssi_crypto::VerificationMethod>(
        self,
    ) -> Result<UntypedProof<N>, ProofCastError>
    where
        M: TryIntoVerificationMethod<N>,
        M::ProofContext: TryInto<N::ProofContext>,
        M::Signature: TryInto<N::Signature>,
    {
        self.try_map_verification_method(|m, context, signature| {
            let n = m.try_into_verification_method()?;
            let context = context
                .try_into()
                .map_err(|_| ProofCastError::ProofContext)?;
            let signature = signature
                .try_into()
                .map_err(|_| ProofCastError::Signature)?;
            Ok((n, context, signature))
        })
    }

    pub fn into_typed<T: CryptographicSuite<VerificationMethod = M>>(self, type_: T) -> Proof<T> {
        Proof {
            type_,
            untyped: self,
        }
    }
}

pub trait ProofParameters<M: ssi_crypto::VerificationMethod> {
    fn verification_method(&self) -> &M;

    fn into_proof(self, context: M::ProofContext, signature: M::Signature) -> UntypedProof<M>;
}

#[derive(Debug, thiserror::Error)]
pub enum ProofCastError {
    #[error("invalid verification method `{0}`")]
    VerificationMethod(IriBuf),

    #[error("invalid proof context")]
    ProofContext,

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
            ProofCastError::ProofContext => VerificationError::InvalidProofContext,
            ProofCastError::Signature => VerificationError::InvalidSignature,
        }
    }
}

impl<M: ssi_crypto::VerificationMethod> UntypedProof<M> {
    pub fn as_proof_ref(&self) -> UntypedProofRef<M> {
        UntypedProofRef {
            created: &self.created,
            verification_method: self.verification_method.as_reference(),
            proof_purpose: self.proof_purpose,
            context: self.context.as_reference(),
            signature: self.signature.as_reference(),
        }
    }
}

impl<M> IntoAnyVerificationMethod for UntypedProof<M>
where
    M: ssi_crypto::VerificationMethod + IntoAnyVerificationMethod,
    M::Output:
        ssi_crypto::VerificationMethod<ProofContext = AnyContext, Signature = signature::Any>,
    M::ProofContext: Into<AnyContext>,
    M::Signature: Into<signature::Any>,
{
    type Output = UntypedProof<M::Output>;

    fn into_any_verification_method(self) -> Self::Output {
        self.map_verification_method(|m, context, signature| {
            let m = m.into_any_verification_method();
            let context = context.into();
            let signature = signature.into();
            (m, context, signature)
        })
    }
}

/// Reference to an untyped proof.
pub struct UntypedProofRef<'a, M: 'a + ssi_crypto::VerificationMethod> {
    /// Date and time of creation.
    pub created: &'a ssi_vc::schema::xsd::layout::DateTime,

    /// Verification method.
    pub verification_method: M::Reference<'a>,

    /// Proof purpose.
    pub proof_purpose: ProofPurpose,

    /// Proof context.
    pub context: <M::ProofContext as ssi_crypto::Referencable>::Reference<'a>,

    /// Signature.
    pub signature: <M::Signature as ssi_crypto::Referencable>::Reference<'a>,
}

impl<'a, M: 'a + ssi_crypto::VerificationMethod> UntypedProofRef<'a, M> {
    pub fn try_cast_verification_method<N: 'a + ssi_crypto::VerificationMethod>(
        self,
    ) -> Result<UntypedProofRef<'a, N>, ProofCastError>
    where
        N::Reference<'a>: TryFromVerificationMethod<M::Reference<'a>>,
        <N::ProofContext as ssi_crypto::Referencable>::Reference<'a>:
            TryFrom<<M::ProofContext as ssi_crypto::Referencable>::Reference<'a>>,
        <N::Signature as ssi_crypto::Referencable>::Reference<'a>:
            TryFrom<<M::Signature as ssi_crypto::Referencable>::Reference<'a>>,
    {
        Ok(UntypedProofRef {
            created: self.created,
            verification_method: self.verification_method.try_into_verification_method()?,
            proof_purpose: self.proof_purpose,
            context: self
                .context
                .try_into()
                .map_err(|_| ProofCastError::ProofContext)?,
            signature: self
                .signature
                .try_into()
                .map_err(|_| ProofCastError::Signature)?,
        })
    }
}

pub const DC_CREATED_IRI: Iri<'static> = iri!("http://purl.org/dc/terms/created");

pub const XSD_DATETIME_IRI: Iri<'static> = iri!("http://www.w3.org/2001/XMLSchema#dateTime");

impl<M: ssi_crypto::VerificationMethod, V: VocabularyMut, I>
    ssi_verification_methods::json_ld::FlattenIntoJsonLdNode<V, I> for UntypedProof<M>
where
    V::Iri: Eq + Hash,
    V::BlankId: Eq + Hash,
    M: treeldr_rust_prelude::ld::IntoJsonLdObjectMeta<V, I>,
    M::ProofContext: ssi_verification_methods::json_ld::FlattenIntoJsonLdNode<V, I>,
    M::Signature: ssi_verification_methods::json_ld::FlattenIntoJsonLdNode<V, I>,
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

        self.context
            .flatten_into_json_ld_node(vocabulary, interpretation, node);
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
    <T::VerificationMethod as ssi_crypto::VerificationMethod>::ProofContext:
        ssi_verification_methods::json_ld::FlattenIntoJsonLdNode<V, I>,
    <T::VerificationMethod as ssi_crypto::VerificationMethod>::Signature:
        ssi_verification_methods::json_ld::FlattenIntoJsonLdNode<V, I>,
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
    <T::VerificationMethod as ssi_crypto::VerificationMethod>::ProofContext: FromRdf<V, I>,
    <T::VerificationMethod as ssi_crypto::VerificationMethod>::Signature: FromRdf<V, I>,
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
        let proof_purpose: ProofPurpose = proof_purpose
            .ok_or(FromRdfError::MissingRequiredPropertyValue)?
            .try_into()
            .map_err(|_| todo!("invalid proof purpose"))?;

        let proof_value = FromRdf::from_rdf(vocabulary, interpretation, graph, id)?;
        let context = FromRdf::from_rdf(vocabulary, interpretation, graph, id)?;

        Ok(Self::new(
            AnyType::new(type_, crypto_suite).into(),
            created,
            verification_method,
            proof_purpose,
            proof_value,
            context,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProofConfiguration<M> {
    pub created: ssi_vc::schema::xsd::layout::DateTime,
    pub verification_method: M,
    pub proof_purpose: ProofPurpose,
}

impl<M: LinkedDataVerificationMethod> ProofConfiguration<M> {
    pub fn try_cast_verification_method<N: TryFromVerificationMethod<M>>(
        self,
    ) -> Result<ProofConfiguration<N>, InvalidVerificationMethod> {
        Ok(ProofConfiguration {
            created: self.created,
            verification_method: self.verification_method.try_into_verification_method()?,
            proof_purpose: self.proof_purpose,
        })
    }

    /// Returns the quads of the proof configuration, in canonical form.
    pub fn quads<T: CryptographicSuite>(&self, suite: &T) -> Vec<Quad> {
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

#[derive(Debug, Clone)]
pub struct ProofOptions<M: ssi_crypto::VerificationMethod> {
    pub created: ssi_vc::schema::xsd::layout::DateTime,
    pub verification_method: M,
    pub proof_purpose: ProofPurpose,
}

impl<M: ssi_crypto::VerificationMethod> ProofOptions<M> {
    pub fn new(
        created: ssi_vc::schema::xsd::layout::DateTime,
        verification_method: M,
        proof_purpose: ProofPurpose,
    ) -> Self {
        Self {
            created,
            verification_method,
            proof_purpose,
        }
    }

    pub fn to_proof_configuration(&self) -> ProofConfiguration<M>
    where
        M: Clone,
    {
        ProofConfiguration {
            created: self.created,
            verification_method: self.verification_method.clone(),
            proof_purpose: self.proof_purpose,
        }
    }

    pub fn into_proof_configuration(self) -> ProofConfiguration<M> {
        ProofConfiguration {
            created: self.created,
            verification_method: self.verification_method,
            proof_purpose: self.proof_purpose,
        }
    }

    pub fn try_cast_verification_method<
        N: ssi_crypto::VerificationMethod + TryFromVerificationMethod<M>,
    >(
        self,
    ) -> Result<ProofOptions<N>, InvalidVerificationMethod> {
        Ok(ProofOptions {
            created: self.created,
            verification_method: self.verification_method.try_into_verification_method()?,
            proof_purpose: self.proof_purpose,
        })
    }
}

impl<M: ssi_crypto::VerificationMethod> ProofParameters<M> for ProofOptions<M> {
    fn verification_method(&self) -> &M {
        &self.verification_method
    }

    fn into_proof(
        self,
        context: <M as ssi_crypto::VerificationMethod>::ProofContext,
        signature: <M as ssi_crypto::VerificationMethod>::Signature,
    ) -> UntypedProof<M> {
        UntypedProof::from_options(self, context, signature)
    }
}
