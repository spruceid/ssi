use std::hash::Hash;

use iref::{Iri, IriBuf};
use json_ld::rdf::{RDF_TYPE, XSD_STRING};
use rdf_types::{
    interpretation::ReverseIriInterpretation, BlankIdBuf, Id, IriVocabulary, Literal, Object, Quad,
    Subject, VocabularyMut,
};
use ssi_crypto::{ProofPurpose, Signature};
use ssi_security::MULTIBASE;
use ssi_verification_methods::{
    signature, IntoAnyVerificationMethod, InvalidVerificationMethod, LinkedDataVerificationMethod,
    TryFromVerificationMethod, TryIntoVerificationMethod,
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
        proof_value: signature::Any,
    ) -> Self {
        Self {
            type_,
            untyped: UntypedProof::new(created, verification_method, proof_purpose, proof_value),
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
pub struct UntypedProof<M> {
    /// Date and time of creation.
    pub created: ssi_vc::schema::xsd::layout::DateTime,

    /// Verification method.
    pub verification_method: M,

    /// Proof purpose.
    pub proof_purpose: ProofPurpose,

    /// Proof value.
    pub proof_value: signature::Any,
}

impl<M> UntypedProof<M> {
    pub fn from_options(options: ProofOptions<M>, proof_value: signature::Any) -> Self {
        Self::new(
            options.created,
            options.verification_method,
            options.proof_purpose,
            proof_value,
        )
    }

    pub fn new(
        created: ssi_vc::schema::xsd::layout::DateTime,
        verification_method: M,
        proof_purpose: ProofPurpose,
        proof_value: signature::Any,
    ) -> Self {
        Self {
            created,
            verification_method,
            proof_purpose,
            proof_value,
        }
    }

    pub fn try_map_verification_method<N, E>(
        self,
        f: impl FnOnce(M) -> Result<N, E>,
    ) -> Result<UntypedProof<N>, E> {
        Ok(UntypedProof::new(
            self.created,
            f(self.verification_method)?,
            self.proof_purpose,
            self.proof_value,
        ))
    }

    pub fn map_verification_method<N>(self, f: impl FnOnce(M) -> N) -> UntypedProof<N> {
        UntypedProof::new(
            self.created,
            f(self.verification_method),
            self.proof_purpose,
            self.proof_value,
        )
    }

    pub fn try_cast_verification_method<N>(
        self,
    ) -> Result<UntypedProof<N>, InvalidVerificationMethod>
    where
        M: TryIntoVerificationMethod<N>,
    {
        self.try_map_verification_method(M::try_into_verification_method)
    }

    pub fn into_typed<T: CryptographicSuite<VerificationMethod = M>>(self, type_: T) -> Proof<T> {
        Proof {
            type_,
            untyped: self,
        }
    }
}

impl<M: ssi_crypto::VerificationMethod> UntypedProof<M> {
    pub fn as_proof_ref(&self) -> UntypedProofRef<M> {
        UntypedProofRef {
            created: &self.created,
            verification_method: self.verification_method.as_reference(),
            proof_purpose: self.proof_purpose,
            proof_value: self.proof_value.as_reference(),
        }
    }
}

impl<M: IntoAnyVerificationMethod> IntoAnyVerificationMethod for UntypedProof<M> {
    type Output = UntypedProof<M::Output>;

    fn into_any_verification_method(self) -> Self::Output {
        self.map_verification_method(M::into_any_verification_method)
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

    /// Proof value.
    pub proof_value: signature::AnyRef<'a>,
}

impl<'a, M: 'a + ssi_crypto::VerificationMethod> UntypedProofRef<'a, M> {
    pub fn try_cast_verification_method<N: 'a + ssi_crypto::VerificationMethod>(
        self,
    ) -> Result<UntypedProofRef<'a, N>, InvalidVerificationMethod>
    where
        N::Reference<'a>: TryFromVerificationMethod<M::Reference<'a>>,
    {
        Ok(UntypedProofRef {
            created: self.created,
            verification_method: self.verification_method.try_into_verification_method()?,
            proof_purpose: self.proof_purpose,
            proof_value: self.proof_value,
        })
    }
}

pub const SEC_CRYPTOSUITE_IRI: Iri<'static> = iri!("https://w3id.org/security#cryptosuite");
pub const SEC_VERIFICATION_METHOD_IRI: Iri<'static> =
    iri!("https://w3id.org/security#verificationMethod");
pub const SEC_PROOF_PURPOSE_IRI: Iri<'static> = iri!("https://w3id.org/security#proofPurpose");
pub const SEC_PROOF_VALUE_IRI: Iri<'static> = iri!("https://w3id.org/security#proofValue");
pub const SEC_JWS_IRI: Iri<'static> = iri!("https://w3id.org/security#jws");
pub const SEC_SIGNATURE_VALUE_IRI: Iri<'static> = iri!("https://w3id.org/security#signatureValue");

pub const DC_CREATED_IRI: Iri<'static> = iri!("http://purl.org/dc/terms/created");

pub const XSD_DATETIME_IRI: Iri<'static> = iri!("http://www.w3.org/2001/XMLSchema#dateTime");

impl<T: CryptographicSuite, V: VocabularyMut, I>
    treeldr_rust_prelude::ld::IntoJsonLdObjectMeta<V, I> for Proof<T>
where
    V::Iri: Eq + Hash,
    V::BlankId: Eq + Hash,
    T::VerificationMethod: treeldr_rust_prelude::ld::IntoJsonLdObjectMeta<V, I>,
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
                Meta(json_ld::Id::iri(vocabulary.insert(SEC_CRYPTOSUITE_IRI)), ()),
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

        properties.insert(
            Meta(json_ld::Id::iri(vocabulary.insert(DC_CREATED_IRI)), ()),
            Meta(
                json_ld::Indexed::new(
                    json_ld::Object::Value(json_ld::Value::Literal(
                        json_ld::object::Literal::String(json_ld::object::LiteralString::Inferred(
                            self.untyped
                                .created
                                .format("%Y-%m-%dT%H:%M:%S%:z")
                                .to_string(),
                        )),
                        Some(vocabulary.insert(XSD_DATETIME_IRI)),
                    )),
                    None,
                ),
                (),
            ),
        );

        properties.insert(
            Meta(
                json_ld::Id::iri(vocabulary.insert(SEC_VERIFICATION_METHOD_IRI)),
                (),
            ),
            self.untyped.verification_method.into_json_ld_object_meta(
                vocabulary,
                interpretation,
                (),
            ),
        );

        properties.insert(
            Meta(
                json_ld::Id::iri(vocabulary.insert(SEC_PROOF_PURPOSE_IRI)),
                (),
            ),
            Meta(
                json_ld::Indexed::new(
                    json_ld::Object::Node(Box::new(json_ld::Node::with_id(
                        json_ld::syntax::Entry::new(
                            (),
                            Meta(
                                json_ld::Id::iri(
                                    vocabulary.insert(self.untyped.proof_purpose.iri()),
                                ),
                                (),
                            ),
                        ),
                    ))),
                    None,
                ),
                (),
            ),
        );

        match self.untyped.proof_value {
            signature::Any::ProofValue(proof_value) => {
                properties.insert(
                    Meta(json_ld::Id::iri(vocabulary.insert(SEC_PROOF_VALUE_IRI)), ()),
                    Meta(
                        json_ld::Indexed::new(
                            json_ld::Object::Value(json_ld::Value::Literal(
                                json_ld::object::Literal::String(
                                    json_ld::object::LiteralString::Inferred(
                                        proof_value.0.to_string(),
                                    ),
                                ),
                                Some(vocabulary.insert(MULTIBASE)),
                            )),
                            None,
                        ),
                        (),
                    ),
                );
            }
            signature::Any::Jws(proof_value) => {
                properties.insert(
                    Meta(json_ld::Id::iri(vocabulary.insert(SEC_JWS_IRI)), ()),
                    Meta(
                        json_ld::Indexed::new(
                            json_ld::Object::Value(json_ld::Value::Literal(
                                json_ld::object::Literal::String(
                                    json_ld::object::LiteralString::Inferred(
                                        proof_value.0.into_string(),
                                    ),
                                ),
                                Some(vocabulary.insert(XSD_STRING)),
                            )),
                            None,
                        ),
                        (),
                    ),
                );
            }
            signature::Any::SignatureValue(proof_value) => {
                properties.insert(
                    Meta(
                        json_ld::Id::iri(vocabulary.insert(SEC_SIGNATURE_VALUE_IRI)),
                        (),
                    ),
                    Meta(
                        json_ld::Indexed::new(
                            json_ld::Object::Value(json_ld::Value::Literal(
                                json_ld::object::Literal::String(
                                    json_ld::object::LiteralString::Inferred(proof_value.0),
                                ),
                                Some(vocabulary.insert(XSD_STRING)),
                            )),
                            None,
                        ),
                        (),
                    ),
                );
            }
        }

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
        let mut proof_value = None;

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
                } else if p == SEC_CRYPTOSUITE_IRI {
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
                } else if p == SEC_VERIFICATION_METHOD_IRI {
                    for o in objects {
                        verification_method = Some(T::VerificationMethod::from_rdf(
                            vocabulary,
                            interpretation,
                            graph,
                            o,
                        )?);
                    }
                } else if p == SEC_PROOF_PURPOSE_IRI {
                    for o in objects {
                        match interpretation.iris_of(o).next() {
                            Some(iri) => {
                                let ty = vocabulary.iri(iri).unwrap();
                                proof_purpose = Some(ty.to_owned())
                            }
                            None => return Err(FromRdfError::UnexpectedLiteralValue),
                        }
                    }
                } else if p == SEC_PROOF_VALUE_IRI {
                    for o in objects {
                        proof_value = Some(signature::Any::ProofValue(
                            ssi_vc::schema::sec::layout::Multibase::from_rdf(
                                vocabulary,
                                interpretation,
                                graph,
                                o,
                            )?
                            .into(),
                        ));
                    }
                } else if p == SEC_JWS_IRI {
                    for o in objects {
                        let string = String::from_rdf(vocabulary, interpretation, graph, o)?;

                        match ssi_jws::CompactJWSString::from_string(string) {
                            Ok(jws) => proof_value = Some(signature::Any::Jws(jws.into())),
                            Err(_) => return Err(FromRdfError::InvalidLexicalRepresentation),
                        }
                    }
                } else if p == SEC_SIGNATURE_VALUE_IRI {
                    for o in objects {
                        let value = String::from_rdf(vocabulary, interpretation, graph, o)?;
                        proof_value = Some(signature::Any::SignatureValue(value.into()))
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
        let proof_value = proof_value.ok_or(FromRdfError::MissingRequiredPropertyValue)?;

        Ok(Self::new(
            AnyType::new(type_, crypto_suite).into(),
            created,
            verification_method,
            proof_purpose,
            proof_value,
        ))
    }
}

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
                SEC_CRYPTOSUITE_IRI.to_owned(),
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
            SEC_VERIFICATION_METHOD_IRI.to_owned(),
            verification_method,
            None,
        ));

        result.push(Quad(
            subject,
            SEC_PROOF_PURPOSE_IRI.to_owned(),
            Object::Id(Id::Iri(self.proof_purpose.iri().to_owned())),
            None,
        ));

        ssi_rdf::urdna2015::normalize(result.iter().map(Quad::as_quad_ref)).collect()
    }
}

#[derive(Debug, Clone)]
pub struct ProofOptions<M> {
    pub created: ssi_vc::schema::xsd::layout::DateTime,
    pub verification_method: M,
    pub proof_purpose: ProofPurpose,
}

impl<M> ProofOptions<M> {
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

    pub fn try_cast_verification_method<N: TryFromVerificationMethod<M>>(
        self,
    ) -> Result<ProofOptions<N>, InvalidVerificationMethod> {
        Ok(ProofOptions {
            created: self.created,
            verification_method: self.verification_method.try_into_verification_method()?,
            proof_purpose: self.proof_purpose,
        })
    }
}
