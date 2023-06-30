use std::hash::Hash;

use iref::{Iri, IriBuf};
use json_ld::rdf::{RDF_TYPE, XSD_STRING};
use rdf_types::{
    interpretation::ReverseIriInterpretation, BlankIdBuf, Id, IriVocabulary, Literal, Object, Quad,
    Subject, VocabularyMut,
};
use ssi_crypto::ProofPurpose;
use ssi_verification_methods::LinkedDataVerificationMethod;
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
    pub type_: T,

    /// Date and time of creation.
    pub created: ssi_vc::schema::xsd::layout::DateTime,

    /// Verification method.
    pub verification_method: T::VerificationMethod,

    /// Proof purpose.
    pub proof_purpose: ProofPurpose,

    /// Multi-base encoded proof value.
    pub proof_value: ssi_vc::schema::sec::layout::Multibase,
}

impl<T: CryptographicSuite> Proof<T> {
    pub fn from_options(
        options: ProofOptions<T>,
        proof_value: ssi_vc::schema::sec::layout::Multibase,
    ) -> Self {
        Self::new(
            options.type_,
            options.created,
            options.verification_method,
            options.proof_purpose,
            proof_value,
        )
    }

    pub fn new(
        type_: T,
        created: ssi_vc::schema::xsd::layout::DateTime,
        verification_method: T::VerificationMethod,
        proof_purpose: ProofPurpose,
        proof_value: ssi_vc::schema::sec::layout::Multibase,
    ) -> Self {
        Self {
            type_,
            created,
            verification_method,
            proof_purpose,
            proof_value,
        }
    }

    pub fn suite(&self) -> &T {
        &self.type_
    }
}

pub const SEC_CRYPTOSUITE_IRI: Iri<'static> = iri!("https://w3id.org/security#cryptosuite");
pub const SEC_VERIFICATION_METHOD_IRI: Iri<'static> =
    iri!("https://w3id.org/security#verificationMethod");
pub const SEC_PROOF_PURPOSE_IRI: Iri<'static> = iri!("https://w3id.org/security#proofPurpose");
pub const SEC_PROOF_VALUE_IRI: Iri<'static> = iri!("https://w3id.org/security#proofValue");

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
            Meta(
                json_ld::Id::iri(vocabulary.insert(SEC_VERIFICATION_METHOD_IRI)),
                (),
            ),
            self.verification_method
                .into_json_ld_object_meta(vocabulary, interpretation, ()),
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

        properties.insert(
            Meta(json_ld::Id::iri(vocabulary.insert(SEC_PROOF_VALUE_IRI)), ()),
            Meta(
                json_ld::Indexed::new(
                    json_ld::Object::Value(json_ld::Value::Literal(
                        json_ld::object::Literal::String(json_ld::object::LiteralString::Inferred(
                            self.proof_value.to_string(),
                        )),
                        Some(vocabulary.insert(iri!("https://w3id.org/security#multibase"))),
                    )),
                    None,
                ),
                (),
            ),
        );

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
                        proof_value = Some(ssi_vc::schema::sec::layout::Multibase::from_rdf(
                            vocabulary,
                            interpretation,
                            graph,
                            o,
                        )?);
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

        Ok(Self {
            type_: AnyType::new(type_, crypto_suite).into(),
            created,
            verification_method,
            proof_purpose,
            proof_value,
        })
    }
}

pub struct ProofConfiguration<T: CryptographicSuite> {
    pub type_: T,
    pub created: ssi_vc::schema::xsd::layout::DateTime,
    pub verification_method: T::VerificationMethod,
    pub proof_purpose: ProofPurpose,
}

impl<T: CryptographicSuite> ProofConfiguration<T> {
    /// Returns the quads of the proof configuration, in canonical form.
    pub fn quads(&self) -> Vec<Quad>
    where
        T::VerificationMethod: LinkedDataVerificationMethod,
    {
        let mut result: Vec<Quad> = Vec::new();

        let subject = Subject::Blank(BlankIdBuf::from_suffix("proofConfiguration").unwrap());

        result.push(Quad(
            subject.clone(),
            RDF_TYPE.to_owned(),
            Object::Id(Id::Iri(self.type_.iri().to_owned())),
            None,
        ));

        if let Some(crypto_suite) = self.type_.cryptographic_suite() {
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
pub struct ProofOptions<T: CryptographicSuite> {
    pub type_: T,
    pub created: ssi_vc::schema::xsd::layout::DateTime,
    pub verification_method: T::VerificationMethod,
    pub proof_purpose: ProofPurpose,
}

impl<T: CryptographicSuite> ProofOptions<T> {
    pub fn new(
        type_: T,
        created: ssi_vc::schema::xsd::layout::DateTime,
        verification_method: T::VerificationMethod,
        proof_purpose: ProofPurpose,
    ) -> Self {
        Self {
            type_,
            created,
            verification_method,
            proof_purpose,
        }
    }
}
