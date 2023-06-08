use std::hash::Hash;

use iref::{Iri, IriBuf};
use rdf_types::{BlankIdBuf, Id, Literal, Object, Quad, Subject, VocabularyMut};
use static_iref::iri;
use treeldr_rust_prelude::{
    json_ld,
    locspan::{Meta, Stripped},
};

use crate::suite::{Type, VerificationMethod};

/// Data Integrity Proof.
///
/// # Type parameters
///
/// - `T`: proof type value type.
/// - `M`: verification method type. Represents the IRI to the verification
/// method. By default it is `IriBuf`, meaning that any IRI can be represented,
/// but some application may choose to restrict the supported methods.
pub struct Proof<T, M = IriBuf> {
    /// Proof type.
    ///
    /// Also includes the cryptographic suite variant.
    pub type_: T,

    /// Date and time of creation.
    pub created: ssi_vc::schema::xsd::layout::DateTime,

    /// Verification method.
    pub verification_method: M,

    /// Proof purpose.
    pub proof_purpose: ProofPurpose,

    /// Multi-base encoded proof value.
    pub proof_value: String,
}

impl<T, M> Proof<T, M> {
    pub fn from_options(options: ProofOptions<T, M>, proof_value: String) -> Self {
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
        verification_method: M,
        proof_purpose: ProofPurpose,
        proof_value: String,
    ) -> Self {
        Self {
            type_,
            created,
            verification_method,
            proof_purpose,
            proof_value,
        }
    }
}

impl<T: Type, M: VerificationMethod, V: VocabularyMut>
    treeldr_rust_prelude::ld::IntoJsonLdObjectMeta<V> for Proof<T, M>
where
    V::Iri: Eq + Hash,
    V::BlankId: Eq + Hash,
{
    fn into_json_ld_object_meta(
        self,
        vocabulary: &mut V,
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
                Meta(
                    json_ld::Id::iri(
                        vocabulary.insert(iri!("https://w3id.org/security#cryptosuite")),
                    ),
                    (),
                ),
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
            Meta(
                json_ld::Id::iri(vocabulary.insert(iri!("http://purl.org/dc/terms/created"))),
                (),
            ),
            Meta(
                json_ld::Indexed::new(
                    json_ld::Object::Value(json_ld::Value::Literal(
                        json_ld::object::Literal::String(json_ld::object::LiteralString::Inferred(
                            self.created.format("%Y-%m-%dT%H:%M:%S%:z").to_string(),
                        )),
                        Some(vocabulary.insert(iri!("http://www.w3.org/2001/XMLSchema#dateTime"))),
                    )),
                    None,
                ),
                (),
            ),
        );

        properties.insert(
            Meta(
                json_ld::Id::iri(
                    vocabulary.insert(iri!("https://w3id.org/security#verificationMethod")),
                ),
                (),
            ),
            Meta(
                json_ld::Indexed::new(
                    json_ld::Object::Node(Box::new(json_ld::Node::with_id(
                        json_ld::syntax::Entry::new(
                            (),
                            Meta(
                                json_ld::Id::iri(vocabulary.insert(self.verification_method.iri())),
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
            Meta(
                json_ld::Id::iri(vocabulary.insert(iri!("https://w3id.org/security#proofPurpose"))),
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
            Meta(
                json_ld::Id::iri(vocabulary.insert(iri!("https://w3id.org/security#proofValue"))),
                (),
            ),
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

pub struct ProofConfiguration<T, M = IriBuf> {
    pub type_: T,
    pub created: ssi_vc::schema::xsd::layout::DateTime,
    pub verification_method: M,
    pub proof_purpose: ProofPurpose,
}

impl<T: Type, M: VerificationMethod> ProofConfiguration<T, M> {
    /// Returns the quads of the proof configuration, in canonical form.
    pub fn quads(&self) -> Vec<Quad> {
        let mut result: Vec<Quad> = Vec::new();

        let subject = Subject::Blank(BlankIdBuf::from_suffix("proofConfiguration").unwrap());

        result.push(Quad(
            subject.clone(),
            iri!("http://www.w3.org/1999/02/22-rdf-syntax-ns#type").to_owned(),
            Object::Id(Id::Iri(self.type_.iri().to_owned())),
            None,
        ));

        if let Some(crypto_suite) = self.type_.cryptographic_suite() {
            result.push(Quad(
                subject.clone(),
                iri!("https://w3id.org/security#cryptosuite").to_owned(),
                Object::Literal(Literal::String(crypto_suite.to_string())),
                None,
            ));
        }

        result.push(Quad(
            subject.clone(),
            iri!("http://purl.org/dc/terms/created").to_owned(),
            Object::Literal(Literal::TypedString(
                self.created.format("%Y-%m-%dT%H:%M:%S").to_string(),
                iri!("http://www.w3.org/2001/XMLSchema#dateTime").to_owned(),
            )),
            None,
        ));

        result.push(Quad(
            subject.clone(),
            iri!("https://w3id.org/security#verificationMethod").to_owned(),
            Object::Id(Id::Iri(self.verification_method.iri().to_owned())),
            None,
        ));

        result.push(Quad(
            subject,
            iri!("https://w3id.org/security#proofPurpose").to_owned(),
            Object::Id(Id::Iri(self.proof_purpose.iri().to_owned())),
            None,
        ));

        ssi_rdf::urdna2015::normalize(result.iter().map(Quad::as_quad_ref)).collect()
    }
}

#[derive(Debug, Clone)]
pub struct ProofOptions<T, M = IriBuf> {
    pub type_: T,
    pub created: ssi_vc::schema::xsd::layout::DateTime,
    pub verification_method: M,
    pub proof_purpose: ProofPurpose,
}

impl<T, M> ProofOptions<T, M> {
    pub fn new(
        type_: T,
        created: ssi_vc::schema::xsd::layout::DateTime,
        verification_method: M,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProofPurpose {
    /// <https://w3id.org/security#assertionMethod>
    AssertionMethod,

    /// <https://w3id.org/security#authenticationMethod>
    Authentication,

    /// <https://w3id.org/security#capabilityInvocationMethod>
    CapabilityInvocation,

    /// <https://w3id.org/security#capabilityDelegationMethod>
    CapabilityDelegation,

    /// <https://w3id.org/security#keyAgreementMethod>
    KeyAgreement,
}

impl ProofPurpose {
    pub fn iri(&self) -> Iri<'static> {
        match self {
            Self::AssertionMethod => iri!("https://w3id.org/security#assertionMethod"),
            Self::Authentication => iri!("https://w3id.org/security#authenticationMethod"),
            Self::CapabilityInvocation => {
                iri!("https://w3id.org/security#capabilityInvocationMethod")
            }
            Self::CapabilityDelegation => {
                iri!("https://w3id.org/security#capabilityDelegationMethod")
            }
            Self::KeyAgreement => iri!("https://w3id.org/security#keyAgreementMethod"),
        }
    }
}
