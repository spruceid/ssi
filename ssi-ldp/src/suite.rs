//! Cryptographic suites.

mod ed25519_signature_2020;

use std::hash::Hash;

pub use ed25519_signature_2020::Ed25519Signature2020;
use rdf_types::{BlankIdBuf, Id, Literal, Object, Quad, Subject, VocabularyMut};
use treeldr_rust_prelude::json_ld;
use treeldr_rust_prelude::{
    iref::{Iri, IriBuf},
    locspan::{Meta, Stripped},
    static_iref::iri,
};

use crate::{LinkedDataCredential, ProofValidity, SignerProvider, VerifierProvider};

pub trait Type {
    fn iri(&self) -> Iri;

    fn cryptographic_suite(&self) -> Option<&str>;
}

pub trait VerificationMethod {
    fn iri(&self) -> Iri;
}

impl VerificationMethod for IriBuf {
    fn iri(&self) -> Iri {
        self.as_iri()
    }
}

pub trait ProofPurpose {
    fn iri(&self) -> Iri;
}

impl ProofPurpose for IriBuf {
    fn iri(&self) -> Iri {
        self.as_iri()
    }
}

pub struct TransformationOptions<T> {
    pub type_: T,
}

pub struct ProofConfiguration<T, M = IriBuf, P = IriBuf> {
    pub type_: T,
    pub created: ssi_vc::schema::xsd::layout::DateTime,
    pub verification_method: M,
    pub proof_purpose: P,
}

impl<T: Type, M: VerificationMethod, P: ProofPurpose> ProofConfiguration<T, M, P> {
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
pub struct ProofOptions<T, M = IriBuf, P = IriBuf> {
    pub type_: T,
    pub created: ssi_vc::schema::xsd::layout::DateTime,
    pub verification_method: M,
    pub proof_purpose: P,
}

impl<T, M, P> ProofOptions<T, M, P> {
    pub fn new(
        type_: T,
        created: ssi_vc::schema::xsd::layout::DateTime,
        verification_method: M,
        proof_purpose: P,
    ) -> Self {
        Self {
            type_,
            created,
            verification_method,
            proof_purpose,
        }
    }
}

/// Data Integrity Proof.
///
/// # Type parameters
///
/// - `T`: proof type value type.
/// - `M`: verification method type. Represents the IRI to the verification
/// method. By default it is `IriBuf`, meaning that any IRI can be represented,
/// but some application may choose to restrict the supported methods.
/// - `P`: proof purpose type. Represents the IRI to the proof purpose. By
/// default it is `IriBuf`, meaning that any IRI can be represented, but some
/// application may choose to restrict the supported proof purposes.
// TODO: Is there an official set of proof purposes defined somewhere? In which
// case `P` might by superfluous.
pub struct DataIntegrityProof<T, M = IriBuf, P = IriBuf> {
    /// Proof type.
    ///
    /// Also includes the cryptographic suite variant.
    pub type_: T,

    /// Date and time of creation.
    pub created: ssi_vc::schema::xsd::layout::DateTime,

    /// Verification method.
    pub verification_method: M,

    /// Proof purpose.
    pub proof_purpose: P,

    /// Multi-base encoded proof value.
    pub proof_value: String,
}

impl<T, M, P> DataIntegrityProof<T, M, P> {
    pub fn from_options(options: ProofOptions<T, M, P>, proof_value: String) -> Self {
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
        proof_purpose: P,
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

impl<T: Type, M: VerificationMethod, P: ProofPurpose, V: VocabularyMut>
    treeldr_rust_prelude::ld::IntoJsonLdObjectMeta<V> for DataIntegrityProof<T, M, P>
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

pub trait CryptographicSuiteInput<T, M, C>: CryptographicSuite<M> {
    /// Transformation algorithm.
    fn transform(
        &self,
        context: &mut C,
        data: &T,
        params: Self::TransformationParameters,
    ) -> Result<Self::Transformed, Self::Error>;
}

/// Cryptographic suite.
///
/// The type parameter `T` is the type of documents on which the suite can be
/// applied.
pub trait CryptographicSuite<M> {
    /// Error that can be raised by the suite.
    type Error;

    /// Transformation algorithm parameters.
    type TransformationParameters;

    /// Transformation algorithm result.
    type Transformed;

    /// Hashing algorithm parameters.
    type HashParameters;

    /// Hashing algorithm result.
    type Hashed;

    /// Proof generation algorithm parameters.
    type ProofParameters;

    /// Proof type.
    ///
    /// Return type of the proof generation algorithm.
    type Proof;

    /// Hashing algorithm.
    fn hash(
        &self,
        data: Self::Transformed,
        params: Self::HashParameters,
    ) -> Result<Self::Hashed, Self::Error>;

    fn generate_proof(
        &self,
        data: Self::Hashed,
        signer_provider: &impl SignerProvider<M>,
        params: Self::ProofParameters,
    ) -> Result<Self::Proof, Self::Error>;

    fn verify_proof(
        &self,
        data: Self::Hashed,
        verifier_provider: &impl VerifierProvider<M>,
        proof: &Self::Proof,
    ) -> Result<ProofValidity, Self::Error>;
}

/// LD cryptographic suite.
pub trait LinkedDataCryptographicSuite<M, C>: CryptographicSuite<M> {
    /// Transformation algorithm.
    fn transform<T: LinkedDataCredential<C>>(
        &self,
        context: &mut C,
        data: &T,
        options: Self::TransformationParameters,
    ) -> Result<Self::Transformed, Self::Error>;
}

/// Any LD cryptographic suite is a cryptographic suite working on LD documents.
impl<
        M,
        C,
        S: CryptographicSuite<M> + LinkedDataCryptographicSuite<M, C>,
        T: LinkedDataCredential<C>,
    > CryptographicSuiteInput<T, M, C> for S
{
    fn transform(
        &self,
        context: &mut C,
        data: &T,
        params: Self::TransformationParameters,
    ) -> Result<Self::Transformed, Self::Error> {
        self.transform(context, data, params)
    }
}
