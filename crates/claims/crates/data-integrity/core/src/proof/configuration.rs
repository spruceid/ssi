use educe::Educe;
use iref::{Iri, IriBuf};
use linked_data::{LinkedDataResource, LinkedDataSubject};
use rdf_types::{
    dataset::{BTreeGraph, IndexedBTreeDataset, PatternMatchingDataset},
    interpretation::ReverseTermInterpretation,
    vocabulary::IriVocabulary,
    Id, InterpretationMut, LexicalQuad, Quad, Term, Triple, VocabularyMut,
};
use serde::{Deserialize, Serialize};
use ssi_core::Referencable;
use ssi_json_ld::AnyJsonLdEnvironment;
use ssi_rdf::{urdna2015, IntoNQuads};
use ssi_verification_methods_core::{ProofPurpose, ReferenceOrOwned, ReferenceOrOwnedRef};
use static_iref::iri;
use std::{collections::BTreeMap, hash::Hash, ops::Deref};

use crate::{CryptographicSuite, Proof};

pub const DC_CREATED_IRI: &Iri = iri!("http://purl.org/dc/terms/created");

pub const XSD_DATETIME_IRI: &Iri = iri!("http://www.w3.org/2001/XMLSchema#dateTime");

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProofConfiguration<M, O = ()> {
    /// Proof context.
    #[serde(rename = "@context", default, skip_serializing_if = "Option::is_none")]
    pub context: Option<json_ld::syntax::Context>,

    /// Date a creation of the proof.
    pub created: xsd_types::DateTime,

    /// Verification method.
    pub verification_method: ReferenceOrOwned<M>,

    /// Purpose of the proof.
    pub proof_purpose: ProofPurpose,

    /// Specifies when the proof expires.
    pub expires: Option<xsd_types::DateTime>, // FIXME: should be `DateTimeStamp`

    #[allow(rustdoc::bare_urls)]
    /// Conveys one or more security domains in which the proof is meant to be
    /// used.
    ///
    /// A verifier SHOULD use the value to ensure that the proof was intended to
    /// be used in the security domain in which the verifier is operating. The
    /// specification of the domain parameter is useful in challenge-response
    /// protocols where the verifier is operating from within a security domain
    /// known to the creator of the proof.
    ///
    /// Example domain values include: `domain.example`` (DNS domain),
    /// `https://domain.example:8443` (Web origin), `mycorp-intranet` (bespoke
    /// text string), and `b31d37d4-dd59-47d3-9dd8-c973da43b63a` (UUID).
    #[serde(rename = "domain")]
    pub domains: Vec<String>,

    /// Used to mitigate replay attacks.
    ///
    /// Used once for a particular domain and window of time. Examples of a
    /// challenge value include: `1235abcd6789`,
    /// `79d34551-ae81-44ae-823b-6dadbab9ebd4`, and `ruby`.
    pub challenge: Option<String>,

    /// Arbitrary string supplied by the proof creator.
    ///
    /// One use of this field is to increase privacy by decreasing linkability
    /// that is the result of deterministically generated signatures.
    pub nonce: Option<String>,

    /// Additional proof options required by the cryptographic suite.
    ///
    /// For instance, tezos cryptosuites requires the public key associated with
    /// the verification method, which is a blockchain account id.
    pub options: O,

    /// Extra properties.
    #[serde(flatten)]
    pub extra_properties: BTreeMap<String, json_syntax::Value>,
}

impl<M, O> ProofConfiguration<M, O> {
    pub fn new(
        created: xsd_types::DateTime,
        verification_method: ReferenceOrOwned<M>,
        proof_purpose: ProofPurpose,
        options: O,
    ) -> Self {
        Self {
            context: None,
            created,
            verification_method,
            proof_purpose,
            expires: None,
            domains: Vec::new(),
            challenge: None,
            nonce: None,
            options,
            extra_properties: BTreeMap::new(),
        }
    }

    pub fn from_method_and_options(verification_method: ReferenceOrOwned<M>, options: O) -> Self {
        Self {
            context: None,
            created: xsd_types::DateTime::now_ms(),
            verification_method,
            proof_purpose: ProofPurpose::default(),
            expires: None,
            domains: Vec::new(),
            challenge: None,
            nonce: None,
            options,
            extra_properties: BTreeMap::new(),
        }
    }

    pub fn from_method(verification_method: ReferenceOrOwned<M>) -> Self
    where
        O: Default,
    {
        Self::from_method_and_options(verification_method, O::default())
    }

    pub fn into_proof<S>(self, suite: S, signature: S::Signature) -> Proof<S>
    where
        S: CryptographicSuite<VerificationMethod = M, Options = O>,
    {
        Proof {
            context: self.context,
            type_: suite,
            created: self.created,
            verification_method: self.verification_method,
            proof_purpose: self.proof_purpose,
            expires: self.expires,
            domains: self.domains,
            challenge: self.challenge,
            nonce: self.nonce,
            options: self.options,
            signature,
            extra_properties: self.extra_properties,
        }
    }

    pub fn borrowed(&self) -> ProofConfigurationRef<M, O>
    where
        M: Referencable,
        O: Referencable,
    {
        ProofConfigurationRef {
            context: self.context.as_ref(),
            created: &self.created,
            verification_method: self.verification_method.borrowed(),
            proof_purpose: self.proof_purpose,
            options: self.options.as_reference(),
            extra_properties: &self.extra_properties,
        }
    }
}

#[derive(serde::Serialize)]
#[serde(bound = "M::Reference<'a>: serde::Serialize, O::Reference<'a>: serde::Serialize")]
pub struct ProofConfigurationWithSuiteRef<'a, 'b, M: Referencable, O: 'a + Referencable> {
    /// Proof context.
    #[serde(rename = "@context", skip_serializing_if = "Option::is_none")]
    pub context: Option<&'a json_ld::syntax::Context>,

    #[serde(rename = "type")]
    pub type_: &'b str,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptosuite: Option<&'b str>,

    pub created: &'a xsd_types::DateTime,

    #[serde(rename = "verificationMethod")]
    pub verification_method: ReferenceOrOwnedRef<'a, M>,

    #[serde(rename = "proofPurpose")]
    pub proof_purpose: ProofPurpose,

    #[serde(flatten)]
    pub options: O::Reference<'a>,

    /// Extra properties.
    #[serde(flatten)]
    pub extra_properties: &'a BTreeMap<String, json_syntax::Value>,
}

#[derive(Serialize, Educe)]
#[educe(Debug(bound = "M::Reference<'a>: core::fmt::Debug, O::Reference<'a>: core::fmt::Debug"))]
#[serde(
    rename_all = "camelCase",
    bound(serialize = "M::Reference<'a>: Serialize, O::Reference<'a>: Serialize")
)]
pub struct ProofConfigurationRef<'a, M: Referencable, O: 'a + Referencable = ()> {
    /// Proof context.
    #[serde(rename = "@context", default, skip_serializing_if = "Option::is_none")]
    pub context: Option<&'a json_ld::syntax::Context>,

    pub created: &'a xsd_types::DateTime,

    pub verification_method: ReferenceOrOwnedRef<'a, M>,

    pub proof_purpose: ProofPurpose,

    #[serde(flatten)]
    pub options: O::Reference<'a>,

    /// Extra properties.
    #[serde(flatten)]
    pub extra_properties: &'a BTreeMap<String, json_syntax::Value>,
}

#[derive(Debug, thiserror::Error)]
pub enum ProofConfigurationCastError<M, O> {
    #[error("invalid verification method")]
    VerificationMethod(M),

    #[error("invalid options")]
    Options(O),
}

impl<'a, M: Referencable, O: Referencable> ProofConfigurationRef<'a, M, O> {
    pub fn new(
        context: Option<&'a json_ld::syntax::Context>,
        created: &'a xsd_types::DateTime,
        verification_method: ReferenceOrOwnedRef<'a, M>,
        proof_purpose: ProofPurpose,
        options: O::Reference<'a>,
        extra_properties: &'a BTreeMap<String, json_syntax::Value>,
    ) -> Self {
        Self {
            context,
            created,
            verification_method,
            proof_purpose,
            options,
            extra_properties,
        }
    }

    /// Apply covariance rules to shorten the `'a` lifetime.
    pub fn shorten_lifetime<'b>(self) -> ProofConfigurationRef<'b, M, O>
    where
        'a: 'b,
    {
        ProofConfigurationRef {
            context: self.context,
            created: self.created,
            verification_method: self.verification_method.shorten_lifetime(),
            proof_purpose: self.proof_purpose,
            options: O::apply_covariance(self.options),
            extra_properties: self.extra_properties,
        }
    }

    pub fn try_map_verification_method<N: 'a + Referencable, P: 'a + Referencable, E>(
        self,
        f: impl FnOnce(
            ReferenceOrOwnedRef<'a, M>,
            O::Reference<'a>,
        ) -> Result<(ReferenceOrOwnedRef<'a, N>, P::Reference<'a>), E>,
    ) -> Result<ProofConfigurationRef<'a, N, P>, E> {
        let (verification_method, options) = f(self.verification_method, self.options)?;

        Ok(ProofConfigurationRef::new(
            self.context,
            self.created,
            verification_method,
            self.proof_purpose,
            options,
            self.extra_properties,
        ))
    }

    pub fn map_options<P: 'a + Referencable>(
        self,
        f: impl FnOnce(O::Reference<'a>) -> P::Reference<'a>,
    ) -> ProofConfigurationRef<'a, M, P> {
        ProofConfigurationRef::new(
            self.context,
            self.created,
            self.verification_method,
            self.proof_purpose,
            f(self.options),
            self.extra_properties,
        )
    }

    pub fn map_verification_method<N: 'a + Referencable, P: 'a + Referencable>(
        self,
        f: impl FnOnce(
            ReferenceOrOwnedRef<'a, M>,
            O::Reference<'a>,
        ) -> (ReferenceOrOwnedRef<'a, N>, P::Reference<'a>),
    ) -> ProofConfigurationRef<'a, N, P> {
        let (verification_method, options) = f(self.verification_method, self.options);
        ProofConfigurationRef::new(
            self.context,
            self.created,
            verification_method,
            self.proof_purpose,
            options,
            self.extra_properties,
        )
    }

    pub fn try_cast_verification_method<
        N: 'a + Referencable,
        P: 'a + Referencable,
        MError,
        OError,
    >(
        self,
    ) -> Result<ProofConfigurationRef<'a, N, P>, ProofConfigurationCastError<MError, OError>>
    where
        M::Reference<'a>: TryInto<N::Reference<'a>, Error = MError>,
        O::Reference<'a>: TryInto<P::Reference<'a>, Error = OError>,
    {
        self.try_map_verification_method(|m, options| {
            let m = m
                .try_cast()
                .map_err(ProofConfigurationCastError::VerificationMethod)?;
            let options = options
                .try_into()
                .map_err(ProofConfigurationCastError::Options)?;
            Ok((m, options))
        })
    }

    pub fn with_suite<'b, T: CryptographicSuite>(
        &self,
        suite: &'b T,
    ) -> ProofConfigurationWithSuiteRef<'a, 'b, M, O> {
        ProofConfigurationWithSuiteRef {
            context: self.context,
            type_: suite.name(),
            cryptosuite: suite.cryptographic_suite(),
            created: self.created,
            verification_method: self.verification_method,
            proof_purpose: self.proof_purpose,
            options: self.options,
            extra_properties: self.extra_properties,
        }
    }

    pub fn without_options(self) -> ProofConfigurationRef<'a, M> {
        ProofConfigurationRef {
            context: self.context,
            created: self.created,
            verification_method: self.verification_method,
            proof_purpose: self.proof_purpose,
            options: (),
            extra_properties: self.extra_properties,
        }
    }

    pub async fn expand<S, E: ProofConfigurationRefExpansion<'a, S>>(
        &self,
        context: &json_ld::syntax::Context,
        suite: &S,
        environment: &mut E,
    ) -> Result<LinkedDataConfiguration, ConfigurationExpansionError<E::LoadError>>
    where
        S: CryptographicSuite<VerificationMethod = M, Options = O>,
    {
        environment
            .expand_configuration(context, *self, suite)
            .await
    }
}

pub trait ProofConfigurationExpansion {
    type LoadError;
}

impl<E: AnyJsonLdEnvironment, I> ProofConfigurationExpansion for E
where
    E::Vocabulary: IriVocabulary<Iri = I>,
{
    type LoadError = <E::Loader as json_ld::Loader<I>>::Error;
}

pub trait ProofConfigurationRefExpansion<'a, S: CryptographicSuite>:
    ProofConfigurationExpansion
{
    #[allow(async_fn_in_trait)]
    async fn expand_configuration(
        &mut self,
        context: &json_ld::syntax::Context,
        configuration: ProofConfigurationRef<'a, S::VerificationMethod, S::Options>,
        suite: &S,
    ) -> Result<LinkedDataConfiguration, ConfigurationExpansionError<Self::LoadError>>;
}

impl<'a, S: CryptographicSuite, E, V, I, L> ProofConfigurationRefExpansion<'a, S> for E
where
    S::VerificationMethod: 'a,
    <S::VerificationMethod as Referencable>::Reference<'a>: serde::Serialize,
    S::Options: 'a,
    <S::Options as Referencable>::Reference<'a>: serde::Serialize,
    E: AnyJsonLdEnvironment<Vocabulary = V, Interpretation = I, Loader = L>,
    V: VocabularyMut,
    V::Iri: Clone + Eq + Hash + LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
    V::BlankId: Clone + Eq + Hash + LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
    I: InterpretationMut<V>
        + ReverseTermInterpretation<Iri = V::Iri, BlankId = V::BlankId, Literal = V::Literal>,
    I::Resource: Clone,
    L: json_ld::Loader<V::Iri>,
    L::Error: std::fmt::Display,
{
    async fn expand_configuration(
        &mut self,
        context: &json_ld::syntax::Context,
        configuration: ProofConfigurationRef<'a, S::VerificationMethod, S::Options>,
        suite: &S,
    ) -> Result<LinkedDataConfiguration, ConfigurationExpansionError<L::Error>> {
        use ssi_rdf::Expandable;

        #[derive(serde::Serialize)]
        #[serde(bound = "M::Reference<'a>: serde::Serialize, O::Reference<'a>: serde::Serialize")]
        struct CompactProofConfigurationDocument<'c, 'a, 'b, M: Referencable, O: Referencable> {
            #[serde(rename = "@context")]
            context: &'c json_ld::syntax::Context,

            proof: ProofConfigurationWithSuiteRef<'a, 'b, M, O>,
        }

        // Expand the proof.
        let proof_document = CompactProofConfigurationDocument {
            context,
            proof: configuration.with_suite(suite),
        };

        let json_proof_document = json_syntax::to_value(proof_document).unwrap();
        let json_ld_proof_document = ssi_json_ld::CompactJsonLd(json_proof_document)
            .expand(self)
            .await?;

        match json_ld_proof_document.into_main_node() {
            Some(node) => {
                let env = self.as_ld_environment_mut();

                // Get the proof type IRI.
                let proof_prop = json_ld::Id::iri(
                    env.vocabulary
                        .get(ssi_security::PROOF)
                        .ok_or(ConfigurationExpansionError::MissingProof)?,
                );
                let proof_type = match node.get_any(&proof_prop) {
                    Some(proof) => match proof.as_node() {
                        Some(proof) => match &proof.graph {
                            Some(proof_graph) => match proof_graph.first() {
                                Some(proof) => match proof.as_node() {
                                    Some(proof) => match proof.types() {
                                        [json_ld::Id::Valid(Id::Iri(iri))] => {
                                            Ok(env.vocabulary.iri(iri).unwrap().to_owned())
                                        }
                                        _ => Err(ConfigurationExpansionError::InvalidProofType),
                                    },
                                    None => Err(ConfigurationExpansionError::InvalidProofValue),
                                },
                                None => Err(ConfigurationExpansionError::MissingProof),
                            },
                            None => Err(ConfigurationExpansionError::InvalidProofValue),
                        },
                        None => Err(ConfigurationExpansionError::InvalidProofValue),
                    },
                    None => Err(ConfigurationExpansionError::MissingProof),
                }?;

                let (subject, quads) = linked_data::to_lexical_subject_quads_with(
                    env.vocabulary,
                    env.interpretation,
                    None,
                    &node,
                )?;

                let subject = Term::Id(subject);

                let mut dataset: IndexedBTreeDataset = quads
                    .into_iter()
                    .map(|q| Quad(Term::Id(q.0), Term::iri(q.1), q.2, q.3.map(Term::Id)))
                    .collect();

                let proof_prop = Term::iri(ssi_security::PROOF.to_owned());
                match dataset.quad_objects(None, &subject, &proof_prop).next() {
                    Some(Term::Id(proof_id)) => {
                        let proof_id = Term::Id(proof_id.clone());
                        match dataset.remove_graph(Some(&proof_id)) {
                            Some(graph) => Ok(LinkedDataConfiguration {
                                type_iri: proof_type,
                                graph,
                            }),
                            None => Err(ConfigurationExpansionError::MissingProofGraph),
                        }
                    }
                    Some(Term::Literal(_)) => Err(ConfigurationExpansionError::InvalidProofValue),
                    None => Err(ConfigurationExpansionError::MissingProof),
                }
            }
            None => Err(ConfigurationExpansionError::InvalidContext),
        }
    }
}

impl<'a, M: Referencable, O: 'a + Referencable> Clone for ProofConfigurationRef<'a, M, O> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, M: Referencable, O: 'a + Referencable> Copy for ProofConfigurationRef<'a, M, O> {}

#[derive(Debug, thiserror::Error)]
pub enum ConfigurationExpansionError<E> {
    #[error(transparent)]
    Expansion(#[from] ssi_json_ld::JsonLdError<E>),

    #[error(transparent)]
    IntoQuads(#[from] linked_data::IntoQuadsError),

    #[error("missing proof configuration")]
    MissingProof,

    #[error("missing proof configuration value")]
    InvalidProofValue,

    #[error("invalid proof type")]
    InvalidProofType,

    #[error("missing proof configuration graph")]
    MissingProofGraph,

    #[error("invalid JSON-LD context")]
    InvalidContext,
}

/// Linked-Data proof configuration.
pub struct LinkedDataConfiguration {
    pub type_iri: IriBuf,
    pub graph: BTreeGraph,
}

impl LinkedDataConfiguration {
    pub fn with_configuration<M: Referencable, O: Referencable>(
        self,
        configuration: ProofConfigurationRef<'_, M, O>,
    ) -> ExpandedConfiguration<'_, M, O> {
        ExpandedConfiguration {
            configuration,
            ld: self,
        }
    }
}

/// Expanded proof configuration.
#[derive(serde::Serialize)]
#[serde(bound = "M::Reference<'a>: serde::Serialize, O::Reference<'a>: serde::Serialize")]
#[serde(transparent)]
pub struct ExpandedConfiguration<'a, M: Referencable, O: Referencable = ()> {
    configuration: ProofConfigurationRef<'a, M, O>,

    #[serde(skip)]
    ld: LinkedDataConfiguration,
}

impl<'a, M: Referencable, O: Referencable> ExpandedConfiguration<'a, M, O> {
    /// Returns the quads of the proof configuration, in canonical form.
    pub fn quads(&self) -> impl '_ + Iterator<Item = LexicalQuad> {
        let quads = self.ld.graph.iter().map(|Triple(s, p, o)| {
            Quad(
                s.as_lexical_term_ref().into_id().unwrap(),
                p.as_lexical_term_ref().into_iri().unwrap(),
                o.as_lexical_term_ref(),
                None,
            )
        });

        urdna2015::normalize(quads)
    }

    /// Returns the quads of the proof configuration, in canonical form.
    pub fn nquads(&self) -> String {
        self.quads().into_nquads()
    }

    pub fn borrow(&self) -> ExpandedConfigurationRef<M, O> {
        ExpandedConfigurationRef {
            configuration: self.configuration.shorten_lifetime(),
            ld: &self.ld,
        }
    }

    /// Apply covariance rules to shorten the `'a` lifetime.
    pub fn shorten_lifetime<'b>(self) -> ExpandedConfiguration<'b, M, O>
    where
        'a: 'b,
    {
        ExpandedConfiguration {
            configuration: self.configuration.shorten_lifetime(),
            ld: self.ld,
        }
    }

    pub fn try_map_verification_method<N: 'a + Referencable, P: 'a + Referencable, E>(
        self,
        f: impl FnOnce(
            ReferenceOrOwnedRef<'a, M>,
            O::Reference<'a>,
        ) -> Result<(ReferenceOrOwnedRef<'a, N>, P::Reference<'a>), E>,
    ) -> Result<ExpandedConfiguration<'a, N, P>, E> {
        Ok(ExpandedConfiguration {
            configuration: self.configuration.try_map_verification_method(f)?,
            ld: self.ld,
        })
    }

    pub fn map_options<P: 'a + Referencable>(
        self,
        f: impl FnOnce(O::Reference<'a>) -> P::Reference<'a>,
    ) -> ExpandedConfiguration<'a, M, P> {
        ExpandedConfiguration {
            configuration: self.configuration.map_options(f),
            ld: self.ld,
        }
    }

    pub fn map_verification_method<N: 'a + Referencable, P: 'a + Referencable>(
        self,
        f: impl FnOnce(
            ReferenceOrOwnedRef<'a, M>,
            O::Reference<'a>,
        ) -> (ReferenceOrOwnedRef<'a, N>, P::Reference<'a>),
    ) -> ExpandedConfiguration<'a, N, P> {
        ExpandedConfiguration {
            configuration: self.configuration.map_verification_method(f),
            ld: self.ld,
        }
    }

    pub fn try_cast_verification_method<
        N: 'a + Referencable,
        P: 'a + Referencable,
        MError,
        OError,
    >(
        self,
    ) -> Result<ExpandedConfiguration<'a, N, P>, ProofConfigurationCastError<MError, OError>>
    where
        M::Reference<'a>: TryInto<N::Reference<'a>, Error = MError>,
        O::Reference<'a>: TryInto<P::Reference<'a>, Error = OError>,
    {
        Ok(ExpandedConfiguration {
            configuration: self.configuration.try_cast_verification_method()?,
            ld: self.ld,
        })
    }

    pub fn without_options(self) -> ExpandedConfiguration<'a, M> {
        ExpandedConfiguration {
            configuration: self.configuration.without_options(),
            ld: self.ld,
        }
    }
}

#[derive(serde::Serialize)]
#[serde(bound = "M::Reference<'a>: serde::Serialize, O::Reference<'a>: serde::Serialize")]
#[serde(transparent)]
pub struct ExpandedConfigurationRef<'a, M: Referencable, O: Referencable = ()> {
    configuration: ProofConfigurationRef<'a, M, O>,

    #[serde(skip)]
    ld: &'a LinkedDataConfiguration,
}

impl<'a, M: Referencable, O: Referencable> Deref for ExpandedConfigurationRef<'a, M, O> {
    type Target = ProofConfigurationRef<'a, M, O>;

    fn deref(&self) -> &Self::Target {
        &self.configuration
    }
}

impl<'a, M: Referencable, O: Referencable> ExpandedConfigurationRef<'a, M, O> {
    pub fn compact(&self) -> ProofConfigurationRef<'a, M, O> {
        self.configuration
    }
}

impl<'a, M: Referencable, O: Referencable> ExpandedConfigurationRef<'a, M, O> {
    /// Returns the quads of the proof configuration, in canonical form.
    pub fn quads(&self) -> impl '_ + Iterator<Item = LexicalQuad> {
        let quads = self.ld.graph.iter().map(|Triple(s, p, o)| {
            Quad(
                s.as_lexical_term_ref().into_id().unwrap(),
                p.as_lexical_term_ref().into_iri().unwrap(),
                o.as_lexical_term_ref(),
                None,
            )
        });

        urdna2015::normalize(quads)
    }

    /// Returns the quads of the proof configuration, in canonical form.
    pub fn nquads(&self) -> String {
        self.quads().into_nquads()
    }

    /// Apply covariance rules to shorten the `'a` lifetime.
    pub fn shorten_lifetime<'b>(self) -> ExpandedConfigurationRef<'b, M, O>
    where
        'a: 'b,
    {
        ExpandedConfigurationRef {
            configuration: self.configuration.shorten_lifetime(),
            ld: self.ld,
        }
    }

    pub fn try_map_verification_method<N: 'a + Referencable, P: 'a + Referencable, E>(
        self,
        f: impl FnOnce(
            ReferenceOrOwnedRef<'a, M>,
            O::Reference<'a>,
        ) -> Result<(ReferenceOrOwnedRef<'a, N>, P::Reference<'a>), E>,
    ) -> Result<ExpandedConfigurationRef<'a, N, P>, E> {
        Ok(ExpandedConfigurationRef {
            configuration: self.configuration.try_map_verification_method(f)?,
            ld: self.ld,
        })
    }

    pub fn map_options<P: 'a + Referencable>(
        self,
        f: impl FnOnce(O::Reference<'a>) -> P::Reference<'a>,
    ) -> ExpandedConfigurationRef<'a, M, P> {
        ExpandedConfigurationRef {
            configuration: self.configuration.map_options(f),
            ld: self.ld,
        }
    }

    pub fn map_verification_method<N: 'a + Referencable, P: 'a + Referencable>(
        self,
        f: impl FnOnce(
            ReferenceOrOwnedRef<'a, M>,
            O::Reference<'a>,
        ) -> (ReferenceOrOwnedRef<'a, N>, P::Reference<'a>),
    ) -> ExpandedConfigurationRef<'a, N, P> {
        ExpandedConfigurationRef {
            configuration: self.configuration.map_verification_method(f),
            ld: self.ld,
        }
    }

    pub fn try_cast_verification_method<
        N: 'a + Referencable,
        P: 'a + Referencable,
        MError,
        OError,
    >(
        self,
    ) -> Result<ExpandedConfigurationRef<'a, N, P>, ProofConfigurationCastError<MError, OError>>
    where
        M::Reference<'a>: TryInto<N::Reference<'a>, Error = MError>,
        O::Reference<'a>: TryInto<P::Reference<'a>, Error = OError>,
    {
        Ok(ExpandedConfigurationRef {
            configuration: self.configuration.try_cast_verification_method()?,
            ld: self.ld,
        })
    }

    pub fn without_options(self) -> ExpandedConfigurationRef<'a, M> {
        ExpandedConfigurationRef {
            configuration: self.configuration.without_options(),
            ld: self.ld,
        }
    }
}
