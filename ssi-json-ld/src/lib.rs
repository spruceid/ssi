//! JSON-LD context loaders.

use std::collections::HashMap;
use std::sync::Arc;

pub mod rdf;
pub mod urdna2015;

use async_std::sync::RwLock;
use futures::future::{BoxFuture, FutureExt};
use iref::{Iri, IriBuf};
pub use json_ld::{syntax, Options, RemoteDocumentReference};
use json_ld::{syntax::TryFromJson, Loader};
use json_syntax::Parse;
use locspan::{Meta, Span};
use rdf_types::IriVocabularyMut;
use static_iref::iri;
use thiserror::Error;

/// Remote JSON-LD document.
pub type RemoteDocument = json_ld::RemoteDocument<IriBuf, Span>;

/// Error raised by the `json_to_dataset` function.
pub type ToRdfError<
    E = UnknownContext,
    C = json_ld::loader::ContextLoaderError<
        UnknownContext,
        Meta<json_ld::loader::ExtractContextError<Span>, Span>,
    >,
> = json_ld::ToRdfError<Span, E, C>;

pub const CREDENTIALS_V1_CONTEXT: Iri = iri!("https://www.w3.org/2018/credentials/v1");
pub const CREDENTIALS_V2_CONTEXT: Iri = iri!("https://www.w3.org/ns/credentials/v2");
pub const CREDENTIALS_EXAMPLES_V1_CONTEXT: Iri =
    iri!("https://www.w3.org/2018/credentials/examples/v1");
pub const CREDENTIALS_EXAMPLES_V2_CONTEXT: Iri =
    iri!("https://www.w3.org/ns/credentials/examples/v2");
pub const ODRL_CONTEXT: Iri = iri!("https://www.w3.org/ns/odrl.jsonld");
pub const SECURITY_V1_CONTEXT: Iri = iri!("https://w3id.org/security/v1");
pub const SECURITY_V2_CONTEXT: Iri = iri!("https://w3id.org/security/v2");
pub const SCHEMA_ORG_CONTEXT: Iri = iri!("https://schema.org/");
pub const DID_V1_CONTEXT: Iri = iri!("https://www.w3.org/ns/did/v1");
pub const DID_V1_CONTEXT_NO_WWW: Iri = iri!("https://w3.org/ns/did/v1");
pub const W3ID_DID_V1_CONTEXT: Iri = iri!("https://w3id.org/did/v1");
pub const DID_RESOLUTION_V1_CONTEXT: Iri = iri!("https://w3id.org/did-resolution/v1");
pub const DIF_ESRS2020_CONTEXT: Iri = iri!("https://identity.foundation/EcdsaSecp256k1RecoverySignature2020/lds-ecdsa-secp256k1-recovery2020-0.0.jsonld");
#[deprecated(note = "Use W3ID_ESRS2020_V2_CONTEXT instead")]
pub const ESRS2020_EXTRA_CONTEXT: Iri =
    iri!("https://demo.spruceid.com/EcdsaSecp256k1RecoverySignature2020/esrs2020-extra-0.0.jsonld");
pub const W3ID_ESRS2020_V2_CONTEXT: Iri =
    iri!("https://w3id.org/security/suites/secp256k1recovery-2020/v2");
pub const LDS_JWS2020_V1_CONTEXT: Iri =
    iri!("https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json");
pub const W3ID_JWS2020_V1_CONTEXT: Iri = iri!("https://w3id.org/security/suites/jws-2020/v1");
pub const W3ID_ED2020_V1_CONTEXT: Iri = iri!("https://w3id.org/security/suites/ed25519-2020/v1");
pub const W3ID_MULTIKEY_V1_CONTEXT: Iri = iri!("https://w3id.org/security/multikey/v1");
pub const W3ID_DATA_INTEGRITY_V1_CONTEXT: Iri = iri!("https://w3id.org/security/data-integrity/v1");
pub const BLOCKCHAIN2021_V1_CONTEXT: Iri =
    iri!("https://w3id.org/security/suites/blockchain-2021/v1");
pub const CITIZENSHIP_V1_CONTEXT: Iri = iri!("https://w3id.org/citizenship/v1");
pub const VACCINATION_V1_CONTEXT: Iri = iri!("https://w3id.org/vaccination/v1");
pub const TRACEABILITY_CONTEXT: Iri = iri!("https://w3id.org/traceability/v1");
pub const REVOCATION_LIST_2020_V1_CONTEXT: Iri =
    iri!("https://w3id.org/vc-revocation-list-2020/v1");
pub const BBS_V1_CONTEXT: Iri = iri!("https://w3id.org/security/bbs/v1");
pub const STATUS_LIST_2021_V1_CONTEXT: Iri = iri!("https://w3id.org/vc/status-list/2021/v1");
pub const EIP712SIG_V0_1_CONTEXT: Iri =
    iri!("https://demo.spruceid.com/ld/eip712sig-2021/v0.1.jsonld");
pub const EIP712SIG_V1_CONTEXT: Iri = iri!("https://w3id.org/security/suites/eip712sig-2021/v1");
pub const PRESENTATION_SUBMISSION_V1_CONTEXT: Iri =
    iri!("https://identity.foundation/presentation-exchange/submission/v1");
pub const VDL_V1_CONTEXT: Iri = iri!("https://w3id.org/vdl/v1");
pub const WALLET_V1_CONTEXT: Iri = iri!("https://w3id.org/wallet/v1");
pub const ZCAP_V1_CONTEXT: Iri = iri!("https://w3id.org/zcap/v1");
pub const CACAO_ZCAP_V1_CONTEXT: Iri =
    iri!("https://demo.didkit.dev/2022/cacao-zcap/contexts/v1.json");
pub const JFF_VC_EDU_PLUGFEST_2022_CONTEXT: Iri =
    iri!("https://w3c-ccg.github.io/vc-ed/plugfest-1-2022/jff-vc-edu-plugfest-1-context.json");
pub const DID_CONFIGURATION_V0_0_CONTEXT: Iri =
    iri!("https://identity.foundation/.well-known/contexts/did-configuration-v0.0.jsonld");
pub const JFF_VC_EDU_PLUGFEST_2022_2_CONTEXT: Iri =
    iri!("https://purl.imsglobal.org/spec/ob/v3p0/context.json");

/// Load a remote context from its static definition.
fn load_static_context(iri: Iri, content: &str) -> RemoteDocument {
    RemoteDocument::new(
        Some(iri.to_owned()),
        Some("application/ld+json".parse().unwrap()),
        json_syntax::Value::parse_str(content, |span| span).unwrap(),
    )
}

lazy_static::lazy_static! {
    pub static ref CREDENTIALS_V1_CONTEXT_DOCUMENT: RemoteDocument = load_static_context(
        CREDENTIALS_V1_CONTEXT,
        ssi_contexts::CREDENTIALS_V1
    );
    pub static ref CREDENTIALS_V2_CONTEXT_DOCUMENT: RemoteDocument = load_static_context(
        CREDENTIALS_V2_CONTEXT,
        ssi_contexts::CREDENTIALS_V2
    );
    pub static ref CREDENTIALS_EXAMPLES_V1_CONTEXT_DOCUMENT: RemoteDocument = load_static_context(
        CREDENTIALS_EXAMPLES_V1_CONTEXT,
        ssi_contexts::CREDENTIALS_EXAMPLES_V1
    );
    pub static ref CREDENTIALS_EXAMPLES_V2_CONTEXT_DOCUMENT: RemoteDocument = load_static_context(
        CREDENTIALS_EXAMPLES_V2_CONTEXT,
        ssi_contexts::CREDENTIALS_EXAMPLES_V2
    );
    pub static ref ODRL_CONTEXT_DOCUMENT: RemoteDocument = load_static_context(
        ODRL_CONTEXT,
        ssi_contexts::ODRL
    );
    pub static ref SCHEMA_ORG_CONTEXT_DOCUMENT: RemoteDocument = load_static_context(
        SCHEMA_ORG_CONTEXT,
        ssi_contexts::SCHEMA_ORG
    );
    pub static ref SECURITY_V1_CONTEXT_DOCUMENT: RemoteDocument = load_static_context(
        SECURITY_V1_CONTEXT,
        ssi_contexts::SECURITY_V1
    );
    pub static ref SECURITY_V2_CONTEXT_DOCUMENT: RemoteDocument = load_static_context(
        SECURITY_V2_CONTEXT,
        ssi_contexts::SECURITY_V2
    );
    pub static ref DID_V1_CONTEXT_DOCUMENT: RemoteDocument = load_static_context(
        DID_V1_CONTEXT,
        ssi_contexts::DID_V1
    );
    pub static ref DID_RESOLUTION_V1_CONTEXT_DOCUMENT: RemoteDocument = load_static_context(
        DID_RESOLUTION_V1_CONTEXT,
        ssi_contexts::DID_RESOLUTION_V1
    );
    /// Deprecated in favor of W3ID_ESRS2020_V2_CONTEXT_DOCUMENT
    pub static ref DIF_ESRS2020_CONTEXT_DOCUMENT: RemoteDocument = load_static_context(
        #[allow(deprecated)]
        DIF_ESRS2020_CONTEXT,
        #[allow(deprecated)]
        ssi_contexts::DIF_ESRS2020
    );
    pub static ref W3ID_ESRS2020_V2_CONTEXT_DOCUMENT: RemoteDocument = load_static_context(
        W3ID_ESRS2020_V2_CONTEXT,
        ssi_contexts::W3ID_ESRS2020_V2
    );
    /// Deprecated in favor of W3ID_ESRS2020_V2_CONTEXT_DOCUMENT
    pub static ref ESRS2020_EXTRA_CONTEXT_DOCUMENT: RemoteDocument = load_static_context(
        #[allow(deprecated)]
        ESRS2020_EXTRA_CONTEXT,
        #[allow(deprecated)]
        ssi_contexts::ESRS2020_EXTRA
    );
    pub static ref LDS_JWS2020_V1_CONTEXT_DOCUMENT: RemoteDocument = load_static_context(
        LDS_JWS2020_V1_CONTEXT,
        ssi_contexts::LDS_JWS2020_V1
    );
    pub static ref W3ID_JWS2020_V1_CONTEXT_DOCUMENT: RemoteDocument = load_static_context(
        W3ID_JWS2020_V1_CONTEXT,
        ssi_contexts::W3ID_JWS2020_V1
    );
    pub static ref W3ID_ED2020_V1_CONTEXT_DOCUMENT: RemoteDocument = load_static_context(
        W3ID_ED2020_V1_CONTEXT,
        ssi_contexts::W3ID_ED2020_V1
    );
    pub static ref W3ID_MULTIKEY_V1_CONTEXT_DOCUMENT: RemoteDocument = load_static_context(
        W3ID_MULTIKEY_V1_CONTEXT,
        ssi_contexts::W3ID_MULTIKEY_V1
    );
    pub static ref W3ID_DATA_INTEGRITY_V1_CONTEXT_DOCUMENT: RemoteDocument = load_static_context(
        W3ID_DATA_INTEGRITY_V1_CONTEXT,
        ssi_contexts::W3ID_DATA_INTEGRITY_V1
    );
    pub static ref BLOCKCHAIN2021_V1_CONTEXT_DOCUMENT: RemoteDocument = load_static_context(
        BLOCKCHAIN2021_V1_CONTEXT,
        ssi_contexts::BLOCKCHAIN2021_V1
    );
    pub static ref CITIZENSHIP_V1_CONTEXT_DOCUMENT: RemoteDocument = load_static_context(
        CITIZENSHIP_V1_CONTEXT,
        ssi_contexts::CITIZENSHIP_V1
    );
    pub static ref VACCINATION_V1_CONTEXT_DOCUMENT: RemoteDocument = load_static_context(
        VACCINATION_V1_CONTEXT,
        ssi_contexts::VACCINATION_V1
    );
    pub static ref TRACEABILITY_CONTEXT_DOCUMENT: RemoteDocument = load_static_context(
        TRACEABILITY_CONTEXT,
        ssi_contexts::TRACEABILITY_V1
    );
    pub static ref REVOCATION_LIST_2020_V1_CONTEXT_DOCUMENT: RemoteDocument = load_static_context(
        REVOCATION_LIST_2020_V1_CONTEXT,
        ssi_contexts::REVOCATION_LIST_2020_V1
    );
    pub static ref STATUS_LIST_2021_V1_CONTEXT_DOCUMENT: RemoteDocument = load_static_context(
        STATUS_LIST_2021_V1_CONTEXT,
        ssi_contexts::STATUS_LIST_2021_V1
    );
    pub static ref EIP712SIG_V0_1_CONTEXT_DOCUMENT: RemoteDocument = load_static_context(
        EIP712SIG_V0_1_CONTEXT,
        ssi_contexts::EIP712SIG_V0_1
    );
    pub static ref BBS_V1_CONTEXT_DOCUMENT: RemoteDocument = load_static_context(
        BBS_V1_CONTEXT,
        ssi_contexts::BBS_V1
    );
    pub static ref EIP712SIG_V1_CONTEXT_DOCUMENT: RemoteDocument = load_static_context(
        EIP712SIG_V1_CONTEXT,
        ssi_contexts::EIP712SIG_V1
    );
    pub static ref PRESENTATION_SUBMISSION_V1_CONTEXT_DOCUMENT: RemoteDocument = load_static_context(
        PRESENTATION_SUBMISSION_V1_CONTEXT,
        ssi_contexts::PRESENTATION_SUBMISSION_V1
    );
    pub static ref VDL_V1_CONTEXT_DOCUMENT: RemoteDocument = load_static_context(
        VDL_V1_CONTEXT,
        ssi_contexts::VDL_V1
    );
    pub static ref WALLET_V1_CONTEXT_DOCUMENT: RemoteDocument = load_static_context(
        WALLET_V1_CONTEXT,
        ssi_contexts::WALLET_V1
    );
    pub static ref ZCAP_V1_CONTEXT_DOCUMENT: RemoteDocument = load_static_context(
        ZCAP_V1_CONTEXT,
        ssi_contexts::ZCAP_V1
    );
    pub static ref CACAO_ZCAP_V1_CONTEXT_DOCUMENT: RemoteDocument = load_static_context(
        CACAO_ZCAP_V1_CONTEXT,
        ssi_contexts::CACAO_ZCAP_V1
    );
    pub static ref JFF_VC_EDU_PLUGFEST_2022_CONTEXT_DOCUMENT: RemoteDocument = load_static_context(
        JFF_VC_EDU_PLUGFEST_2022_CONTEXT,
        ssi_contexts::JFF_VC_EDU_PLUGFEST_2022
    );
    pub static ref DID_CONFIGURATION_V0_0_CONTEXT_DOCUMENT: RemoteDocument = load_static_context(
        DID_CONFIGURATION_V0_0_CONTEXT,
        ssi_contexts::DID_CONFIGURATION_V0_0
    );
    pub static ref JFF_VC_EDU_PLUGFEST_2022_2_CONTEXT_DOCUMENT: RemoteDocument = load_static_context(
        JFF_VC_EDU_PLUGFEST_2022_2_CONTEXT,
        ssi_contexts::JFF_VC_EDU_PLUGFEST_2022_2
    );
}

macro_rules! iri_match {
    { match $input:ident { $($(#[$meta:meta])? $($id:ident)|* => $e:expr,)* _ as $default:ident => $de:expr } } => {
        match $input {
            $($(#[$meta])? $input if $($input == $id)||* => $e),*
            $default => $de
        }
    };
}

/// Error raised when an unknown context is loaded with [`StaticLoader`] or
/// [`ContextLoader`].
#[derive(thiserror::Error, Debug)]
#[error("Unknown context: {0}")]
pub struct UnknownContext(IriBuf);

#[derive(Clone)]
pub struct StaticLoader;

impl Loader<IriBuf, Span> for StaticLoader {
    type Output = json_syntax::Value<Span>;
    type Error = UnknownContext;

    fn load_with<'a>(
        &'a mut self,
        _vocabulary: &'a mut (impl Sync + Send + IriVocabularyMut<Iri = IriBuf>),
        url: IriBuf,
    ) -> BoxFuture<'a, json_ld::LoadingResult<IriBuf, Span, Self::Output, Self::Error>>
    where
        IriBuf: 'a,
    {
        async move {
            iri_match! {
                match url {
                    CREDENTIALS_V1_CONTEXT => Ok(CREDENTIALS_V1_CONTEXT_DOCUMENT.clone()),
                    CREDENTIALS_V2_CONTEXT => Ok(CREDENTIALS_V2_CONTEXT_DOCUMENT.clone()),
                    CREDENTIALS_EXAMPLES_V1_CONTEXT => {
                        Ok(CREDENTIALS_EXAMPLES_V1_CONTEXT_DOCUMENT.clone())
                    },
                    CREDENTIALS_EXAMPLES_V2_CONTEXT => {
                        Ok(CREDENTIALS_EXAMPLES_V2_CONTEXT_DOCUMENT.clone())
                    },
                    ODRL_CONTEXT => Ok(ODRL_CONTEXT_DOCUMENT.clone()),
                    SECURITY_V1_CONTEXT => Ok(SECURITY_V1_CONTEXT_DOCUMENT.clone()),
                    SECURITY_V2_CONTEXT => Ok(SECURITY_V2_CONTEXT_DOCUMENT.clone()),
                    SCHEMA_ORG_CONTEXT => Ok(SCHEMA_ORG_CONTEXT_DOCUMENT.clone()),
                    DID_V1_CONTEXT | DID_V1_CONTEXT_NO_WWW | W3ID_DID_V1_CONTEXT => {
                        Ok(DID_V1_CONTEXT_DOCUMENT.clone())
                    },
                    DID_RESOLUTION_V1_CONTEXT => Ok(DID_RESOLUTION_V1_CONTEXT_DOCUMENT.clone()),
                    #[allow(deprecated)]
                    DIF_ESRS2020_CONTEXT => Ok(DIF_ESRS2020_CONTEXT_DOCUMENT.clone()),
                    W3ID_ESRS2020_V2_CONTEXT => Ok(W3ID_ESRS2020_V2_CONTEXT_DOCUMENT.clone()),
                    #[allow(deprecated)]
                    ESRS2020_EXTRA_CONTEXT => Ok(ESRS2020_EXTRA_CONTEXT_DOCUMENT.clone()),
                    LDS_JWS2020_V1_CONTEXT => Ok(LDS_JWS2020_V1_CONTEXT_DOCUMENT.clone()),
                    W3ID_JWS2020_V1_CONTEXT => Ok(W3ID_JWS2020_V1_CONTEXT_DOCUMENT.clone()),
                    W3ID_ED2020_V1_CONTEXT => Ok(W3ID_ED2020_V1_CONTEXT_DOCUMENT.clone()),
                    W3ID_MULTIKEY_V1_CONTEXT => Ok(W3ID_MULTIKEY_V1_CONTEXT_DOCUMENT.clone()),
                    W3ID_DATA_INTEGRITY_V1_CONTEXT => Ok(W3ID_DATA_INTEGRITY_V1_CONTEXT_DOCUMENT.clone()),
                    BLOCKCHAIN2021_V1_CONTEXT => Ok(BLOCKCHAIN2021_V1_CONTEXT_DOCUMENT.clone()),
                    CITIZENSHIP_V1_CONTEXT => Ok(CITIZENSHIP_V1_CONTEXT_DOCUMENT.clone()),
                    VACCINATION_V1_CONTEXT => Ok(VACCINATION_V1_CONTEXT_DOCUMENT.clone()),
                    TRACEABILITY_CONTEXT => Ok(TRACEABILITY_CONTEXT_DOCUMENT.clone()),
                    REVOCATION_LIST_2020_V1_CONTEXT => {
                        Ok(REVOCATION_LIST_2020_V1_CONTEXT_DOCUMENT.clone())
                    },
                    STATUS_LIST_2021_V1_CONTEXT => Ok(STATUS_LIST_2021_V1_CONTEXT_DOCUMENT.clone()),
                    EIP712SIG_V0_1_CONTEXT => Ok(EIP712SIG_V0_1_CONTEXT_DOCUMENT.clone()),
                    BBS_V1_CONTEXT => Ok(BBS_V1_CONTEXT_DOCUMENT.clone()),
                    EIP712SIG_V1_CONTEXT => Ok(EIP712SIG_V1_CONTEXT_DOCUMENT.clone()),
                    PRESENTATION_SUBMISSION_V1_CONTEXT => {
                        Ok(PRESENTATION_SUBMISSION_V1_CONTEXT_DOCUMENT.clone())
                    },
                    VDL_V1_CONTEXT => Ok(VDL_V1_CONTEXT_DOCUMENT.clone()),
                    WALLET_V1_CONTEXT => Ok(WALLET_V1_CONTEXT_DOCUMENT.clone()),
                    ZCAP_V1_CONTEXT => Ok(ZCAP_V1_CONTEXT_DOCUMENT.clone()),
                    CACAO_ZCAP_V1_CONTEXT => Ok(CACAO_ZCAP_V1_CONTEXT_DOCUMENT.clone()),
                    JFF_VC_EDU_PLUGFEST_2022_CONTEXT => {
                        Ok(JFF_VC_EDU_PLUGFEST_2022_CONTEXT_DOCUMENT.clone())
                    },
                    DID_CONFIGURATION_V0_0_CONTEXT => {
                        Ok(DID_CONFIGURATION_V0_0_CONTEXT_DOCUMENT.clone())
                    },
                    JFF_VC_EDU_PLUGFEST_2022_2_CONTEXT => {
                        Ok(JFF_VC_EDU_PLUGFEST_2022_2_CONTEXT_DOCUMENT.clone())
                    },
                    _ as iri => Err(UnknownContext(iri))
                }
            }
        }
        .boxed()
    }
}

pub type ContextMap = HashMap<IriBuf, RemoteDocument>;

#[derive(Clone)]
pub struct ContextLoader {
    // Specifies if StaticLoader is meant to be checked first.
    static_loader: Option<StaticLoader>,
    // This map holds the optional, additional context objects.  This is where any app-specific context
    // objects would go.  The Arc<RwLock<_>> is necessary because json_ld::Loader trait unfortunately
    // has a method that uses `&mut self`.
    context_map: Option<Arc<RwLock<ContextMap>>>,
}

impl std::fmt::Debug for ContextLoader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.debug_struct("ContextLoader").finish_non_exhaustive()
    }
}

/// Error that can be raised by the [`ContextLoader::with_context_map_from`]
/// constructor function.
///
/// This error is raised either if some input document is not JSON, or if it is
/// bound to an invalid IRI.
#[derive(Debug, Error)]
pub enum FromContextMapError {
    #[error(transparent)]
    ParseError(#[from] Meta<json_ld::syntax::parse::Error<Span>, Span>),

    #[error("invalid IRI `{0}`: {1}")]
    InvalidIri(String, iref::Error),
}

impl From<(iref::Error, String)> for FromContextMapError {
    fn from((e, iri): (iref::Error, String)) -> Self {
        Self::InvalidIri(iri, e)
    }
}

impl ContextLoader {
    /// Constructs an "empty" ContextLoader.
    pub fn empty() -> Self {
        Self {
            static_loader: None,
            context_map: None,
        }
    }
    /// Using the builder pattern, the StaticLoader can be enabled so that contexts are checked
    /// against it before being checked against context_map.
    pub fn with_static_loader(mut self) -> Self {
        self.static_loader = Some(StaticLoader);
        self
    }
    /// Using the builder pattern, the map of additional contexts can be set.  These context objects
    /// will be checked after StaticLoader (if it's specified).  preparsed_context_map should map
    /// the context URLs to their JSON content.
    pub fn with_context_map_from(
        mut self,
        preparsed_context_map: HashMap<String, String>,
    ) -> Result<Self, FromContextMapError> {
        let context_map = preparsed_context_map
            .into_iter()
            .map(
                |(url, jsonld)| -> Result<(IriBuf, RemoteDocument), FromContextMapError> {
                    let doc = json_syntax::Value::parse_str(&jsonld, |span| span)?;
                    let iri = IriBuf::from_string(url)?;
                    let remote_doc = RemoteDocument::new(
                        Some(iri.clone()),
                        Some("application/ld+json".parse().unwrap()),
                        doc,
                    );
                    Ok((iri, remote_doc))
                },
            )
            .collect::<Result<HashMap<IriBuf, RemoteDocument>, FromContextMapError>>()?;
        self.context_map = Some(Arc::new(RwLock::new(context_map)));
        Ok(self)
    }
}

/// The default ContextLoader only uses StaticLoader.
impl std::default::Default for ContextLoader {
    fn default() -> Self {
        Self {
            static_loader: Some(StaticLoader),
            context_map: None,
        }
    }
}

impl Loader<IriBuf, Span> for ContextLoader {
    type Output = json_syntax::Value<Span>;
    type Error = UnknownContext;

    fn load_with<'a>(
        &'a mut self,
        _vocabulary: &'a mut (impl Sync + Send + IriVocabularyMut<Iri = IriBuf>),
        url: IriBuf,
    ) -> BoxFuture<'a, json_ld::LoadingResult<IriBuf, Span, Self::Output, Self::Error>>
    where
        IriBuf: 'a,
    {
        async move {
            let url = match &mut self.static_loader {
                Some(static_loader) => {
                    match static_loader.load(url).await {
                        Ok(x) => {
                            // The url was present in `StaticLoader`.
                            return Ok(x);
                        }
                        Err(UnknownContext(url)) => {
                            // This is ok, the url just wasn't found in
                            // `StaticLoader`. Fall through to
                            // `self.context_map`.
                            url
                        }
                    }
                }
                None => url,
            };

            // If we fell through, then try `self.context_map`.
            if let Some(context_map) = &mut self.context_map {
                context_map
                    .read()
                    .await
                    .get(&url)
                    .cloned()
                    .ok_or(UnknownContext(url))
            } else {
                Err(UnknownContext(url))
            }
        }
        .boxed()
    }
}

/// Remote JSON-LD context document.
pub type RemoteContext =
    json_ld::RemoteDocument<IriBuf, Span, json_ld::syntax::context::Value<Span>>;

/// Remote JSON-LD context document reference.
pub type RemoteContextReference =
    RemoteDocumentReference<IriBuf, Span, json_ld::syntax::context::Value<Span>>;

#[derive(Debug, thiserror::Error)]
pub enum ContextError {
    #[error("Invalid JSON: {0}")]
    InvalidJson(#[from] json_syntax::parse::MetaError<Span>),

    #[error("Invalid JSON-LD context: {0}")]
    InvalidContext(#[from] Meta<json_ld::syntax::context::InvalidContext, Span>),
}

/// Parse a JSON-LD context.
pub fn parse_ld_context(content: &str) -> Result<RemoteContextReference, ContextError> {
    let json = json_syntax::Value::parse_str(content, |span| span)?;
    let context = json_ld::syntax::context::Value::try_from_json(json)?;
    Ok(RemoteContextReference::Loaded(RemoteContext::new(
        None, None, context,
    )))
}

/// Converts the input JSON-LD document into an RDF dataset.
///
/// The input document will be expanded with the given `expand_context` with
/// the [`Strict`] expansion policy as required by the [VC HTTP API Test Suite].
///
/// [`Strict`]: json_ld::expansion::Policy::Strict
/// [VC HTTP API Test Suite]: https://github.com/w3c-ccg/vc-api-test-suite
pub async fn json_to_dataset<L>(
    json: json_ld::syntax::MetaValue<Span>,
    loader: &mut L,
    expand_context: Option<RemoteContextReference>,
) -> Result<rdf::DataSet, Box<ToRdfError<L::Error, L::ContextError>>>
where
    L: json_ld::Loader<IriBuf, Span> + json_ld::ContextLoader<IriBuf, Span> + Send + Sync,
    L::Output: Into<json_ld::syntax::Value<Span>>,
    L::Error: Send,
    L::Context: Into<json_ld::syntax::context::Value<Span>>,
    L::ContextError: Send,
{
    use json_ld::JsonLdProcessor;

    let options = Options {
        expand_context,
        // VC HTTP API Test Suite expect properties to not be silently dropped.
        // More info: https://github.com/timothee-haudebourg/json-ld/issues/13
        expansion_policy: json_ld::expansion::Policy::Strict,
        ..Default::default()
    };

    let doc = json_ld::RemoteDocument::new(None, None, json);
    let mut generator =
        rdf_types::generator::Blank::new_with_prefix("b".to_string()).with_default_metadata();
    let mut to_rdf = doc
        .to_rdf_using(&mut generator, loader, options)
        .await
        .map_err(Box::new)?;
    Ok(to_rdf
        .cloned_quads()
        .map(|q| {
            // Since `produce_generalized_rdf` is set to `false`, it is guaranteed
            // each predicate is an IRI.
            q.map_predicate(|p| p.into_iri().unwrap())
        })
        .collect())
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use super::*;

    #[tokio::test]
    async fn context_loader() {
        let mut cl = ContextLoader::default().with_context_map_from([(
            "https://w3id.org/age/v1".to_string(),
            serde_json::to_string(&json!({
              "@context": {
                "@protected": "true",
                "id": "@id",
                "type": "@type",
                "description": "https://schema.org/description",
                "image": {
                  "@id": "https://schema.org/image",
                  "@type": "@id"
                },
                "name": "https://schema.org/name",
                "overAge": {
                  "@id": "https://w3id.org/age#overAge",
                  "@type": "http://www.w3.org/2001/XMLSchema#positiveInteger"
                },
                "concealedIdToken": {
                  "@id": "https://w3id.org/cit#concealedIdToken",
                  "@type": "https://w3id.org/security#multibase"
                },
                "anchoredResource": {
                  "@type": "@id",
                  "@id": "https://w3id.org/security#anchoredResource"
                },
                "digestMultibase": {
                  "@id": "https://w3id.org/security#digestMultibase",
                  "@type": "https://w3id.org/security#multibase"
                },
                "PersonalPhotoCredential": "https://convenience.org/vocab#PersonalPhotoCredential",
                "OverAgeTokenCredential": "https://w3id.org/age#OverAgeTokenCredential",
                "VerifiableCredentialRefreshService2021": {
                  "@id": "https://w3id.org/vc-refresh-service#VerifiableCredentialRefreshService2021",
                  "@context": {
                    "@protected": true,
                    "url": {
                      "@id": "https://schema.org/url",
                      "@type": "@id"
                    },
                    "refreshToken": {
                      "@id": "https://w3id.org/vc-refresh-service#refreshToken",
                      "@type": "https://w3id.org/security#multibase"
                    }
                  }
                },
                "AgeVerificationCredential": "https://w3id.org/age#AgeVerificationCredential",
                "AgeVerificationContainerCredential": "https://w3id.org/age#AgeVerificationContainerCredential"
              }
            })).unwrap())]
            .iter()
                .cloned()
                .collect(),
                ).unwrap() ;
        cl.load_with(&mut (), IriBuf::new("https://w3id.org/age/v1").unwrap())
            .await
            .unwrap();
    }
}
