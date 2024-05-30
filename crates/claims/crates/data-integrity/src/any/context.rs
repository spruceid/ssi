use rdf_types::{
    generator,
    interpretation::{self, WithGenerator},
    vocabulary::IriVocabulary,
};
use ssi_json_ld::{AnyJsonLdEnvironment, ContextLoader, JsonLdEnvironment};
use ssi_rdf::{AnyLdEnvironment, LdEnvironment};

/// Input environment for any cryptographic suite supported by `AnySuite` with
/// a given JSON-LD context loader and sensible defaults for the vocabulary,
/// interpretation and EIP712 type loader.
pub type AnyEnvironmentWithLdLoader<L = ContextLoader> =
    AnyInputContext<JsonLdEnvironment<(), WithGenerator<generator::Blank>, L>>;

/// Input context for any cryptographic suite supported by `AnySuite`.
pub struct AnyInputContext<E = JsonLdEnvironment, L = ()> {
    /// The Linked-Data context used to interpret RDF terms.
    pub ld: E,

    /// Remote resources loader.
    ///
    /// Used for instance with the `EthereumEip712Signature2021` suite to load
    /// EIP712 type definitions from the URI given in the proof options.
    pub loader: L,
}

impl<E, L> AnyInputContext<E, L> {
    pub fn new(ld: E, loader: L) -> Self {
        Self { ld, loader }
    }
}

impl<L> AnyInputContext<JsonLdEnvironment<(), WithGenerator<generator::Blank>, L>> {
    pub fn from_ld_context_loader(loader: L) -> Self {
        Self {
            ld: JsonLdEnvironment::from_loader(loader),
            loader: (),
        }
    }
}

impl<E: AnyLdEnvironment, L> AnyLdEnvironment for AnyInputContext<E, L> {
    type Vocabulary = E::Vocabulary;
    type Interpretation = E::Interpretation;

    fn as_ld_environment_mut(
        &mut self,
    ) -> LdEnvironment<&mut Self::Vocabulary, &mut Self::Interpretation> {
        self.ld.as_ld_environment_mut()
    }
}

impl<E: AnyJsonLdEnvironment, L> AnyJsonLdEnvironment for AnyInputContext<E, L>
where
    E::Vocabulary: IriVocabulary,
{
    type Loader = E::Loader;

    fn as_json_ld_environment_mut(
        &mut self,
    ) -> ssi_json_ld::JsonLdEnvironment<
        &mut Self::Vocabulary,
        &mut Self::Interpretation,
        &mut Self::Loader,
    > {
        self.ld.as_json_ld_environment_mut()
    }
}

impl<E, L: ssi_data_integrity_suites::eip712::TypesProvider>
    ssi_data_integrity_suites::eip712::TypesProvider for AnyInputContext<E, L>
{
    async fn fetch_types(
        &self,
        uri: &iref::Uri,
    ) -> Result<ssi_eip712::Types, ssi_data_integrity_suites::eip712::TypesFetchError> {
        self.loader.fetch_types(uri).await
    }
}

impl<E> AnyInputContext<E> {
    pub fn from_environment(ld: E) -> Self {
        Self { ld, loader: () }
    }
}

impl<I, V> From<LdEnvironment<V, I>> for AnyInputContext<LdEnvironment<V, I>> {
    fn from(value: LdEnvironment<V, I>) -> Self {
        AnyInputContext {
            ld: value,
            loader: (),
        }
    }
}

impl Default
    for AnyInputContext<
        JsonLdEnvironment<(), interpretation::WithGenerator<rdf_types::generator::Blank>>,
        (),
    >
{
    fn default() -> Self {
        Self {
            ld: JsonLdEnvironment {
                vocabulary: (),
                interpretation: interpretation::WithGenerator::new(
                    (),
                    rdf_types::generator::Blank::new(),
                ),
                loader: ContextLoader::default(),
            },
            loader: (),
        }
    }
}
