use std::borrow::Cow;

use serde::Serialize;
use ssi_crypto::{Error, HashFunction, Options};
use ssi_json_ld::{
    CompactJsonLd, Expandable, JsonLdContextLoader, JsonLdError, JsonLdNodeObject, JsonLdObject,
};
use ssi_rdf::{AnyLdEnvironment, LdEnvironment};

use crate::{CryptographicSuite, ProofRef};

pub async fn canonicalize_json_ld_claims_and_configuration<T, S>(
    claims: &T,
    configuration: ProofRef<'_, S>,
    params: &Options,
) -> Result<CanonicalClaimsAndConfiguration, Error>
where
    T: JsonLdNodeObject + Expandable,
    S: CryptographicSuite,
{
    let mut ld = LdEnvironment::default();

    let context_loader = params.get_or_default::<JsonLdContextLoader>();

    let expanded_claims = claims
        .expand_with(&mut ld, context_loader.as_ref())
        .await
        .map_err(Error::malformed_input)?;

    let contextualized_configuration = ContextualizedProof {
        context: claims.json_ld_context(),
        r#type: claims.json_ld_type(),
        proof: configuration,
    };

    let expanded_contextualized_configuration = contextualized_configuration
        .expand_with(&mut ld, context_loader.as_ref())
        .await
        .map_err(Error::malformed_input)?;

    Ok(CanonicalClaimsAndConfiguration {
        claims: ld
            .canonical_form_of(&expanded_claims)
            .map_err(Error::internal)?,
        configuration: ld
            .canonical_form_of(&expanded_contextualized_configuration)
            .map_err(Error::internal)?,
    })
}

pub struct CanonicalClaimsAndConfiguration {
    pub claims: Vec<String>,
    pub configuration: Vec<String>,
}

impl CanonicalClaimsAndConfiguration {
    pub fn hash(self, f: HashFunction) -> Box<[u8]> {
        let mut proof_configuration_hash = self
            .configuration
            .iter()
            .fold(f.begin(), |h, line| h.chain_update(line.as_bytes()))
            .end()
            .into_vec();

        let claims_hash = self
            .claims
            .iter()
            .fold(f.begin(), |h, line| h.chain_update(line.as_bytes()))
            .end();

        proof_configuration_hash.extend_from_slice(&claims_hash);
        proof_configuration_hash.into_boxed_slice()
    }
}

#[derive(Serialize)]
#[serde(bound(serialize = "S: CryptographicSuite"))]
struct ContextualizedProof<'a, S> {
    /// Proof context.
    #[serde(rename = "@context", default, skip_serializing_if = "Option::is_none")]
    context: Option<Cow<'a, ssi_json_ld::syntax::Context>>,

    #[serde(rename = "type")]
    r#type: ssi_json_ld::JsonLdTypes<'a>,

    proof: ProofRef<'a, S>,
}

impl<'a, S> JsonLdObject for ContextualizedProof<'a, S> {
    fn json_ld_context(&self) -> Option<std::borrow::Cow<ssi_json_ld::json_ld::syntax::Context>> {
        self.context.as_ref().map(|c| Cow::Borrowed(c.as_ref()))
    }
}

impl<'a, S> JsonLdNodeObject for ContextualizedProof<'a, S> {
    fn json_ld_type(&self) -> ssi_json_ld::JsonLdTypes {
        self.r#type.reborrow()
    }
}

impl<'a, S: CryptographicSuite> Expandable for ContextualizedProof<'a, S> {
    type Error = JsonLdError;
    type Expanded<I, V>
        = ssi_json_ld::ExpandedDocument<V::Iri, V::BlankId>
    where
        I: ssi_rdf::Interpretation,
        V: ssi_rdf::VocabularyMut,
        V::Iri: linked_data::LinkedDataResource<I, V> + linked_data::LinkedDataSubject<I, V>,
        V::BlankId: linked_data::LinkedDataResource<I, V> + linked_data::LinkedDataSubject<I, V>;

    async fn expand_with<I, V>(
        &self,
        ld: &mut LdEnvironment<V, I>,
        loader: &impl ssi_json_ld::Loader,
    ) -> Result<Self::Expanded<I, V>, Self::Error>
    where
        I: ssi_rdf::Interpretation,
        V: ssi_rdf::VocabularyMut,
        V::Iri: Clone
            + Eq
            + std::hash::Hash
            + ssi_rdf::LinkedDataResource<I, V>
            + ssi_rdf::LinkedDataSubject<I, V>,
        V::BlankId: Clone
            + Eq
            + std::hash::Hash
            + ssi_rdf::LinkedDataResource<I, V>
            + ssi_rdf::LinkedDataSubject<I, V>,
    {
        CompactJsonLd(json_syntax::to_value(self).unwrap())
            .expand_with(ld, loader)
            .await
    }
}
