use std::{borrow::Cow, collections::HashMap, hash::Hash};

use iref::UriBuf;
use rdf_types::VocabularyMut;
use serde::{Deserialize, Serialize};
use ssi_claims_core::{ClaimsValidity, Proof, Validate, ValidateProof, Verifiable};
use ssi_data_integrity::{ssi_rdf::Expandable, AnyInputContext, AnyProofs};
use ssi_json_ld::{
    AnyJsonLdEnvironment, CompactJsonLd, JsonLdError, JsonLdNodeObject, JsonLdObject,
};
use ssi_jws::{CompactJWS, InvalidCompactJWS, JWSVerifier};
use ssi_vc::{json::JsonCredentialTypes, Context, V2};
use ssi_verification_methods::ssi_core::OneOrMany;

use crate::{
    bitstream_status_list::FromBytesError, FromBytes, FromBytesOptions, StatusMapEntrySet,
};

use super::BitstringStatusListEntry;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BitstringStatusListEntrySetCredential {
    /// JSON-LD context.
    #[serde(rename = "@context")]
    pub context: Context<V2>,

    /// Credential identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<UriBuf>,

    /// Credential type.
    #[serde(rename = "type")]
    pub types: JsonCredentialTypes,

    pub credential_status: OneOrMany<BitstringStatusListEntry>,

    #[serde(flatten)]
    pub other_properties: HashMap<String, serde_json::Value>,
}

impl StatusMapEntrySet for BitstringStatusListEntrySetCredential {
    type Entry<'a> = &'a BitstringStatusListEntry where Self: 'a;

    fn get_entry(&self, purpose: crate::StatusPurpose<&str>) -> Option<Self::Entry<'_>> {
        (&self.credential_status)
            .into_iter()
            .find(|&entry| entry.status_purpose == purpose)
    }
}

impl JsonLdObject for BitstringStatusListEntrySetCredential {
    fn json_ld_context(&self) -> Option<Cow<json_ld::syntax::Context>> {
        Some(Cow::Borrowed(self.context.as_ref()))
    }
}

impl JsonLdNodeObject for BitstringStatusListEntrySetCredential {
    fn json_ld_type(&self) -> ssi_json_ld::JsonLdTypes {
        self.types.to_json_ld_types()
    }
}

impl<V, E, L> Expandable<E> for BitstringStatusListEntrySetCredential
where
    E: AnyJsonLdEnvironment<Vocabulary = V, Loader = L>,
    V: VocabularyMut,
    V::Iri: Clone + Eq + Hash,
    V::BlankId: Clone + Eq + Hash,
    L: json_ld::Loader<V::Iri>,
    L::Error: std::fmt::Display,
{
    type Error = JsonLdError<L::Error>;
    type Expanded = json_ld::ExpandedDocument<V::Iri, V::BlankId>;

    async fn expand(&self, environment: &mut E) -> Result<Self::Expanded, Self::Error> {
        CompactJsonLd(json_syntax::to_value(self).unwrap())
            .expand(environment)
            .await
    }
}

impl<E, P: Proof> Validate<E, P> for BitstringStatusListEntrySetCredential {
    fn validate(&self, _env: &E, _proof: &P::Prepared) -> ClaimsValidity {
        // TODO use `ssi`'s own VC DM v2.0 validation function once it's implemented.
        Ok(())
    }
}

impl<V> FromBytes<V> for BitstringStatusListEntrySetCredential
where
    V: JWSVerifier,
    <AnyProofs as Proof>::Prepared: ValidateProof<Self, V>,
{
    type Error = FromBytesError;

    async fn from_bytes_with(
        bytes: &[u8],
        media_type: &str,
        verifier: &V,
        options: FromBytesOptions,
    ) -> Result<Self, Self::Error> {
        match media_type {
            "application/vc+ld+json+jwt" => {
                use ssi_claims_core::VerifiableClaims;
                let jws = CompactJWS::new(bytes)
                    .map_err(InvalidCompactJWS::into_owned)?
                    .to_decoded()?
                    .try_map::<Self, _>(|bytes| serde_json::from_slice(&bytes))?
                    .into_verifiable()
                    .await?;
                jws.verify(verifier).await??;
                Ok(jws.into_parts().0.payload)
            }
            "application/vc+ld+json+sd-jwt" => {
                todo!()
            }
            "application/vc+ld+json+cose" => {
                todo!()
            }
            "application/vc+ld+json" => {
                let vc: Verifiable<Self, AnyProofs> =
                    ssi_data_integrity::from_json_slice(bytes, AnyInputContext::default()).await?;

                if !options.allow_unsecured || !vc.proof.is_empty() {
                    vc.verify(verifier).await??;
                }

                Ok(vc.into_parts().0)
            }
            other => Err(FromBytesError::UnexpectedMediaType(other.to_owned())),
        }
    }
}
