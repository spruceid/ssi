use std::{borrow::Cow, collections::HashMap, hash::Hash};

use iref::UriBuf;
use rdf_types::{Interpretation, VocabularyMut};
use serde::{Deserialize, Serialize};
use ssi_claims_core::{
    ClaimsValidity, DateTimeProvider, Eip712TypesLoaderProvider, ResolverProvider, ValidateClaims,
};
use ssi_data_integrity::{
    ssi_rdf::{LdEnvironment, LinkedDataResource, LinkedDataSubject},
    AnySuite,
};
use ssi_json_ld::{
    CompactJsonLd, Expandable, JsonLdError, JsonLdLoaderProvider, JsonLdNodeObject, JsonLdObject,
    Loader,
};
use ssi_jwk::JWKResolver;
use ssi_jws::{InvalidJws, JwsSlice, ValidateJwsHeader};
use ssi_vc::v2::{syntax::JsonCredentialTypes, Context};
use ssi_verification_methods::{ssi_core::OneOrMany, AnyMethod, VerificationMethodResolver};

use crate::{
    bitstring_status_list::FromBytesError, FromBytes, FromBytesOptions, StatusMapEntrySet,
};

use super::BitstringStatusListEntry;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BitstringStatusListEntrySetCredential {
    /// JSON-LD context.
    #[serde(rename = "@context")]
    pub context: Context,

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
    fn json_ld_context(&self) -> Option<Cow<ssi_json_ld::syntax::Context>> {
        Some(Cow::Borrowed(self.context.as_ref()))
    }
}

impl JsonLdNodeObject for BitstringStatusListEntrySetCredential {
    fn json_ld_type(&self) -> ssi_json_ld::JsonLdTypes {
        self.types.to_json_ld_types()
    }
}

impl Expandable for BitstringStatusListEntrySetCredential {
    type Error = JsonLdError;
    type Expanded<I, V> = ssi_json_ld::ExpandedDocument<V::Iri, V::BlankId>
    where
        I: Interpretation,
        V: VocabularyMut,
        V::Iri: LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
        V::BlankId: LinkedDataResource<I, V> + LinkedDataSubject<I, V>;

    async fn expand_with<I, V>(
        &self,
        ld: &mut LdEnvironment<V, I>,
        loader: &impl Loader,
    ) -> Result<Self::Expanded<I, V>, Self::Error>
    where
        I: Interpretation,
        V: VocabularyMut,
        V::Iri: Clone + Eq + Hash + LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
        V::BlankId: Clone + Eq + Hash + LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
    {
        CompactJsonLd(ssi_json_ld::syntax::to_value(self).unwrap())
            .expand_with(ld, loader)
            .await
    }
}

impl<E, P> ValidateClaims<E, P> for BitstringStatusListEntrySetCredential {
    fn validate_claims(&self, _env: &E, _proof: &P) -> ClaimsValidity {
        // TODO use `ssi`'s own VC DM v2.0 validation function once it's implemented.
        Ok(())
    }
}

impl<E> ValidateJwsHeader<E> for BitstringStatusListEntrySetCredential {
    fn validate_jws_header(&self, _env: &E, _header: &ssi_jws::Header) -> ClaimsValidity {
        Ok(())
    }
}

impl<V> FromBytes<V> for BitstringStatusListEntrySetCredential
where
    V: ResolverProvider + DateTimeProvider + JsonLdLoaderProvider + Eip712TypesLoaderProvider,
    V::Resolver: JWKResolver + VerificationMethodResolver<Method = AnyMethod>,
{
    type Error = FromBytesError;

    async fn from_bytes_with(
        bytes: &[u8],
        media_type: &str,
        params: &V,
        options: FromBytesOptions,
    ) -> Result<Self, Self::Error> {
        match media_type {
            "application/vc+ld+json+jwt" => {
                let jws = JwsSlice::new(bytes)
                    .map_err(InvalidJws::into_owned)?
                    .decode()?
                    .try_map::<Self, _>(|bytes| serde_json::from_slice(&bytes))?;
                jws.verify(params).await??;
                Ok(jws.signing_bytes.payload)
            }
            // "application/vc+ld+json+sd-jwt" => {
            //     todo!()
            // }
            // "application/vc+ld+json+cose" => {
            //     todo!()
            // }
            "application/vc+ld+json" => {
                let vc = ssi_data_integrity::from_json_slice::<Self, AnySuite>(bytes)?;

                if !options.allow_unsecured || !vc.proofs.is_empty() {
                    vc.verify(params).await??;
                }

                Ok(vc.claims)
            }
            other => Err(FromBytesError::UnexpectedMediaType(other.to_owned())),
        }
    }
}
