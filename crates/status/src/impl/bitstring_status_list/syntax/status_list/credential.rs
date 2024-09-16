use std::{borrow::Cow, collections::HashMap, hash::Hash, io};

use iref::UriBuf;
use rdf_types::{Interpretation, Vocabulary, VocabularyMut};
use serde::{Deserialize, Serialize};
use ssi_claims_core::{
    ClaimsValidity, DateTimeProvider, Eip712TypesLoaderProvider, InvalidClaims, ResolverProvider,
    ValidateClaims,
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
use ssi_vc::{
    syntax::RequiredType,
    v2::syntax::{Context, JsonCredentialTypes},
};
use ssi_verification_methods::{AnyMethod, VerificationMethodResolver};

use crate::{EncodedStatusMap, FromBytes, FromBytesOptions};

use super::{BitstringStatusList, StatusList};

pub const BITSTRING_STATUS_LIST_CREDENTIAL_TYPE: &str = "BitstringStatusListCredential";

#[derive(Debug, Clone, Copy)]
pub struct BitstringStatusListCredentialType;

impl RequiredType for BitstringStatusListCredentialType {
    const REQUIRED_TYPE: &'static str = BITSTRING_STATUS_LIST_CREDENTIAL_TYPE;
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BitstringStatusListCredential {
    /// JSON-LD context.
    #[serde(rename = "@context")]
    pub context: Context,

    /// Credential identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<UriBuf>,

    /// Credential type.
    #[serde(rename = "type")]
    pub types: JsonCredentialTypes<BitstringStatusListCredentialType>,

    /// Valid from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<xsd_types::DateTimeStamp>,

    /// Valid until.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<xsd_types::DateTimeStamp>,

    /// Status list.
    pub credential_subject: BitstringStatusList,

    /// Other properties.
    #[serde(flatten)]
    pub other_properties: HashMap<String, serde_json::Value>,
}

impl BitstringStatusListCredential {
    pub fn new(id: Option<UriBuf>, credential_subject: BitstringStatusList) -> Self {
        Self {
            context: Context::default(),
            id,
            types: JsonCredentialTypes::default(),
            valid_from: None,
            valid_until: None,
            credential_subject,
            other_properties: HashMap::default(),
        }
    }

    pub fn decode_status_list(&self) -> Result<StatusList, DecodeError> {
        self.credential_subject.decode()
    }
}

impl JsonLdObject for BitstringStatusListCredential {
    fn json_ld_context(&self) -> Option<Cow<ssi_json_ld::syntax::Context>> {
        Some(Cow::Borrowed(self.context.as_ref()))
    }
}

impl JsonLdNodeObject for BitstringStatusListCredential {
    fn json_ld_type(&self) -> ssi_json_ld::JsonLdTypes {
        self.types.to_json_ld_types()
    }
}

impl Expandable for BitstringStatusListCredential {
    type Error = JsonLdError;

    type Expanded<I: Interpretation, V: Vocabulary> = ssi_json_ld::ExpandedDocument<V::Iri, V::BlankId>
    where
        I: Interpretation,
        V: VocabularyMut,
        V::Iri: LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
        V::BlankId: LinkedDataResource<I, V> + LinkedDataSubject<I, V>;

    #[allow(async_fn_in_trait)]
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

impl<E, P> ValidateClaims<E, P> for BitstringStatusListCredential
where
    E: DateTimeProvider,
{
    fn validate_claims(&self, env: &E, _proof: &P) -> ClaimsValidity {
        // TODO use `ssi`'s own VC DM v2.0 validation function once it's implemented.
        let now = env.date_time();

        if let Some(valid_from) = self.valid_from {
            if now < valid_from {
                return Err(InvalidClaims::Premature {
                    now,
                    valid_from: valid_from.into(),
                });
            }
        }

        if let Some(valid_until) = self.valid_until {
            if now > valid_until {
                return Err(InvalidClaims::Expired {
                    now,
                    valid_until: valid_until.into(),
                });
            }
        }

        Ok(())
    }
}

impl<E> ValidateJwsHeader<E> for BitstringStatusListCredential {
    fn validate_jws_header(&self, _env: &E, _header: &ssi_jws::Header) -> ClaimsValidity {
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("invalid multibase: {0}")]
    Multibase(#[from] multibase::Error),

    #[error("GZIP error: {0}")]
    Gzip(io::Error),
}

impl EncodedStatusMap for BitstringStatusListCredential {
    type Decoded = StatusList;
    type DecodeError = DecodeError;

    fn decode(self) -> Result<Self::Decoded, Self::DecodeError> {
        self.decode_status_list()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FromBytesError {
    #[error("unexpected media type `{0}`")]
    UnexpectedMediaType(String),

    #[error(transparent)]
    Jws(#[from] InvalidJws<Vec<u8>>),

    #[error("invalid JWS: {0}")]
    JWS(#[from] ssi_jws::DecodeError),

    #[error(transparent)]
    DataIntegrity(#[from] ssi_data_integrity::DecodeError),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error("proof preparation failed: {0}")]
    Preparation(#[from] ssi_claims_core::ProofPreparationError),

    #[error("proof validation failed: {0}")]
    Verification(#[from] ssi_claims_core::ProofValidationError),

    #[error("rejected claims: {0}")]
    Rejected(#[from] ssi_claims_core::Invalid),
}

impl<V> FromBytes<V> for BitstringStatusListCredential
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
