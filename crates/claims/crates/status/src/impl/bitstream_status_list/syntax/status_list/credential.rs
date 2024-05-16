use std::{borrow::Cow, collections::HashMap, hash::Hash, io};

use iref::UriBuf;
use rdf_types::VocabularyMut;
use serde::{Deserialize, Serialize};
use ssi_claims_core::{
    ClaimsValidity, DateTimeEnvironment, InvalidClaims, Proof, Validate, ValidateProof, Verifiable,
};
use ssi_data_integrity::{ssi_rdf::Expandable, AnyInputContext, AnyProofs};
use ssi_json_ld::{
    AnyJsonLdEnvironment, CompactJsonLd, JsonLdError, JsonLdNodeObject, JsonLdObject,
};
use ssi_jws::{CompactJWS, InvalidCompactJWS, JWSVerifier};
use ssi_vc::{
    json::{JsonCredentialTypes, RequiredCredentialType},
    Context, V2,
};

use crate::{EncodedStatusMap, FromBytes, FromBytesOptions};

use super::{BitstringStatusList, StatusList};

pub const BITSTRING_STATUS_LIST_CREDENTIAL_TYPE: &str = "BitstringStatusListCredential";

#[derive(Debug, Clone, Copy)]
pub struct BitstringStatusListCredentialType;

impl RequiredCredentialType for BitstringStatusListCredentialType {
    const REQUIRED_CREDENTIAL_TYPE: &'static str = BITSTRING_STATUS_LIST_CREDENTIAL_TYPE;
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BitstringStatusListCredential {
    /// JSON-LD context.
    #[serde(rename = "@context")]
    pub context: Context<V2>,

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
    fn json_ld_context(&self) -> Option<Cow<json_ld::syntax::Context>> {
        Some(Cow::Borrowed(self.context.as_ref()))
    }
}

impl JsonLdNodeObject for BitstringStatusListCredential {
    fn json_ld_type(&self) -> ssi_json_ld::JsonLdTypes {
        self.types.to_json_ld_types()
    }
}

impl<V, E, L> Expandable<E> for BitstringStatusListCredential
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

impl<E, P: Proof> Validate<E, P> for BitstringStatusListCredential
where
    E: DateTimeEnvironment,
{
    fn validate(&self, env: &E, _proof: &P::Prepared) -> ClaimsValidity {
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
    CompactJWS(#[from] InvalidCompactJWS<Vec<u8>>),

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
