use super::JoseDecodeError;
use serde::{de::DeserializeOwned, Serialize};
use ssi_claims_core::{ClaimsValidity, DateTimeProvider, SignatureError, ValidateClaims};
use ssi_json_ld::{iref::Uri, syntax::Context};
use ssi_jws::{CompactJWS, DecodedJWS, JWSPayload, JWSSigner};
use ssi_vc::{
    enveloped::EnvelopedVerifiableCredential,
    v2::{Credential, CredentialTypes, JsonCredential},
    MaybeIdentified,
};
use std::borrow::Cow;
use xsd_types::DateTimeStamp;

/// Payload of a JWS-secured Verifiable Credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct JoseVc<T = JsonCredential>(pub T);

impl<T: Serialize> JoseVc<T> {
    /// Sign a JOSE VC into an enveloped verifiable credential.
    pub async fn sign_into_enveloped(
        &self,
        signer: &impl JWSSigner,
    ) -> Result<EnvelopedVerifiableCredential, SignatureError> {
        let jws = JWSPayload::sign(self, signer).await?;
        Ok(EnvelopedVerifiableCredential {
            context: Context::iri_ref(ssi_vc::v2::CREDENTIALS_V2_CONTEXT_IRI.to_owned().into()),
            id: format!("data:application/vc-ld+jwt;{jws}").parse().unwrap(),
        })
    }
}

impl<T: DeserializeOwned> JoseVc<T> {
    /// Decode a JOSE VC.
    pub fn decode(jws: &CompactJWS) -> Result<DecodedJWS<Self>, JoseDecodeError> {
        jws.to_decoded()?
            .try_map(|payload| serde_json::from_slice(&payload).map(Self))
            .map_err(Into::into)
    }
}

impl JoseVc {
    /// Decode a JOSE VC with an arbitrary credential type.
    pub fn decode_any(jws: &CompactJWS) -> Result<DecodedJWS<Self>, JoseDecodeError> {
        Self::decode(jws)
    }
}

impl<T: Serialize> JWSPayload for JoseVc<T> {
    fn typ(&self) -> Option<&str> {
        Some("vc-ld+jwt")
    }

    fn cty(&self) -> Option<&str> {
        Some("vc")
    }

    fn payload_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(serde_json::to_vec(&self.0).unwrap())
    }
}

impl<T: MaybeIdentified> MaybeIdentified for JoseVc<T> {
    fn id(&self) -> Option<&Uri> {
        self.0.id()
    }
}

impl<T: Credential> Credential for JoseVc<T> {
    type Description = T::Description;
    type Subject = T::Subject;
    type Issuer = T::Issuer;
    type Status = T::Status;
    type Schema = T::Schema;
    type RelatedResource = T::RelatedResource;
    type RefreshService = T::RefreshService;
    type TermsOfUse = T::TermsOfUse;
    type Evidence = T::Evidence;

    fn id(&self) -> Option<&Uri> {
        Credential::id(&self.0)
    }

    fn additional_types(&self) -> &[String] {
        self.0.additional_types()
    }

    fn types(&self) -> CredentialTypes {
        self.0.types()
    }

    fn name(&self) -> Option<&str> {
        self.0.name()
    }

    fn description(&self) -> Option<&Self::Description> {
        self.0.description()
    }

    fn credential_subjects(&self) -> &[Self::Subject] {
        self.0.credential_subjects()
    }

    fn issuer(&self) -> &Self::Issuer {
        self.0.issuer()
    }

    fn valid_from(&self) -> Option<DateTimeStamp> {
        self.0.valid_from()
    }

    fn valid_until(&self) -> Option<DateTimeStamp> {
        self.0.valid_until()
    }

    fn credential_status(&self) -> &[Self::Status] {
        self.0.credential_status()
    }

    fn credential_schemas(&self) -> &[Self::Schema] {
        self.0.credential_schemas()
    }

    fn related_resources(&self) -> &[Self::RelatedResource] {
        self.0.related_resources()
    }

    fn refresh_services(&self) -> &[Self::RefreshService] {
        self.0.refresh_services()
    }

    fn terms_of_use(&self) -> &[Self::TermsOfUse] {
        self.0.terms_of_use()
    }

    fn evidence(&self) -> &[Self::Evidence] {
        self.0.evidence()
    }

    fn validate_credential<E>(&self, env: &E) -> ClaimsValidity
    where
        E: DateTimeProvider,
    {
        self.0.validate_credential(env)
    }
}

impl<E, P, T: ValidateClaims<E, P>> ValidateClaims<E, P> for JoseVc<T> {
    fn validate_claims(&self, environment: &E, proof: &P) -> ClaimsValidity {
        self.0.validate_claims(environment, proof)
    }
}
