use super::JoseDecodeError;
use serde::{de::DeserializeOwned, Serialize};
use ssi_claims_core::SignatureError;
use ssi_json_ld::{iref::Uri, syntax::Context};
use ssi_jws::{CompactJWS, DecodedJWS, JWSPayload, JWSSigner};
use ssi_vc::{
    enveloped::EnvelopedVerifiablePresentation,
    v2::{syntax::JsonPresentation, Presentation, PresentationTypes},
    MaybeIdentified,
};
use std::borrow::Cow;

/// Payload of a JWS-secured Verifiable Presentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct JoseVp<T = JsonPresentation>(pub T);

impl<T: Serialize> JWSPayload for JoseVp<T> {
    fn typ(&self) -> Option<&str> {
        Some("vp-ld+jwt")
    }

    fn cty(&self) -> Option<&str> {
        Some("vp")
    }

    fn payload_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(serde_json::to_vec(&self.0).unwrap())
    }
}

impl<T: Serialize> JoseVp<T> {
    /// Sign a JOSE VC into an enveloped verifiable presentation.
    pub async fn sign_into_enveloped(
        &self,
        signer: &impl JWSSigner,
    ) -> Result<EnvelopedVerifiablePresentation, SignatureError> {
        let jws = JWSPayload::sign(self, signer).await?;
        Ok(EnvelopedVerifiablePresentation {
            context: Context::iri_ref(ssi_vc::v2::CREDENTIALS_V2_CONTEXT_IRI.to_owned().into()),
            id: format!("data:application/vp-ld+jwt;{jws}").parse().unwrap(),
        })
    }
}

impl<T: DeserializeOwned> JoseVp<T> {
    /// Decode a JOSE VP.
    pub fn decode(jws: &CompactJWS) -> Result<DecodedJWS<Self>, JoseDecodeError> {
        jws.to_decoded()?
            .try_map(|payload| serde_json::from_slice(&payload).map(Self))
            .map_err(Into::into)
    }
}

impl JoseVp {
    /// Decode a JOSE VP with an arbitrary presentation type.
    pub fn decode_any(jws: &CompactJWS) -> Result<DecodedJWS<Self>, JoseDecodeError> {
        Self::decode(jws)
    }
}

impl<T: MaybeIdentified> MaybeIdentified for JoseVp<T> {
    fn id(&self) -> Option<&ssi_json_ld::iref::Uri> {
        self.0.id()
    }
}

impl<T: Presentation> Presentation for JoseVp<T> {
    type Credential = T::Credential;
    type Holder = T::Holder;

    fn id(&self) -> Option<&Uri> {
        Presentation::id(&self.0)
    }

    fn additional_types(&self) -> &[String] {
        self.0.additional_types()
    }

    fn types(&self) -> PresentationTypes {
        self.0.types()
    }

    fn verifiable_credentials(&self) -> &[Self::Credential] {
        self.0.verifiable_credentials()
    }

    fn holders(&self) -> &[Self::Holder] {
        self.0.holders()
    }
}
