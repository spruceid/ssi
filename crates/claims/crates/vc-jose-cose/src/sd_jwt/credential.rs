use std::borrow::Borrow;

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use ssi_claims_core::{ClaimsValidity, DateTimeProvider, SignatureError, ValidateClaims};
use ssi_json_ld::{iref::Uri, syntax::Context};
use ssi_jws::JwsSigner;
use ssi_jwt::{ClaimSet, InfallibleClaimSet, JWTClaims};
use ssi_sd_jwt::{JsonPointer, RevealError, RevealedSdJwt, SdAlg, SdJwt, SdJwtBuf};
use ssi_vc::{
    enveloped::EnvelopedVerifiableCredential,
    v2::{Credential, CredentialTypes, JsonCredential},
    MaybeIdentified,
};
use xsd_types::DateTimeStamp;

/// SD-JWT VC claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SdJwtVc<T = JsonCredential>(pub T);

impl<T> SdJwtVc<T> {
    pub fn as_jwt_claims(&self) -> JWTClaims<&Self> {
        JWTClaims {
            registered: Default::default(),
            private: self,
        }
    }

    pub fn into_jwt_claims(self) -> JWTClaims<Self> {
        JWTClaims {
            registered: Default::default(),
            private: self,
        }
    }
}

impl<T: Serialize> SdJwtVc<T> {
    pub async fn sign(&self, signer: &impl JwsSigner) -> Result<SdJwtBuf, SignatureError> {
        let pointers: [&JsonPointer; 0] = [];
        self.conceal_and_sign(SdAlg::Sha256, &pointers, signer)
            .await
    }

    pub async fn conceal_and_sign(
        &self,
        sd_alg: SdAlg,
        pointers: &[impl Borrow<JsonPointer>],
        signer: &impl JwsSigner,
    ) -> Result<SdJwtBuf, SignatureError> {
        SdJwtBuf::conceal_and_sign(&self.as_jwt_claims(), sd_alg, pointers, signer).await
    }

    pub async fn sign_into_enveloped(
        &self,
        signer: &impl JwsSigner,
    ) -> Result<EnvelopedVerifiableCredential, SignatureError> {
        let pointers: [&JsonPointer; 0] = [];
        self.conceal_and_sign_into_enveloped(SdAlg::Sha256, &pointers, signer)
            .await
    }

    /// Sign a JOSE VC into an enveloped verifiable credential.
    pub async fn conceal_and_sign_into_enveloped(
        &self,
        sd_alg: SdAlg,
        pointers: &[impl Borrow<JsonPointer>],
        signer: &impl JwsSigner,
    ) -> Result<EnvelopedVerifiableCredential, SignatureError> {
        let sd_jwt = self.conceal_and_sign(sd_alg, pointers, signer).await?;
        Ok(EnvelopedVerifiableCredential {
            context: Context::iri_ref(ssi_vc::v2::CREDENTIALS_V2_CONTEXT_IRI.to_owned().into()),
            id: format!("data:application/vc-ld+sd-jwt,{sd_jwt}")
                .parse()
                .unwrap(),
        })
    }
}

impl<T: DeserializeOwned> SdJwtVc<T> {
    /// Decode a SD-JWT VC.
    pub fn decode_reveal(sd_jwt: &SdJwt) -> Result<RevealedSdJwt<Self>, RevealError> {
        sd_jwt.decode_reveal()
    }
}

impl SdJwtVc {
    /// Decode a SD-JWT VC.
    pub fn decode_reveal_any(sd_jwt: &SdJwt) -> Result<RevealedSdJwt<Self>, RevealError> {
        sd_jwt.decode_reveal()
    }
}

impl<T: MaybeIdentified> MaybeIdentified for SdJwtVc<T> {
    fn id(&self) -> Option<&Uri> {
        self.0.id()
    }
}

impl<T: Credential> Credential for SdJwtVc<T> {
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

impl<E, P, T: ValidateClaims<E, P>> ValidateClaims<E, P> for SdJwtVc<T> {
    fn validate_claims(&self, environment: &E, proof: &P) -> ClaimsValidity {
        self.0.validate_claims(environment, proof)
    }
}

impl<T> ClaimSet for SdJwtVc<T> {}
impl<T> InfallibleClaimSet for SdJwtVc<T> {}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use ssi_claims_core::VerificationParameters;
    use ssi_jwk::JWK;
    use ssi_sd_jwt::{json_pointer, SdAlg, SdJwt, SdJwtBuf};
    use ssi_vc::v2::JsonCredential;

    use crate::SdJwtVc;

    async fn verify(input: &SdJwt, key: &JWK) {
        let vc = SdJwtVc::decode_reveal_any(input).unwrap();
        let params = VerificationParameters::from_resolver(key);
        let result = vc.verify(params).await.unwrap();
        assert_eq!(result, Ok(()))
    }

    #[async_std::test]
    async fn sd_jwt_vc_roundtrip() {
        let vc: JsonCredential = serde_json::from_value(json!({
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2"
            ],
            "id": "http://university.example/credentials/1872",
            "type": [
                "VerifiableCredential",
                "ExampleAlumniCredential"
            ],
            "issuer": "https://university.example/issuers/565049",
            "validFrom": "2010-01-01T19:23:24Z",
            "credentialSchema": {
                "id": "https://example.org/examples/degree.json",
                "type": "JsonSchema"
            },
            "credentialSubject": {
                "id": "did:example:123",
                "degree": {
                    "type": "BachelorDegree",
                    "name": "Bachelor of Science and Arts"
                }
            }
        }))
        .unwrap();

        let key = JWK::generate_p256();
        let enveloped = SdJwtVc(vc)
            .conceal_and_sign_into_enveloped(
                SdAlg::Sha256,
                &[json_pointer!("/credentialSubject/id")],
                &key,
            )
            .await
            .unwrap();
        let jws = SdJwtBuf::new(enveloped.id.decoded_data().unwrap().into_owned()).unwrap();
        verify(&jws, &key).await
    }
}
