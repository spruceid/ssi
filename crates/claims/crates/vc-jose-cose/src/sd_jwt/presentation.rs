use std::borrow::Borrow;

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use ssi_claims_core::{ClaimsValidity, SignatureError, ValidateClaims};
use ssi_json_ld::{iref::Uri, syntax::Context};
use ssi_jws::JwsSigner;
use ssi_jwt::{ClaimSet, InfallibleClaimSet, JWTClaims};
use ssi_sd_jwt::{JsonPointer, RevealError, RevealedSdJwt, SdAlg, SdJwt, SdJwtBuf};
use ssi_vc::{
    enveloped::EnvelopedVerifiableCredential,
    v2::{syntax::JsonPresentation, Presentation, PresentationTypes},
    MaybeIdentified,
};

/// SD-JWT VP claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SdJwtVp<T = JsonPresentation<EnvelopedVerifiableCredential>>(pub T);

impl<T> SdJwtVp<T> {
    /// Returns this presentation as JWT claims.
    ///
    /// These are the claims that will be encoded in the SD-JWT.
    pub fn as_jwt_claims(&self) -> JWTClaims<&Self> {
        JWTClaims {
            registered: Default::default(),
            private: self,
        }
    }

    /// Turns this presentation into JWT claims.
    ///
    /// These claims can then be encoded in the SD-JWT.
    pub fn into_jwt_claims(self) -> JWTClaims<Self> {
        JWTClaims {
            registered: Default::default(),
            private: self,
        }
    }
}

impl<T: Serialize> SdJwtVp<T> {
    /// Signs the presentation into an SD-JWT without any concealed claims.
    ///
    /// The generated SD-JWT will not have any disclosures.
    ///
    /// Use [`Self::conceal_and_sign`] to select the claims to be concealed.
    pub async fn sign(&self, signer: &impl JwsSigner) -> Result<SdJwtBuf, SignatureError> {
        let pointers: [&JsonPointer; 0] = [];
        self.conceal_and_sign(SdAlg::Sha256, &pointers, signer)
            .await
    }

    /// Signs the presentation while concealing the claims selected by the given
    /// JSON pointers.
    ///
    /// You can use [`Self::sign`] directly if you don't need to conceal
    /// anything.
    pub async fn conceal_and_sign(
        &self,
        sd_alg: SdAlg,
        pointers: &[impl Borrow<JsonPointer>],
        signer: &impl JwsSigner,
    ) -> Result<SdJwtBuf, SignatureError> {
        SdJwtBuf::conceal_and_sign(&self.as_jwt_claims(), sd_alg, pointers, signer).await
    }

    /// Signs the presentation into an enveloped verifiable presentation (with
    /// an SD-JWT identifier) without concealing any claim.
    ///
    /// The generated SD-JWT, encoded in the presentation identifier, will not
    /// have any disclosures.
    ///
    /// Use [`Self::conceal_and_sign_into_enveloped`] to select the claims to be
    /// concealed.
    pub async fn sign_into_enveloped(
        &self,
        signer: &impl JwsSigner,
    ) -> Result<EnvelopedVerifiableCredential, SignatureError> {
        let pointers: [&JsonPointer; 0] = [];
        self.conceal_and_sign_into_enveloped(SdAlg::Sha256, &pointers, signer)
            .await
    }

    /// Signs the presentation into an enveloped verifiable presentation (with
    /// an SD-JWT identifier) while concealing the claims selected by the given
    /// JSON pointers.
    ///
    /// The generated SD-JWT, encoded in the presentation identifier, will not
    /// have any disclosures.
    ///
    /// Use [`Self::conceal_and_sign_into_enveloped`] to select the claims to be
    /// concealed.
    pub async fn conceal_and_sign_into_enveloped(
        &self,
        sd_alg: SdAlg,
        pointers: &[impl Borrow<JsonPointer>],
        signer: &impl JwsSigner,
    ) -> Result<EnvelopedVerifiableCredential, SignatureError> {
        let sd_jwt = self.conceal_and_sign(sd_alg, pointers, signer).await?;
        Ok(EnvelopedVerifiableCredential {
            context: Context::iri_ref(ssi_vc::v2::CREDENTIALS_V2_CONTEXT_IRI.to_owned().into()),
            id: format!("data:application/vp-ld+sd-jwt,{sd_jwt}")
                .parse()
                .unwrap(),
        })
    }
}

impl<T: DeserializeOwned> SdJwtVp<T> {
    /// Decodes a SD-JWT VP, revealing its disclosed claims.
    ///
    /// This function requires the `T` parameter, representing the presentation
    /// type, to be known. If you don't know what `T` you should use, use the
    /// [`Self::decode_reveal_any`].
    pub fn decode_reveal(sd_jwt: &SdJwt) -> Result<RevealedSdJwt<Self>, RevealError> {
        sd_jwt.decode_reveal()
    }
}

impl SdJwtVp {
    /// Decodes a SD-JWT VP, revealing its disclosed claims.
    ///
    /// This function uses [`JsonPresentation<EnvelopedVerifiableCredential>`]
    /// as presentation type. If you need to use a custom presentation type, use
    /// the [`Self::decode_reveal`] function.
    pub fn decode_reveal_any(sd_jwt: &SdJwt) -> Result<RevealedSdJwt<Self>, RevealError> {
        sd_jwt.decode_reveal()
    }
}

impl<T: MaybeIdentified> MaybeIdentified for SdJwtVp<T> {
    fn id(&self) -> Option<&Uri> {
        self.0.id()
    }
}

impl<T: Presentation> Presentation for SdJwtVp<T> {
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

impl<E, P, T: ValidateClaims<E, P>> ValidateClaims<E, P> for SdJwtVp<T> {
    fn validate_claims(&self, environment: &E, proof: &P) -> ClaimsValidity {
        self.0.validate_claims(environment, proof)
    }
}

impl<T> ClaimSet for SdJwtVp<T> {}
impl<T> InfallibleClaimSet for SdJwtVp<T> {}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use ssi_claims_core::VerificationParameters;
    use ssi_jwk::JWK;
    use ssi_sd_jwt::{SdJwt, SdJwtBuf};
    use ssi_vc::{enveloped::EnvelopedVerifiableCredential, v2::syntax::JsonPresentation};

    use crate::SdJwtVp;

    async fn verify(input: &SdJwt, key: &JWK) {
        let vp = SdJwtVp::decode_reveal_any(input).unwrap();
        let params = VerificationParameters::from_resolver(key);
        let result = vp.verify(params).await.unwrap();
        assert_eq!(result, Ok(()))
    }

    #[async_std::test]
    async fn sd_jwt_vp_roundtrip() {
        let vp: JsonPresentation<EnvelopedVerifiableCredential> = serde_json::from_value(json!({
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2"
            ],
            "type": "VerifiablePresentation",
            "verifiableCredential": [{
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["EnvelopedVerifiableCredential"],
                "id": "data:application/vc-ld+jwt,eyJraWQiOiJFeEhrQk1XOWZtYmt2VjI2Nm1ScHVQMnNVWV9OX0VXSU4xbGFwVXpPOHJvIiwiYWxnIjoiRVMzODQifQ.eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvZXhhbXBsZXMvdjIiXSwiaWQiOiJodHRwOi8vdW5pdmVyc2l0eS5leGFtcGxlL2NyZWRlbnRpYWxzLzE4NzIiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiRXhhbXBsZUFsdW1uaUNyZWRlbnRpYWwiXSwiaXNzdWVyIjoiaHR0cHM6Ly91bml2ZXJzaXR5LmV4YW1wbGUvaXNzdWVycy81NjUwNDkiLCJ2YWxpZEZyb20iOiIyMDEwLTAxLTAxVDE5OjIzOjI0WiIsImNyZWRlbnRpYWxTY2hlbWEiOnsiaWQiOiJodHRwczovL2V4YW1wbGUub3JnL2V4YW1wbGVzL2RlZ3JlZS5qc29uIiwidHlwZSI6Ikpzb25TY2hlbWEifSwiY3JlZGVudGlhbFN1YmplY3QiOnsiaWQiOiJkaWQ6ZXhhbXBsZToxMjMiLCJkZWdyZWUiOnsidHlwZSI6IkJhY2hlbG9yRGVncmVlIiwibmFtZSI6IkJhY2hlbG9yIG9mIFNjaWVuY2UgYW5kIEFydHMifX19.d2k4O3FytQJf83kLh-HsXuPvh6yeOlhJELVo5TF71gu7elslQyOf2ZItAXrtbXF4Kz9WivNdztOayz4VUQ0Mwa8yCDZkP9B2pH-9S_tcAFxeoeJ6Z4XnFuL_DOfkR1fP"
            }]
        })).unwrap();

        let key = JWK::generate_p256();
        let enveloped = SdJwtVp(vp).sign_into_enveloped(&key).await.unwrap();
        let jws = SdJwtBuf::new(enveloped.id.decoded_data().unwrap().into_owned()).unwrap();
        verify(&jws, &key).await
    }
}
