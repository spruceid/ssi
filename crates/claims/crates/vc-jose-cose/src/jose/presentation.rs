use super::JoseDecodeError;
use serde::{de::DeserializeOwned, Serialize};
use ssi_claims_core::{ClaimsValidity, SignatureError, ValidateClaims};
use ssi_json_ld::{iref::Uri, syntax::Context};
use ssi_jws::{DecodedJws, JwsPayload, JwsSigner, JwsSlice, ValidateJwsHeader};
use ssi_vc::{
    enveloped::{EnvelopedVerifiableCredential, EnvelopedVerifiablePresentation},
    v2::{syntax::JsonPresentation, Presentation, PresentationTypes},
    MaybeIdentified,
};
use std::borrow::Cow;

/// Payload of a JWS-secured Verifiable Presentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct JoseVp<T = JsonPresentation<EnvelopedVerifiableCredential>>(pub T);

impl<T: Serialize> JwsPayload for JoseVp<T> {
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

impl<E, T> ValidateJwsHeader<E> for JoseVp<T> {
    fn validate_jws_header(&self, _env: &E, _header: &ssi_jws::Header) -> ClaimsValidity {
        // There are no formal obligations about `typ` and `cty`.
        // It SHOULD be `vp-ld+jwt` and `vp`, but it does not MUST.
        Ok(())
    }
}

impl<T: Serialize> JoseVp<T> {
    /// Sign a JOSE VC into an enveloped verifiable presentation.
    pub async fn sign_into_enveloped(
        &self,
        signer: &impl JwsSigner,
    ) -> Result<EnvelopedVerifiablePresentation, SignatureError> {
        let jws = JwsPayload::sign(self, signer).await?;
        Ok(EnvelopedVerifiablePresentation {
            context: Context::iri_ref(ssi_vc::v2::CREDENTIALS_V2_CONTEXT_IRI.to_owned().into()),
            id: format!("data:application/vp-ld+jwt,{jws}").parse().unwrap(),
        })
    }
}

impl<T: DeserializeOwned> JoseVp<T> {
    /// Decode a JOSE VP.
    pub fn decode(jws: &JwsSlice) -> Result<DecodedJws<Self>, JoseDecodeError> {
        jws.decode()?
            .try_map(|payload| serde_json::from_slice(&payload).map(Self))
            .map_err(Into::into)
    }
}

impl JoseVp {
    /// Decode a JOSE VP with an arbitrary presentation type.
    pub fn decode_any(jws: &JwsSlice) -> Result<DecodedJws<Self>, JoseDecodeError> {
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

impl<E, P, T: ValidateClaims<E, P>> ValidateClaims<E, P> for JoseVp<T> {
    fn validate_claims(&self, environment: &E, proof: &P) -> ClaimsValidity {
        self.0.validate_claims(environment, proof)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use ssi_claims_core::VerificationParameters;
    use ssi_jwk::JWK;
    use ssi_jws::{JwsSlice, JwsVec};
    use ssi_vc::{enveloped::EnvelopedVerifiableCredential, v2::syntax::JsonPresentation};

    use crate::JoseVp;

    async fn verify(input: &JwsSlice, key: &JWK) {
        let vp = JoseVp::decode_any(input).unwrap();
        let params = VerificationParameters::from_resolver(key);
        let result = vp.verify(params).await.unwrap();
        assert_eq!(result, Ok(()))
    }

    #[async_std::test]
    async fn jose_vp_roundtrip() {
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
        let enveloped = JoseVp(vp).sign_into_enveloped(&key).await.unwrap();
        let jws = JwsVec::new(enveloped.id.decoded_data().unwrap().into_owned()).unwrap();
        verify(&jws, &key).await
    }
}
