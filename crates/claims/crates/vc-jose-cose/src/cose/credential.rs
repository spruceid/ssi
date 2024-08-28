use base64::Engine;
use serde::{de::DeserializeOwned, Serialize};
use ssi_claims_core::{ClaimsValidity, DateTimeProvider, SignatureError, ValidateClaims};
use ssi_cose::{CosePayload, CoseSign1Bytes, CoseSigner, DecodedCoseSign1, ValidateCoseHeader};
use ssi_json_ld::{iref::Uri, syntax::Context};
use ssi_vc::{
    enveloped::EnvelopedVerifiableCredential,
    v2::{Credential, CredentialTypes, JsonCredential},
    MaybeIdentified,
};
use std::borrow::Cow;
use xsd_types::DateTimeStamp;

use super::CoseDecodeError;

/// Payload of a COSE_Sign1-secured Verifiable Credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CoseVc<T = JsonCredential>(pub T);

impl<T: Serialize> CoseVc<T> {
    /// Sign a COSE VC into an enveloped verifiable credential.
    pub async fn sign_into_enveloped(
        &self,
        signer: impl CoseSigner,
    ) -> Result<EnvelopedVerifiableCredential, SignatureError> {
        let cose = CosePayload::sign(self, signer, true).await?;
        let base64_cose = base64::prelude::BASE64_STANDARD.encode(&cose);
        Ok(EnvelopedVerifiableCredential {
            context: Context::iri_ref(ssi_vc::v2::CREDENTIALS_V2_CONTEXT_IRI.to_owned().into()),
            id: format!("data:application/vc-ld+cose;base64,{base64_cose}")
                .parse()
                .unwrap(),
        })
    }
}

impl<T: DeserializeOwned> CoseVc<T> {
    /// Decode a COSE VC.
    pub fn decode(
        cose: &CoseSign1Bytes,
        tagged: bool,
    ) -> Result<DecodedCoseSign1<Self>, CoseDecodeError> {
        cose.decode(tagged)?
            .try_map(|_, payload| serde_json::from_slice(payload).map(Self))
            .map_err(Into::into)
    }
}

impl CoseVc {
    /// Decode a JOSE VC with an arbitrary credential type.
    pub fn decode_any(
        cose: &CoseSign1Bytes,
        tagged: bool,
    ) -> Result<DecodedCoseSign1<Self>, CoseDecodeError> {
        Self::decode(cose, tagged)
    }
}

impl<T: Serialize> CosePayload for CoseVc<T> {
    fn typ(&self) -> Option<ssi_cose::CosePayloadType> {
        Some(ssi_cose::CosePayloadType::Text(
            "application/vc-ld+cose".to_owned(),
        ))
    }

    fn content_type(&self) -> Option<ssi_cose::ContentType> {
        Some(ssi_cose::ContentType::Text("application/vc".to_owned()))
    }

    fn payload_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(serde_json::to_vec(&self.0).unwrap())
    }
}

impl<E, T> ValidateCoseHeader<E> for CoseVc<T> {
    fn validate_cose_headers(
        &self,
        _params: &E,
        _protected: &ssi_cose::ProtectedHeader,
        _unprotected: &ssi_cose::Header,
    ) -> ClaimsValidity {
        Ok(())
    }
}

impl<T: MaybeIdentified> MaybeIdentified for CoseVc<T> {
    fn id(&self) -> Option<&Uri> {
        self.0.id()
    }
}

impl<T: Credential> Credential for CoseVc<T> {
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

impl<E, P, T: ValidateClaims<E, P>> ValidateClaims<E, P> for CoseVc<T> {
    fn validate_claims(&self, environment: &E, proof: &P) -> ClaimsValidity {
        self.0.validate_claims(environment, proof)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use ssi_claims_core::VerificationParameters;
    use ssi_cose::{coset::CoseKey, key::CoseKeyGenerate, CoseSign1Bytes, CoseSign1BytesBuf};
    use ssi_vc::v2::JsonCredential;

    use super::CoseVc;

    async fn verify(input: &CoseSign1Bytes, key: &CoseKey) {
        let vc = CoseVc::decode_any(input, true).unwrap();
        let params = VerificationParameters::from_resolver(key);
        let result = vc.verify(params).await.unwrap();
        assert_eq!(result, Ok(()))
    }

    #[async_std::test]
    async fn cose_vc_roundtrip() {
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

        let key = CoseKey::generate_p256();
        let enveloped = CoseVc(vc).sign_into_enveloped(&key).await.unwrap();
        let jws = CoseSign1BytesBuf::new(enveloped.id.decoded_data().unwrap().into_owned());
        verify(&jws, &key).await
    }

    #[test]
    fn example7() {
        let input_hex = "d28444a1013822a05901f87b2240636f6e74657874223a5b2268747470733a2f2f7777772e77332e6f72672f6e732f63726564656e7469616c732f7632222c2268747470733a2f2f7777772e77332e6f72672f6e732f63726564656e7469616c732f6578616d706c65732f7632225d2c226964223a22687474703a2f2f756e69766572736974792e6578616d706c652f63726564656e7469616c732f31383732222c2274797065223a5b2256657269666961626c6543726564656e7469616c222c224578616d706c65416c756d6e6943726564656e7469616c225d2c22697373756572223a2268747470733a2f2f756e69766572736974792e6578616d706c652f697373756572732f353635303439222c2276616c696446726f6d223a22323031302d30312d30315431393a32333a32345a222c2263726564656e7469616c536368656d61223a7b226964223a2268747470733a2f2f6578616d706c652e6f72672f6578616d706c65732f6465677265652e6a736f6e222c2274797065223a224a736f6e536368656d61227d2c2263726564656e7469616c5375626a656374223a7b226964223a226469643a6578616d706c653a313233222c22646567726565223a7b2274797065223a2242616368656c6f72446567726565222c226e616d65223a2242616368656c6f72206f6620536369656e636520616e642041727473227d7d7d58405731e67b84ce95105ea78d49b97f90f962c7e247ebaf4c057b2d8ef16b11882cea11170fcf7b566fd7d8932a597885599d7e010b15d1aa639bcceaf114325a01";
        let input = CoseSign1BytesBuf::new(hex::decode(input_hex).unwrap());
        let _ = CoseVc::decode_any(&input, true).unwrap();
    }
}
