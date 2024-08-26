use super::CoseDecodeError;
use base64::Engine;
use serde::{de::DeserializeOwned, Serialize};
use ssi_claims_core::{ClaimsValidity, SignatureError, ValidateClaims};
use ssi_cose::{CosePayload, CoseSign1Bytes, CoseSigner, DecodedCoseSign1, ValidateCoseHeader};
use ssi_json_ld::{iref::Uri, syntax::Context};
use ssi_vc::{
    enveloped::{EnvelopedVerifiableCredential, EnvelopedVerifiablePresentation},
    v2::{syntax::JsonPresentation, Presentation, PresentationTypes},
    MaybeIdentified,
};
use std::borrow::Cow;

/// Payload of a COSE-secured Verifiable Presentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CoseVp<T = JsonPresentation<EnvelopedVerifiableCredential>>(pub T);

impl<T: Serialize> CosePayload for CoseVp<T> {
    fn typ(&self) -> Option<ssi_cose::CosePayloadType> {
        Some(ssi_cose::CosePayloadType::Text(
            "application/vp-ld+cose".to_owned(),
        ))
    }

    fn content_type(&self) -> Option<ssi_cose::ContentType> {
        Some(ssi_cose::ContentType::Text("application/vp".to_owned()))
    }

    fn payload_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(serde_json::to_vec(&self.0).unwrap())
    }
}

impl<E, T> ValidateCoseHeader<E> for CoseVp<T> {
    fn validate_cose_headers(
        &self,
        _params: &E,
        _protected: &ssi_cose::ProtectedHeader,
        _unprotected: &ssi_cose::Header,
    ) -> ClaimsValidity {
        Ok(())
    }
}

impl<T: Serialize> CoseVp<T> {
    /// Sign a COSE VP into an enveloped verifiable presentation.
    pub async fn sign_into_enveloped(
        &self,
        signer: &impl CoseSigner,
    ) -> Result<EnvelopedVerifiablePresentation, SignatureError> {
        let cose = CosePayload::sign(self, signer, true).await?;
        let base64_cose = base64::prelude::BASE64_STANDARD.encode(&cose);
        Ok(EnvelopedVerifiablePresentation {
            context: Context::iri_ref(ssi_vc::v2::CREDENTIALS_V2_CONTEXT_IRI.to_owned().into()),
            id: format!("data:application/vp-ld+cose;base64,{base64_cose}")
                .parse()
                .unwrap(),
        })
    }
}

impl<T: DeserializeOwned> CoseVp<T> {
    /// Decode a JOSE VP.
    pub fn decode(
        cose: &CoseSign1Bytes,
        tagged: bool,
    ) -> Result<DecodedCoseSign1<Self>, CoseDecodeError> {
        cose.decode(tagged)?
            .try_map(|_, payload| serde_json::from_slice(payload).map(Self))
            .map_err(Into::into)
    }
}

impl CoseVp {
    /// Decode a JOSE VP with an arbitrary presentation type.
    pub fn decode_any(
        jws: &CoseSign1Bytes,
        tagged: bool,
    ) -> Result<DecodedCoseSign1<Self>, CoseDecodeError> {
        Self::decode(jws, tagged)
    }
}

impl<T: MaybeIdentified> MaybeIdentified for CoseVp<T> {
    fn id(&self) -> Option<&ssi_json_ld::iref::Uri> {
        self.0.id()
    }
}

impl<T: Presentation> Presentation for CoseVp<T> {
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

impl<E, P, T: ValidateClaims<E, P>> ValidateClaims<E, P> for CoseVp<T> {
    fn validate_claims(&self, environment: &E, proof: &P) -> ClaimsValidity {
        self.0.validate_claims(environment, proof)
    }
}

#[cfg(test)]
mod tests {
    use super::CoseVp;
    use serde_json::json;
    use ssi_claims_core::VerificationParameters;
    use ssi_cose::{key::CoseKeyGenerate, CoseKey, CoseSign1Bytes, CoseSign1BytesBuf};
    use ssi_vc::{enveloped::EnvelopedVerifiableCredential, v2::syntax::JsonPresentation};

    async fn verify(input: &CoseSign1Bytes, key: &CoseKey) {
        let vp = CoseVp::decode_any(input, true).unwrap();
        let params = VerificationParameters::from_resolver(key);
        let result = vp.verify(params).await.unwrap();
        assert_eq!(result, Ok(()))
    }

    #[async_std::test]
    async fn cose_vp_roundtrip() {
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

        let key = CoseKey::generate_p256();
        let enveloped = CoseVp(vp).sign_into_enveloped(&key).await.unwrap();
        let jws = CoseSign1BytesBuf::new(enveloped.id.decoded_data().unwrap().into_owned());
        verify(&jws, &key).await
    }

    // NOTE: the example is incorrect because of the invalid data URL.
    // #[test]
    // fn example8() {
    //     let input_hex = "d28444a1013822a05908d67b2240636f6e74657874223a5b2268747470733a2f2f7777772e77332e6f72672f6e732f63726564656e7469616c732f7632222c2268747470733a2f2f7777772e77332e6f72672f6e732f63726564656e7469616c732f6578616d706c65732f7632225d2c2274797065223a2256657269666961626c6550726573656e746174696f6e222c2276657269666961626c6543726564656e7469616c223a5b7b2240636f6e74657874223a2268747470733a2f2f7777772e77332e6f72672f6e732f63726564656e7469616c732f7632222c226964223a22646174613a6170706c69636174696f6e2f76632d6c642b73642d6a77743b65794a68624763694f694a46557a4d344e434973496d74705a434936496c565254563966626c4530557a5a43547a68755554527554303559654842346148526f62336c4f654749314d30785a5a316c364c544a42516e4d694c434a30655841694f694a32634374735a437471633239754b334e6b4c57703364434973496d4e3065534936496e5a774b32786b4b32707a6232346966512e65794a4159323975644756346443493657794a6f64485277637a6f764c336433647935334d793576636d6376626e4d7659334a6c5a47567564476c6862484d76646a49694c434a6f64485277637a6f764c336433647935334d793576636d6376626e4d7659334a6c5a47567564476c6862484d765a586868625842735a584d76646a496958537769646d567961575a7059574a735a554e795a57526c626e5270595777694f6c7437496b426a623235305a586830496a7062496d68306448427a4f693876643364334c6e637a4c6d39795a7939756379396a636d566b5a57353061574673637939324d694973496d68306448427a4f693876643364334c6e637a4c6d39795a7939756379396a636d566b5a573530615746736379396c654746746347786c637939324d694a644c434a7063334e315a5849694f694a6f64485277637a6f764c33567561585a6c636e4e7064486b755a586868625842735a53397063334e315a584a7a4c7a55324e5441304f534973496e5a6862476c6b526e4a7662534936496a49774d5441744d4445744d4446554d546b364d6a4d364d6a52614969776959334a6c5a47567564476c6862464e31596d706c593351694f6e73695957783162573570543259694f6e7369626d46745a534936496b5634595731776247556756573570646d567963326c3065534973496c397a5a43493657794a6f656b394c527a55326344493563314279544746444e554534526e64466455637a5655303564556c5a5531703163553959637a4a6c56474a42496c31394c434a66633251694f6c736957566458566d5644526e6478516d6b34574442715346396a56304e575755313653544e684f48426a5445565952575a6963464e5351566c6e64794a646653776958334e6b496a7062496a4a4a5a6a68686155733452455a7756574a346445633163474d77656c395361464a7a626d3179624746524d45687a63546b3457464e79595773694c434a5565445a345a575a4d565564555a557066595774565546644765484e766255686f62477457566e70664e7a566f61565a3665577079596d567a496c31395853776958334e6b496a7062496a6432616e6c3056564e335a454a304d585135526b746c4f56466653334a49525868465747787254454661547a424b4d304a7064323030646c6b695853776958334e6b583246735a794936496e4e6f595330794e5459694c434a70595851694f6a45334d4459314e6a49344e446b73496d5634634349364d54637a4f4445344e5449304f5377695932356d496a7037496d70336179493665794a7264486b694f694a4651794973496d4e7964694936496c41744d7a6730496977695957786e496a6f6952564d7a4f4451694c434a34496a6f6964577445643155325a7a6c51555652465557685961456779636b525a4e6e644d516c67335548466c556a5a4263476c685648424555586f77636c387464446c3655584e78656d35345a3068456345356f656b5a6c51794973496e6b694f694a4d516e6856596e425664464e474d56564b56545670596e4a49646b70494e6a4255534735594d6b3178613078485a476c7455316c3055475234526c6b784f456468636c64695333465a5630646a556b5a4856453942496e313966512e6b594436335974424e596e4c55547736537a663176735f556733554258685077437971704e6d506e5044613372585a5168514c6442314267616f4f387a67512d6333423431667861584d6e4c485956392d42323075626f53704a5030422d325672653931376551743163534473774447415f5974766e3442537159564242324a7e57794a464d6b4673527a68735932703051564672636c6c49626a6c49626e565249697767496e5235634755694c434169566d567961575a7059574a735a5642795a584e6c626e526864476c7662694a647e577949354e6c64594d44526e656e6f3463565a7a4f565a4c553277775954566e49697767496d6c6b49697767496d6830644841364c793931626d6c325a584a7a615852354c6d5634595731776247557659334a6c5a47567564476c6862484d764d5467334d694a647e57794a61656b553256465661616d74484d5731445758424b4d45686e63306c3349697767496e5235634755694c434262496c5a6c636d6c6d6157466962475644636d566b5a5735306157467349697767496b5634595731776247564262485674626d6c44636d566b5a57353061574673496c31647e5779497451334e73533235475a47465962324a695157737955304a425647523349697767496d6c6b49697767496d52705a44706c654746746347786c4f6d56695a6d56694d5759334d544a6c596d4d325a6a466a4d6a63325a5445795a574d794d534a647e57794a75526d314f576c3949637a423357574e6f4f46646b6554646e51554e5249697767496d6c6b49697767496d52705a44706c654746746347786c4f6d4d794e7a5a6c4d544a6c597a49785a574a6d5a5749785a6a63784d6d5669597a5a6d4d534a64222c2274797065223a22456e76656c6f70656456657269666961626c6543726564656e7469616c227d5d7d5840710a23eba256305aaadd73655219bc38acf04714ce3310823f3ad2288a58f9b40e8764cbe28fe20a60e415e63fba71f352160dd2c812c2dd794cd67f420999fd";
    //     let input = CoseSign1BytesBuf::new(hex::decode(input_hex).unwrap());
    //     let _ = CoseVp::decode_any(&input, true).unwrap();
    // }
}
