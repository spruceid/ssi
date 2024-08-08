use coset::{Algorithm, AsCborValue, CoseSign1, Header, ProtectedHeader};
use ssi_claims_core::SignatureError;

use crate::{CompactCoseSign1Buf, CosePayload, TYP_LABEL};

pub struct CoseSignerInfo {
    pub algorithm: Option<Algorithm>,
    pub key_id: Vec<u8>,
}

/// COSE Signer.
pub trait CoseSigner {
    #[allow(async_fn_in_trait)]
    async fn fetch_info(&self) -> Result<CoseSignerInfo, SignatureError>;

    #[allow(async_fn_in_trait)]
    async fn sign_bytes(&self, signing_bytes: &[u8]) -> Result<Vec<u8>, SignatureError>;

    #[allow(async_fn_in_trait)]
    async fn sign(
        &self,
        payload: &(impl ?Sized + CosePayload),
        additional_data: Option<&[u8]>,
    ) -> Result<CompactCoseSign1Buf, SignatureError> {
        let info = self.fetch_info().await?;

        let mut result = CoseSign1 {
            protected: ProtectedHeader {
                header: Header {
                    alg: info.algorithm,
                    key_id: info.key_id,
                    content_type: payload.content_type(),
                    rest: match payload.typ() {
                        Some(typ) => vec![(TYP_LABEL, typ.into())],
                        None => Vec::new(),
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
            unprotected: Header::default(),
            payload: Some(payload.payload_bytes().into_owned()),
            signature: Vec::new(),
        };

        let tbs = result.tbs_data(additional_data.unwrap_or_default());

        result.signature = self.sign_bytes(&tbs).await?;
        Ok(result.to_cbor_value().unwrap().into())
    }
}

impl<'a, T: CoseSigner> CoseSigner for &'a T {
    async fn fetch_info(&self) -> Result<CoseSignerInfo, SignatureError> {
        T::fetch_info(*self).await
    }

    async fn sign_bytes(&self, signing_bytes: &[u8]) -> Result<Vec<u8>, SignatureError> {
        T::sign_bytes(*self, signing_bytes).await
    }

    async fn sign(
        &self,
        payload: &(impl ?Sized + CosePayload),
        additional_data: Option<&[u8]>,
    ) -> Result<CompactCoseSign1Buf, SignatureError> {
        T::sign(*self, payload, additional_data).await
    }
}
