use coset::{
    Algorithm, CborSerializable, CoseSign1, Header, ProtectedHeader, TaggedCborSerializable,
};
use ssi_claims_core::SignatureError;

use crate::{CompactCoseSign1Buf, CosePayload, TYP_LABEL};

/// COSE signer information.
pub struct CoseSignerInfo {
    /// Signature algorithm.
    pub algorithm: Option<Algorithm>,

    /// Signing key identifier.
    pub key_id: Vec<u8>,
}

/// COSE signer.
///
/// Any type with the ability to sign a COSE payload.
pub trait CoseSigner {
    /// Fetches the information about the signing key.
    ///
    /// This information will be included in the COSE header.
    #[allow(async_fn_in_trait)]
    async fn fetch_info(&self) -> Result<CoseSignerInfo, SignatureError>;

    /// Signs the given bytes.
    #[allow(async_fn_in_trait)]
    async fn sign_bytes(&self, signing_bytes: &[u8]) -> Result<Vec<u8>, SignatureError>;

    /// Signs the given payload.
    ///
    /// Returns a serialized `COSE_Sign1` object, tagged or not according to
    /// `tagged`.
    #[allow(async_fn_in_trait)]
    async fn sign(
        &self,
        payload: &(impl ?Sized + CosePayload),
        additional_data: Option<&[u8]>,
        tagged: bool,
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

        Ok(if tagged {
            result.to_tagged_vec().unwrap().into()
        } else {
            result.to_vec().unwrap().into()
        })
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
        tagged: bool,
    ) -> Result<CompactCoseSign1Buf, SignatureError> {
        T::sign(*self, payload, additional_data, tagged).await
    }
}
