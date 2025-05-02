use coset::{CoseKey, Header, ProtectedHeader};
use ssi_claims_core::{
    ClaimsValidity, InvalidProof, ProofValidationError, ProofValidity, ResolverProvider,
    ValidateClaims, ValidateProof, VerifiableClaims, Verification,
};
use ssi_crypto::VerificationError;

use crate::{
    algorithm::instantiate_algorithm,
    key::{CoseKeyDecode, CoseKeyResolver, KeyDecodingError},
    CoseSignatureBytes, DecodedCoseSign1, UnsignedCoseSign1,
};

impl<T> DecodedCoseSign1<T> {
    /// Verify.
    pub async fn verify<P>(&self, params: P) -> Result<Verification, ProofValidationError>
    where
        T: ValidateCoseHeader<P> + ValidateClaims<P, CoseSignatureBytes>,
        P: ResolverProvider<Resolver: CoseKeyResolver>,
    {
        VerifiableClaims::verify(self, params).await
    }
}

impl<T> VerifiableClaims for DecodedCoseSign1<T> {
    type Claims = UnsignedCoseSign1<T>;
    type Proof = CoseSignatureBytes;

    fn claims(&self) -> &Self::Claims {
        &self.signing_bytes
    }

    fn proof(&self) -> &Self::Proof {
        &self.signature
    }
}

pub trait ValidateCoseHeader<P> {
    fn validate_cose_headers(
        &self,
        _params: &P,
        _protected: &ProtectedHeader,
        _unprotected: &Header,
    ) -> ClaimsValidity {
        Ok(())
    }
}

impl<P> ValidateCoseHeader<P> for () {}

impl<E, T> ValidateClaims<E, CoseSignatureBytes> for UnsignedCoseSign1<T>
where
    T: ValidateClaims<E, CoseSignatureBytes> + ValidateCoseHeader<E>,
{
    fn validate_claims(&self, params: &E, signature: &CoseSignatureBytes) -> ClaimsValidity {
        self.payload
            .validate_cose_headers(params, &self.protected, &self.unprotected)?;
        self.payload.validate_claims(params, signature)
    }
}

impl<P, T> ValidateProof<P, UnsignedCoseSign1<T>> for CoseSignatureBytes
where
    P: ResolverProvider<Resolver: CoseKeyResolver>,
{
    async fn validate_proof<'a>(
        &'a self,
        params: &'a P,
        claims: &'a UnsignedCoseSign1<T>,
    ) -> Result<ProofValidity, ProofValidationError> {
        let key = params
            .resolver()
            .fetch_public_cose_key(Some(&claims.protected.header.key_id))
            .await?;

        let signing_bytes = claims.tbs_data(&[]);

        verify_bytes(
            claims
                .protected
                .header
                .alg
                .as_ref()
                .ok_or(ProofValidationError::MissingAlgorithm)?,
            &key,
            &signing_bytes,
            &self.0,
        )
        .map(|b| {
            if b {
                Ok(())
            } else {
                Err(InvalidProof::Signature)
            }
        })
        .map_err(Into::into)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CoseVerificationError {
    #[error("unsupported COSE algorithm")]
    UnsupportedAlgorithm(coset::Algorithm),

    #[error(transparent)]
    PublicKey(#[from] KeyDecodingError),

    #[error(transparent)]
    Verification(#[from] VerificationError),
}

impl From<CoseVerificationError> for ProofValidationError {
    fn from(value: CoseVerificationError) -> Self {
        match value {
            CoseVerificationError::PublicKey(_) => Self::InvalidKey,
            e => ProofValidationError::other(e),
        }
    }
}

/// Verify a signature using a COSE key and algorithm.
pub fn verify_bytes(
    algorithm: &coset::Algorithm,
    key: &CoseKey,
    signing_bytes: &[u8],
    signature_bytes: &[u8],
) -> Result<bool, CoseVerificationError> {
    let instance = instantiate_algorithm(algorithm)
        .ok_or_else(|| CoseVerificationError::UnsupportedAlgorithm(algorithm.clone()))?;
    let public_key = key.decode_public()?;

    public_key
        .verify(instance, signing_bytes, signature_bytes)
        .map_err(Into::into)
}
