use coset::{Header, ProtectedHeader};
use ssi_claims_core::{
    ClaimsValidity, ProofValidationError, ProofValidity, ValidateClaims, ValidateProof,
    VerifiableClaims, Verification, VerificationParameters,
};
use ssi_crypto::Verifier;

use crate::{
    algorithm::instantiate_algorithm, CoseSignatureBytes, DecodedCoseSign1, UnsignedCoseSign1,
};

impl<T> DecodedCoseSign1<T> {
    /// Verify.
    pub async fn verify(
        &self,
        verifier: impl Verifier,
    ) -> Result<Verification, ProofValidationError>
    where
        T: ValidateCoseHeader + ValidateClaims<CoseSignatureBytes>,
    {
        VerifiableClaims::verify(self, verifier).await
    }

    /// Verify.
    pub async fn verify_with(
        &self,
        verifier: impl Verifier,
        params: &VerificationParameters,
    ) -> Result<Verification, ProofValidationError>
    where
        T: ValidateCoseHeader + ValidateClaims<CoseSignatureBytes>,
    {
        VerifiableClaims::verify_with(self, verifier, params).await
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

pub trait ValidateCoseHeader {
    fn validate_cose_headers(
        &self,
        _params: &VerificationParameters,
        _protected: &ProtectedHeader,
        _unprotected: &Header,
    ) -> ClaimsValidity {
        Ok(())
    }
}

impl ValidateCoseHeader for () {}

impl<T> ValidateClaims<CoseSignatureBytes> for UnsignedCoseSign1<T>
where
    T: ValidateClaims<CoseSignatureBytes> + ValidateCoseHeader,
{
    fn validate_claims(
        &self,
        params: &VerificationParameters,
        signature: &CoseSignatureBytes,
    ) -> ClaimsValidity {
        self.payload
            .validate_cose_headers(params, &self.protected, &self.unprotected)?;
        self.payload.validate_claims(params, signature)
    }
}

impl<T> ValidateProof<UnsignedCoseSign1<T>> for CoseSignatureBytes {
    async fn validate_proof<'a>(
        &'a self,
        verifier: impl Verifier,
        _params: &'a VerificationParameters,
        claims: &'a UnsignedCoseSign1<T>,
    ) -> Result<ProofValidity, ProofValidationError> {
        let signing_bytes = claims.tbs_data(&[]);

        Ok(verifier
            .verify_bytes(
                Some(&claims.protected.header.key_id),
                claims
                    .protected
                    .header
                    .alg
                    .as_ref()
                    .and_then(instantiate_algorithm),
                &signing_bytes,
                &self.0,
            )
            .await?
            .map_err(Into::into))
    }
}
