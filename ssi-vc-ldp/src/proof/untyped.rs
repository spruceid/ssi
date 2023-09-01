use linked_data::LinkedData;
use ssi_verification_methods::{
    InvalidVerificationMethod, ProofPurpose, Referencable, ReferenceOrOwned, ReferenceOrOwnedRef,
    VerificationError,
};

use crate::{CryptographicSuite, Proof, ProofConfiguration, ProofConfigurationRef};

/// Untyped Data Integrity Proof.
#[derive(Debug, Clone, LinkedData, serde::Serialize, serde::Deserialize)]
#[ld(prefix("sec" = "https://w3id.org/security#"))]
#[serde(rename_all = "camelCase")]
pub struct UntypedProof<M, S> {
    /// Date and time of creation.
    #[ld("sec:created")]
    pub created: xsd_types::DateTime,

    /// Verification method.
    #[ld("sec:verificationMethod")]
    pub verification_method: ReferenceOrOwned<M>,

    /// Proof purpose.
    #[ld("sec:proofPurpose")]
    pub proof_purpose: ProofPurpose,

    /// Proof value.
    #[ld(flatten)]
    #[serde(flatten)]
    pub signature: S,
}

impl<M, S> UntypedProof<M, S> {
    pub fn from_options(options: ProofConfiguration<M>, signature: S) -> Self {
        Self::new(
            options.created,
            options.verification_method,
            options.proof_purpose,
            signature,
        )
    }

    pub fn new(
        created: xsd_types::DateTime,
        verification_method: ReferenceOrOwned<M>,
        proof_purpose: ProofPurpose,
        signature: S,
    ) -> Self {
        Self {
            created,
            verification_method,
            proof_purpose,
            signature,
        }
    }

    pub fn borrowed(&self) -> UntypedProofRef<M, S>
    where
        M: Referencable,
        S: Referencable,
    {
        UntypedProofRef {
            created: &self.created,
            verification_method: self.verification_method.borrowed(),
            proof_purpose: self.proof_purpose,
            signature: self.signature.as_reference(),
        }
    }

    pub fn configuration(&self) -> ProofConfigurationRef<M>
    where
        M: Referencable,
    {
        ProofConfigurationRef {
            created: &self.created,
            verification_method: self.verification_method.borrowed(),
            proof_purpose: self.proof_purpose,
        }
    }

    pub fn clone_configuration(&self) -> ProofConfiguration<M>
    where
        M: Clone,
    {
        ProofConfiguration {
            created: self.created,
            verification_method: self.verification_method.clone(),
            proof_purpose: self.proof_purpose,
        }
    }

    pub fn try_map_verification_method<N, T, E>(
        self,
        f: impl FnOnce(ReferenceOrOwned<M>, S) -> Result<(ReferenceOrOwned<N>, T), E>,
    ) -> Result<UntypedProof<N, T>, E> {
        let (verification_method, signature) = f(self.verification_method, self.signature)?;

        Ok(UntypedProof::new(
            self.created,
            verification_method,
            self.proof_purpose,
            signature,
        ))
    }

    pub fn map_verification_method<N, T>(
        self,
        f: impl FnOnce(ReferenceOrOwned<M>, S) -> (ReferenceOrOwned<N>, T),
    ) -> UntypedProof<N, T> {
        let (verification_method, signature) = f(self.verification_method, self.signature);

        UntypedProof::new(
            self.created,
            verification_method,
            self.proof_purpose,
            signature,
        )
    }

    pub fn try_cast_verification_method<N, T>(self) -> Result<UntypedProof<N, T>, ProofCastError>
    where
        M: TryInto<N, Error = InvalidVerificationMethod>,
        S: TryInto<T>,
    {
        self.try_map_verification_method(|m, signature| {
            let n = m.try_cast()?;
            let signature = signature
                .try_into()
                .map_err(|_| ProofCastError::Signature)?;
            Ok((n, signature))
        })
    }

    pub fn into_typed<T: CryptographicSuite<VerificationMethod = M, Signature = S>>(
        self,
        type_: T,
    ) -> Proof<T> {
        Proof {
            type_,
            untyped: self,
        }
    }
}

/// Untyped Data Integrity Proof.
pub struct UntypedProofRef<'a, M: Referencable, S: 'a + Referencable> {
    /// Date and time of creation.
    pub created: &'a xsd_types::DateTime,

    /// Verification method.
    pub verification_method: ReferenceOrOwnedRef<'a, M>,

    /// Proof purpose.
    pub proof_purpose: ProofPurpose,

    /// Proof value.
    pub signature: S::Reference<'a>,
}

impl<'a, M: Referencable, S: 'a + Referencable> UntypedProofRef<'a, M, S> {
    pub fn new(
        created: &'a xsd_types::DateTime,
        verification_method: ReferenceOrOwnedRef<'a, M>,
        proof_purpose: ProofPurpose,
        signature: S::Reference<'a>,
    ) -> Self {
        Self {
            created,
            verification_method,
            proof_purpose,
            signature,
        }
    }

    pub fn try_map_verification_method<N: 'a + Referencable, T: 'a + Referencable, E>(
        self,
        f: impl FnOnce(
            ReferenceOrOwnedRef<'a, M>,
            S::Reference<'a>,
        ) -> Result<(ReferenceOrOwnedRef<'a, N>, T::Reference<'a>), E>,
    ) -> Result<UntypedProofRef<'a, N, T>, E> {
        let (verification_method, signature) = f(self.verification_method, self.signature)?;

        Ok(UntypedProofRef::new(
            self.created,
            verification_method,
            self.proof_purpose,
            signature,
        ))
    }

    pub fn map_verification_method<N: 'a + Referencable, T: 'a + Referencable>(
        self,
        f: impl FnOnce(
            ReferenceOrOwnedRef<'a, M>,
            S::Reference<'a>,
        ) -> (ReferenceOrOwnedRef<'a, N>, T::Reference<'a>),
    ) -> UntypedProofRef<'a, N, T> {
        let (verification_method, signature) = f(self.verification_method, self.signature);

        UntypedProofRef::new(
            self.created,
            verification_method,
            self.proof_purpose,
            signature,
        )
    }

    pub fn try_cast_verification_method<N: 'a + Referencable, T: 'a + Referencable>(
        self,
    ) -> Result<UntypedProofRef<'a, N, T>, ProofCastError>
    where
        M::Reference<'a>: TryInto<N::Reference<'a>, Error = InvalidVerificationMethod>,
        S::Reference<'a>: TryInto<T::Reference<'a>>,
    {
        self.try_map_verification_method(|m, signature| {
            let n = m.try_cast()?;
            let signature = signature
                .try_into()
                .map_err(|_| ProofCastError::Signature)?;
            Ok((n, signature))
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProofCastError {
    #[error(transparent)]
    VerificationMethod(#[from] InvalidVerificationMethod),

    #[error("invalid signature")]
    Signature,
}

impl From<ProofCastError> for VerificationError {
    fn from(value: ProofCastError) -> Self {
        match value {
            ProofCastError::VerificationMethod(iri) => {
                VerificationError::InvalidVerificationMethod(iri)
            }
            ProofCastError::Signature => VerificationError::InvalidSignature,
        }
    }
}
