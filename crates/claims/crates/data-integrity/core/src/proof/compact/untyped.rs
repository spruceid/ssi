use ssi_core::Referencable;
use ssi_verification_methods::{
    InvalidVerificationMethod, ProofPurpose, ReferenceOrOwned, ReferenceOrOwnedRef,
    VerificationError,
};
use std::collections::BTreeMap;

use crate::CryptographicSuite;

use super::{Proof, ProofConfiguration, ProofConfigurationRef};

/// Untyped Data Integrity Proof.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UntypedProof<M, O, S> {
    /// Date and time of creation.
    pub created: xsd_types::DateTime,

    /// Verification method.
    pub verification_method: ReferenceOrOwned<M>,

    /// Proof purpose.
    pub proof_purpose: ProofPurpose,

    /// Additional proof options required by the cryptographic suite.
    #[serde(flatten)]
    pub options: O,

    /// Proof value.
    #[serde(flatten)]
    pub signature: S,

    /// Extra properties.
    #[serde(flatten)]
    pub extra_properties: BTreeMap<String, json_syntax::Value>,
}

impl<M, O, S> UntypedProof<M, O, S> {
    pub fn from_configuration(configuration: ProofConfiguration<M, O>, signature: S) -> Self {
        Self::new(
            configuration.created,
            configuration.verification_method,
            configuration.proof_purpose,
            configuration.options,
            signature,
        )
    }

    pub fn new(
        created: xsd_types::DateTime,
        verification_method: ReferenceOrOwned<M>,
        proof_purpose: ProofPurpose,
        options: O,
        signature: S,
    ) -> Self {
        Self {
            created,
            verification_method,
            proof_purpose,
            options,
            signature,
            extra_properties: BTreeMap::new(),
        }
    }

    pub fn borrowed(&self) -> UntypedProofRef<M, O, S>
    where
        M: Referencable,
        O: Referencable,
        S: Referencable,
    {
        UntypedProofRef {
            created: &self.created,
            verification_method: self.verification_method.borrowed(),
            proof_purpose: self.proof_purpose,
            options: self.options.as_reference(),
            signature: self.signature.as_reference(),
        }
    }

    pub fn configuration(&self) -> ProofConfigurationRef<M, O>
    where
        M: Referencable,
        O: Referencable,
    {
        ProofConfigurationRef {
            created: &self.created,
            verification_method: self.verification_method.borrowed(),
            proof_purpose: self.proof_purpose,
            options: self.options.as_reference(),
            extra_properties: &self.extra_properties,
        }
    }

    pub fn clone_configuration(&self) -> ProofConfiguration<M, O>
    where
        M: Clone,
        O: Clone,
    {
        ProofConfiguration {
            created: self.created,
            verification_method: self.verification_method.clone(),
            proof_purpose: self.proof_purpose,
            options: self.options.clone(),
            extra_properties: self.extra_properties.clone(),
        }
    }

    pub fn try_map_verification_method<N, P, T, E>(
        self,
        f: impl FnOnce(ReferenceOrOwned<M>, O, S) -> Result<(ReferenceOrOwned<N>, P, T), E>,
    ) -> Result<UntypedProof<N, P, T>, E> {
        let (verification_method, options, signature) =
            f(self.verification_method, self.options, self.signature)?;

        Ok(UntypedProof::new(
            self.created,
            verification_method,
            self.proof_purpose,
            options,
            signature,
        ))
    }

    pub fn map_verification_method<N, P, T>(
        self,
        f: impl FnOnce(ReferenceOrOwned<M>, O, S) -> (ReferenceOrOwned<N>, P, T),
    ) -> UntypedProof<N, P, T> {
        let (verification_method, options, signature) =
            f(self.verification_method, self.options, self.signature);

        UntypedProof::new(
            self.created,
            verification_method,
            self.proof_purpose,
            options,
            signature,
        )
    }

    pub fn try_cast_verification_method<N, P, T>(
        self,
    ) -> Result<UntypedProof<N, P, T>, ProofCastError>
    where
        M: TryInto<N, Error = InvalidVerificationMethod>,
        O: TryInto<P>,
        S: TryInto<T>,
    {
        self.try_map_verification_method(|m, options, signature| {
            let n = m.try_cast()?;
            let options = options.try_into().map_err(|_| ProofCastError::Options)?;
            let signature = signature
                .try_into()
                .map_err(|_| ProofCastError::Signature)?;
            Ok((n, options, signature))
        })
    }

    pub fn into_typed<T: CryptographicSuite<VerificationMethod = M, Options = O, Signature = S>>(
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
pub struct UntypedProofRef<'a, M: Referencable, O: 'a + Referencable, S: 'a + Referencable> {
    /// Date and time of creation.
    pub created: &'a xsd_types::DateTime,

    /// Verification method.
    pub verification_method: ReferenceOrOwnedRef<'a, M>,

    /// Proof purpose.
    pub proof_purpose: ProofPurpose,

    pub options: O::Reference<'a>,

    /// Proof value.
    pub signature: S::Reference<'a>,
}

impl<'a, M: Referencable, O: 'a + Referencable, S: 'a + Referencable> UntypedProofRef<'a, M, O, S> {
    pub fn new(
        created: &'a xsd_types::DateTime,
        verification_method: ReferenceOrOwnedRef<'a, M>,
        proof_purpose: ProofPurpose,
        options: O::Reference<'a>,
        signature: S::Reference<'a>,
    ) -> Self {
        Self {
            created,
            verification_method,
            proof_purpose,
            options,
            signature,
        }
    }

    pub fn try_map_verification_method<
        N: 'a + Referencable,
        P: 'a + Referencable,
        T: 'a + Referencable,
        E,
    >(
        self,
        f: impl FnOnce(
            ReferenceOrOwnedRef<'a, M>,
            O::Reference<'a>,
            S::Reference<'a>,
        ) -> Result<
            (
                ReferenceOrOwnedRef<'a, N>,
                P::Reference<'a>,
                T::Reference<'a>,
            ),
            E,
        >,
    ) -> Result<UntypedProofRef<'a, N, P, T>, E> {
        let (verification_method, options, signature) =
            f(self.verification_method, self.options, self.signature)?;

        Ok(UntypedProofRef::new(
            self.created,
            verification_method,
            self.proof_purpose,
            options,
            signature,
        ))
    }

    pub fn map_verification_method<
        N: 'a + Referencable,
        P: 'a + Referencable,
        T: 'a + Referencable,
    >(
        self,
        f: impl FnOnce(
            ReferenceOrOwnedRef<'a, M>,
            O::Reference<'a>,
            S::Reference<'a>,
        ) -> (
            ReferenceOrOwnedRef<'a, N>,
            P::Reference<'a>,
            T::Reference<'a>,
        ),
    ) -> UntypedProofRef<'a, N, P, T> {
        let (verification_method, options, signature) =
            f(self.verification_method, self.options, self.signature);

        UntypedProofRef::new(
            self.created,
            verification_method,
            self.proof_purpose,
            options,
            signature,
        )
    }

    pub fn try_cast_verification_method<
        N: 'a + Referencable,
        P: 'a + Referencable,
        T: 'a + Referencable,
    >(
        self,
    ) -> Result<UntypedProofRef<'a, N, P, T>, ProofCastError>
    where
        M::Reference<'a>: TryInto<N::Reference<'a>, Error = InvalidVerificationMethod>,
        O::Reference<'a>: TryInto<P::Reference<'a>>,
        S::Reference<'a>: TryInto<T::Reference<'a>>,
    {
        self.try_map_verification_method(|m, options, signature| {
            let n = m.try_cast()?;
            let options = options.try_into().map_err(|_| ProofCastError::Options)?;
            let signature = signature
                .try_into()
                .map_err(|_| ProofCastError::Signature)?;
            Ok((n, options, signature))
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProofCastError {
    #[error(transparent)]
    VerificationMethod(#[from] InvalidVerificationMethod),

    #[error("invalid options")]
    Options,

    #[error("invalid signature")]
    Signature,
}

impl From<ProofCastError> for VerificationError {
    fn from(value: ProofCastError) -> Self {
        match value {
            ProofCastError::VerificationMethod(iri) => {
                VerificationError::InvalidVerificationMethod(iri)
            }
            ProofCastError::Options => VerificationError::InvalidProofOptions,
            ProofCastError::Signature => VerificationError::InvalidSignature,
        }
    }
}
