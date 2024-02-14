/// Verifiable Claims.
pub trait VerifiableClaims {
    type Proof;

    fn proof(&self) -> &Self::Proof;
}

pub trait Validate {
    /// Validates the claims.
    ///
    /// Validation consists in verifying that the claims themselves are
    /// consistent and valid with regard to the verification environment.
    /// For instance, checking that a credential's expiration date is not in the
    /// past, or the issue date not in the future.
    ///
    /// Validation may fail even if the credential or presentation's proof is
    /// successfully verified.
    ///
    /// You do not need to call this method yourself when verifying a
    /// credential or presentation. It is automatically called by
    /// [`VerifiableWith::verify_with`].
    ///
    /// If you need to implement this function, you can simply reuse
    /// [`Credential::is_valid`] or [`Presentation::is_valid`].
    fn is_valid(&self) -> bool;
}

/// Proof extraction trait.
///
/// Implemented by credential and presentation types that can be separated from
/// their proof value(s).
pub trait ExtractProof: Sized + VerifiableClaims {
    type Proofless;

    fn extract_proof(self) -> (Self::Proofless, Self::Proof);
}

pub trait MergeWithProof<P> {
    type WithProofs;

    fn merge_with_proof(self, proof: P) -> Self::WithProofs;
}

/// Proof type.
pub trait Proof {
    /// Prepared proof type.
    type Prepared;
}

impl<P: Proof> Proof for Vec<P> {
    type Prepared = Vec<P::Prepared>;
}

pub trait PrepareWith<T, E = ()>: Proof {
    type Error;

    #[allow(async_fn_in_trait)]
    async fn prepare_with(
        self,
        value: &T,
        environment: &mut E,
    ) -> Result<Self::Prepared, Self::Error>;
}

impl<T, E, P: PrepareWith<T, E>> PrepareWith<T, E> for Vec<P> {
    type Error = P::Error;

    async fn prepare_with(
        self,
        value: &T,
        environment: &mut E,
    ) -> Result<Self::Prepared, Self::Error> {
        let mut prepared = Vec::with_capacity(self.len());

        for p in self {
            prepared.push(p.prepare_with(value, environment).await?)
        }

        Ok(prepared)
    }
}

pub trait UnprepareProof {
    type Unprepared: Proof<Prepared = Self>;

    fn unprepare(self) -> Self::Unprepared;
}

impl<P: UnprepareProof> UnprepareProof for Vec<P> {
    type Unprepared = Vec<P::Unprepared>;

    fn unprepare(self) -> Self::Unprepared {
        self.into_iter().map(P::unprepare).collect()
    }
}

/// Proof of claims.
pub trait VerifyClaimsWith<T, V> {
    /// Error that can occur during verification.
    type Error;

    /// Verifies the input claim's proof using the given verifier.
    #[allow(async_fn_in_trait)]
    async fn verify_claims_with<'a>(
        &'a self,
        claims: &'a T,
        verifier: &'a V,
    ) -> Result<ProofValidity, Self::Error>;
}

impl<T, V, P: VerifyClaimsWith<T, V>> VerifyClaimsWith<T, V> for Vec<P> {
    type Error = P::Error;

    async fn verify_claims_with<'a>(
        &'a self,
        claims: &'a T,
        verifier: &'a V,
    ) -> Result<ProofValidity, Self::Error> {
        if self.is_empty() {
            // No proof.
            Ok(ProofValidity::Invalid)
        } else {
            for p in self {
                if p.verify_claims_with(claims, verifier).await?.is_invalid() {
                    return Ok(ProofValidity::Invalid);
                }
            }

            Ok(ProofValidity::Valid)
        }
    }
}

/// Error raised when a proof verification fails.
#[derive(Debug, thiserror::Error)]
#[error("invalid proof")]
pub struct InvalidProof;

/// Result of claims verification.
pub enum ProofValidity {
    /// The proof is valid.
    Valid,

    /// The proof is invalid.
    Invalid,
}

impl ProofValidity {
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }

    pub fn is_invalid(&self) -> bool {
        matches!(self, Self::Invalid)
    }

    pub fn into_result(self) -> Result<(), InvalidProof> {
        match self {
            Self::Valid => Ok(()),
            Self::Invalid => Err(InvalidProof),
        }
    }
}

impl From<bool> for ProofValidity {
    fn from(value: bool) -> Self {
        if value {
            Self::Valid
        } else {
            Self::Invalid
        }
    }
}

impl From<ProofValidity> for bool {
    fn from(value: ProofValidity) -> Self {
        match value {
            ProofValidity::Valid => true,
            ProofValidity::Invalid => false,
        }
    }
}
