use std::{marker::PhantomData, ops::Deref};

use ssi_claims_core::{Verifiable, VerifiableWith};

use crate::{CredentialOrPresentation, VerifiableCredentialOrPresentation};

/// Proof extraction trait.
/// 
/// Implemented by credential and presentation types that can be separated from
/// their proof value(s).
pub trait ExtractProofs: Sized + VerifiableCredentialOrPresentation {
	type Proofless;

	fn extract_proofs(self) -> (Self::Proofless, Vec<Self::Proof>);
}

/// Proof type.
pub trait ProofType {
	/// Prepared proof type.
	type Prepared;
}

pub trait PrepareWith<T, E>: ProofType {
	type Error;

	#[allow(async_fn_in_trait)]
	async fn prepare_with(self, value: &T, environment: &mut E) -> Result<Self::Prepared, Self::Error>;
}

/// Prepared verifiable credential or presentation.
pub struct Claims<T, P> {
	/// Credential or presentation without the proof.
	value: T,

	/// Prepared proofs.
	proofs: PhantomData<P>
}

impl<T, P> Deref for Claims<T, P> {
	type Target = T;

	fn deref(&self) -> &Self::Target {
		&self.value
	}
}

pub enum PreparationError<I, P> {
	InvalidProof(I),
	ProofPreparationFailed(P)
}

/// Verifiable credential (or presentation) claims, without the proof.
impl<T, P> Claims<T, P> {
	pub fn from_proofless(value: T) -> Self {
		Self {
			value,
			proofs: PhantomData
		}
	}

	pub async fn new<U, E>(value: U, mut environment: E) -> Result<Verifiable<Self>, PreparationError<<U::Proof as TryInto<P>>::Error, P::Error>>
	where
		U: ExtractProofs<Proofless = T>,
		U::Proof: TryInto<P>,
		P: ProofType,
		P: PrepareWith<T, E>
	{
		let (value, raw_proofs) = value.extract_proofs();
		
		let mut proofs = Vec::with_capacity(raw_proofs.len());
		for p in raw_proofs {
			let unprepared_proof: P = p.try_into().map_err(PreparationError::InvalidProof)?;
			proofs.push(unprepared_proof.prepare_with(&value, &mut environment).await.map_err(PreparationError::ProofPreparationFailed)?)
		}

		Ok(Verifiable::new(
			Self::from_proofless(value),
			proofs
		))
	}
}

impl<T, P> ssi_claims_core::Provable for Claims<T, P>
where
	P: ProofType
{
	type Proof = Vec<P::Prepared>;
}

impl<T, P, V> VerifiableWith<V> for Claims<T, P>
where
	T: CredentialOrPresentation,
	P: ProofType,
	P::Prepared: VerifyPreparedWith<V>
{
	type Error = <P::Prepared as VerifyPreparedWith<V>>::Error;

	async fn verify_with<'a>(
		&'a self,
		verifier: &'a V,
		proof: &'a Self::Proof,
	) -> Result<ssi_claims_core::ProofValidity, Self::Error> {
		if !self.is_valid() {
			// The proof is invalidated by impossible claims.
			return Ok(ssi_claims_core::ProofValidity::Invalid)
		}

		if proof.is_empty() {
			// No proof means no valid proof.
			return Ok(ssi_claims_core::ProofValidity::Invalid)
		}

		for p in proof {
			if p.verify_prepared_with(verifier).await?.is_invalid() {
				return Ok(ssi_claims_core::ProofValidity::Invalid)
			}
		}

		Ok(ssi_claims_core::ProofValidity::Valid)
	}
}

pub trait VerifyPreparedWith<V> {
	type Error;

	#[allow(async_fn_in_trait)]
	async fn verify_prepared_with<'a>(
		&'a self,
		verifier: &'a V,
	) -> Result<ssi_claims_core::ProofValidity, Self::Error>;
}