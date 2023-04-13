//! Cryptographic suites.

pub struct Options;

/// Verifiable credential proof.
pub struct Proof;

/// Error raised when a proof verification fails.
pub struct InvalidProof;

/// Cryptographic suite.
pub trait CryptographicSuite<T> {
	type Transformed;
	type Hashed;

	/// Transformation algorithm.
	fn transform(&self, data: T, options: Options) -> Self::Transformed;

	/// Hashing algorithm.
	fn hash(&self, data: Self::Transformed, options: Options) -> Self::Hashed;

	fn generate_proof(&self, data: Self::Hashed, options: Options) -> Proof;

	fn verify_proof(&self, data: Self::Hashed, proof: Proof) -> Result<(), InvalidProof>;
}