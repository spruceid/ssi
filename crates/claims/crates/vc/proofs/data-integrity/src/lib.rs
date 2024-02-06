//! Data Integrity Proofs format for Verifiable Credentals.

// mod decode;
pub mod eip712;
mod proof;
// mod serialization;
pub mod signing;
pub mod suite;
pub mod verification;

// pub use decode::*;
pub use proof::*;
pub use signing::sign;
pub use suite::{CryptographicSuite, CryptographicSuiteInput, LinkedDataInput};

// #[derive(Debug, thiserror::Error)]
// pub enum Error {
//     #[error("input transformation failed: {0}")]
//     Transform(#[from] TransformError),

//     #[error("hash failed: {0}")]
//     HashFailed(#[from] HashError),
// }

// /// Data Integrity credential.
// #[derive(Educe, serde::Serialize, linked_data::Serialize)]
// #[educe(Clone(bound = "T: Clone, S::Hashed: Clone"))]
// #[serde(transparent)]
// pub struct DataIntegrity<T, S: CryptographicSuite> {
//     /// Credential value.
//     #[ld(flatten)]
//     value: T,

//     /// Hashed value.
//     #[serde(skip)]
//     #[ld(ignore)]
//     hash: S::Hashed,
// }

// impl<T, S: CryptographicSuite> DataIntegrity<T, S> {
//     /// Creates a new data integrity credential from the given input data.
//     ///
//     /// This will transform and hash the input data using the cryptographic
//     /// suite's transformation and hashing algorithms.
//     pub async fn new<'a, 'c: 'a, X: 'a>(
//         input: T,
//         mut context: X,
//         suite: &'a S,
//         params: ProofConfigurationRef<'c, S::VerificationMethod, S::Options>,
//     ) -> Result<Self, Error>
//     where
//         T: 'a,
//         S: CryptographicSuiteInput<T, X>,
//     {
//         let params = params.shorten_lifetime();
//         let transformed = suite.transform(&input, &mut context, params).await?;

//         let hashed = suite.hash(transformed, params)?;

//         Ok(Self::new_hashed(input, hashed))
//     }

//     pub fn new_hashed(credential: T, hashed: S::Hashed) -> Self {
//         Self {
//             value: credential,
//             hash: hashed,
//         }
//     }

//     pub fn value(&self) -> &T {
//         &self.value
//     }

//     pub fn hashed(&self) -> &S::Hashed {
//         &self.hash
//     }

//     pub fn into_value(self) -> T {
//         self.value
//     }

//     pub fn into_hashed(self) -> S::Hashed {
//         self.hash
//     }

//     pub fn into_parts(self) -> (T, S::Hashed) {
//         (self.value, self.hash)
//     }

//     pub async fn map<'a, 'c: 'a, U: 'a, X: 'a>(
//         self,
//         context: X,
//         suite: &'a S,
//         params: ProofConfigurationRef<'c, S::VerificationMethod, S::Options>,
//         f: impl FnOnce(T) -> U,
//     ) -> Result<DataIntegrity<U, S>, Error>
//     where
//         S: CryptographicSuiteInput<U, X>,
//     {
//         DataIntegrity::new(f(self.value), context, suite, params).await
//     }
// }

// impl<T, S: CryptographicSuite> Deref for DataIntegrity<T, S> {
//     type Target = T;

//     fn deref(&self) -> &Self::Target {
//         &self.value
//     }
// }

// /// Reference to Data Integrity claims with a proof.
// ///
// /// Used to serialize a credential/presentation.
// #[derive(linked_data::Serialize)]
// #[ld(prefix("sec" = "https://w3id.org/security#"))]
// struct DataIntegrityWithProof<'a, T, S: CryptographicSuite> {
//     #[ld(flatten)]
//     claims: &'a DataIntegrity<T, S>,

//     #[ld("sec:proof", graph)]
//     proof: &'a Proof<S>,
// }
