use crate::CryptographicSuite;

use super::{StandardConfigurationAlgorithm, TransformationAlgorithm, TypedTransformationAlgorithm};

pub struct VerificationMethod;

pub struct BbsCryptosuite2023;

impl CryptographicSuite for BbsCryptosuite {
	// ...
}

pub struct Options;

/// Base Proof Configuration (bbs-2023)
/// 
/// See: <https://www.w3.org/TR/vc-di-bbs/#base-proof-configuration-bbs-2023>
pub struct BaseProofConfiguration;

impl StandardConfigurationAlgorithm<BbsCryptosuite2023> for BaseProofConfiguration {
	fn configure(options: Options) -> crate::ProofConfiguration<BbsCryptosuite2023> {
		todo!()
	}
}

/// Base Proof Transformation (bbs-2023)
/// 
/// See: <https://www.w3.org/TR/vc-di-bbs/#base-proof-transformation-bbs-2023>
pub struct BaseProofTransformation;

impl TransformationAlgorithm for BaseProofTransformation {
	type Options = TransformationOptions;

	type Output = TransformedData;
}

impl<T> TypedTransformationAlgorithm<T> for BaseProofTransformation {
	fn transform(
		&self,
		data: &T,
		options: Self::Options
	) -> Result<Self::Output, super::TransformationError> {
		todo!()
	}
}

pub struct TransformationOptions {
	pub verification_method: VerificationMethod,

	pub mendatory_pointers: Vec<JsonPointers>
}

pub struct JsonPointers;

pub struct TransformedData;