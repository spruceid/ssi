//! Data Integrity BBS Cryptosuite 2023 (v1.0) implementation.
//! 
//! See: <https://www.w3.org/TR/vc-di-bbs/#bbs-2023>
use ssi_claims_core::{ProofValidationError, ProofValidity, SignatureError};
use ssi_verification_methods::Multikey;
use ssi_data_integrity_core::{suite::{standard::{HashingAlgorithm, HashingError, SignatureAlgorithm, SignatureAndVerificationAlgorithm, TransformationAlgorithm, TransformationError, TransformedData, TypedTransformationAlgorithm, VerificationAlgorithm}, ConfigurationAlgorithm, ConfigurationError, InputOptions}, ProofConfiguration, ProofConfigurationRef, ProofRef, StandardCryptographicSuite, TypeRef};

/// The `bbs-2023` cryptographic suite.
#[derive(Debug, Clone, Copy)]
pub struct Bbs2023;

impl StandardCryptographicSuite for Bbs2023 {
	type Configuration = Bbs2023Configuration;

	type Transformation = Bbs2023Transformation;

	type Hashing = Bbs2023Hashing;

	type VerificationMethod = Multikey;

	type ProofOptions = Bbs2023Options;

	type SignatureAlgorithm = Bbs2023SignatureAlgorithm;

	fn type_(&self) -> TypeRef {
		TypeRef::DataIntegrityProof("bbs-2023")
	}
}

pub struct Bbs2023InputOptions {
	pub mandatory_pointers: Vec<MandatoryPointer>,

	pub feature_option: FeatureOption,

	pub commitment_with_proof: Option<Vec<u8>>,

	pub proof_options: Bbs2023Options
}

pub struct MandatoryPointer;

#[derive(Debug, Default, Clone, Copy)]
pub enum FeatureOption {
	#[default]
	Baseline,
	AnonymousHolderBinding,
	PseudonymIssuerPid,
	PseudonymHidderPid
}

/// Base Proof Configuration.
/// 
/// See: <https://www.w3.org/TR/vc-di-bbs/#base-proof-configuration-bbs-2023>
pub struct Bbs2023Configuration;

impl ConfigurationAlgorithm<Bbs2023> for Bbs2023Configuration {
	type InputSuiteOptions = Bbs2023InputOptions;
	type InputVerificationMethod = Multikey;

	fn configure(
		_: &Bbs2023,
		options: InputOptions<Bbs2023>,
	) -> Result<ProofConfiguration<Bbs2023>, ConfigurationError> {
		todo!()
	}
}

pub struct Bbs2023Transformation;

impl TransformationAlgorithm<Bbs2023> for Bbs2023Transformation {
	type Output = Transformed;
}

impl<T, C> TypedTransformationAlgorithm<Bbs2023, T, C> for Bbs2023Transformation {
async fn transform(
		context: &mut C,
		data: &T,
		options: ProofConfigurationRef<'_, Bbs2023>,
	) -> Result<Self::Output, TransformationError> {
		todo!()
	}
}

pub struct Transformed;

pub struct Bbs2023Hashing;

impl HashingAlgorithm<Bbs2023> for Bbs2023Hashing {
	type Output = Hashed;

	fn hash(
		input: TransformedData<Bbs2023>,
		proof_configuration: ProofConfigurationRef<Bbs2023>,
	) -> Result<Self::Output, HashingError> {
		todo!()
	}
}

pub struct Hashed;

pub struct Bbs2023Options;

pub struct Bbs2023SignatureAlgorithm;

impl SignatureAndVerificationAlgorithm for Bbs2023SignatureAlgorithm {
	type Signature = Bbs2023Signature;
}

impl<T> SignatureAlgorithm<Bbs2023, T> for Bbs2023SignatureAlgorithm {
	async fn sign(
		verification_method: &Multikey,
		signer: T,
		prepared_claims: &Hashed,
		proof_configuration: ProofConfigurationRef<'_, Bbs2023>,
	) -> Result<Self::Signature, SignatureError> {
		todo!()
	}
}

impl VerificationAlgorithm<Bbs2023> for Bbs2023SignatureAlgorithm {
	fn verify(
		method: &Multikey,
		prepared_claims: &Hashed,
		proof: ProofRef<Bbs2023>,
	) -> Result<ProofValidity, ProofValidationError> {
		todo!()
	}
}

pub struct Bbs2023Signature;

impl AsRef<str> for Bbs2023Signature {
	fn as_ref(&self) -> &str {
		todo!()
	}
}