use ssi_jwk::algorithm;

mod jws;
pub use jws::*;

mod multibase;
pub use multibase::*;

pub trait AlgorithmSelection<M, O>: Sized {
    fn select_algorithm(verification_method: &M, options: &O) -> Option<Self>;
}

impl<M: ssi_verification_methods_core::JwkVerificationMethod, O> AlgorithmSelection<M, O>
    for algorithm::Algorithm
{
    fn select_algorithm(verification_method: &M, _options: &O) -> Option<Self> {
        verification_method.to_jwk().get_algorithm()
    }
}

impl<M, O> AlgorithmSelection<M, O> for algorithm::ES256KR {
    fn select_algorithm(_verification_method: &M, _options: &O) -> Option<Self> {
        Some(Self)
    }
}

impl<M, O> AlgorithmSelection<M, O> for algorithm::ES256K {
    fn select_algorithm(_verification_method: &M, _options: &O) -> Option<Self> {
        Some(Self)
    }
}

impl<M, O> AlgorithmSelection<M, O> for algorithm::ES256 {
    fn select_algorithm(_verification_method: &M, _options: &O) -> Option<Self> {
        Some(Self)
    }
}

impl<M, O> AlgorithmSelection<M, O> for algorithm::EdDSA {
    fn select_algorithm(_verification_method: &M, _options: &O) -> Option<Self> {
        Some(Self)
    }
}

impl<M, O> AlgorithmSelection<M, O> for algorithm::EdBlake2b {
    fn select_algorithm(_verification_method: &M, _options: &O) -> Option<Self> {
        Some(Self)
    }
}

impl<M, O> AlgorithmSelection<M, O> for algorithm::ESBlake2b {
    fn select_algorithm(_verification_method: &M, _options: &O) -> Option<Self> {
        Some(Self)
    }
}

pub trait AlterSignature {
    fn alter(&mut self);
}
