use ssi_claims_core::{SignatureError, Verifiable};
use ssi_json_ld::JsonLdNodeObject;
use ssi_verification_methods_core::{Signer, VerificationMethodResolver};

use crate::{sign, signing::sign_single, ExpandedConfigurationRef, Proof, ProofConfigurationRefExpansion, Proofs};

use super::{CryptographicSuite, TransformError};

pub trait CryptographicSuiteInput<T, C = ()>: CryptographicSuite {
    /// Transformation algorithm.
    #[allow(async_fn_in_trait)]
    async fn transform<'a, 'c: 'a>(
        &'a self,
        data: &'a T,
        context: &'a mut C,
        params: ExpandedConfigurationRef<'c, Self>,
    ) -> Result<Self::Transformed, TransformError>
    where
        C: 'a;

    #[allow(async_fn_in_trait)]
    async fn sign<'max, R, S>(
        &self,
        input: T,
        context: C,
        resolver: &'max R,
        signer: &'max S,
        params: Self::InputOptions,
    ) -> Result<Verifiable<T, Proofs<Self>>, SignatureError>
    where
        Self::VerificationMethod: 'max,
        T: JsonLdNodeObject,
        R: 'max + VerificationMethodResolver<Method = Self::VerificationMethod>,
        S: 'max
            + Signer<
                Self::VerificationMethod,
                Self::MessageSignatureAlgorithm
            >,
        C: for<'a> ProofConfigurationRefExpansion<'a, Self>,
    {
        sign(input, context, resolver, signer, self, params).await
    }

    #[allow(async_fn_in_trait)]
    async fn sign_single<'max, R, S>(
        &self,
        input: T,
        context: C,
        resolver: &'max R,
        signer: &'max S,
        params: Self::InputOptions,
    ) -> Result<Verifiable<T, Proof<Self>>, SignatureError>
    where
        Self::VerificationMethod: 'max,
        T: JsonLdNodeObject,
        R: 'max + VerificationMethodResolver<Method = Self::VerificationMethod>,
        S: 'max
            + Signer<
                Self::VerificationMethod,
                Self::MessageSignatureAlgorithm
            >,
        C: for<'a> ProofConfigurationRefExpansion<'a, Self>,
    {
        sign_single(input, context, resolver, signer, self, params).await
    }
}