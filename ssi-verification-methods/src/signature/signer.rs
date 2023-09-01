use iref::Iri;
use std::future::Future;

pub mod single_secret;

pub use single_secret::SingleSecretSigner;

use crate::{Referencable, ReferenceOrOwnedRef, SignatureAlgorithm, SignatureError};

/// Verification method signer.
pub trait Signer<M: Referencable, P> {
    type Sign<'a, A: SignatureAlgorithm<M, Protocol = P>>: 'a
        + Future<Output = Result<A::Signature, SignatureError>>
    where
        Self: 'a,
        M: 'a,
        A: 'a,
        A::Signature: 'a;

    fn sign<'a, 'm: 'a, A: SignatureAlgorithm<M, Protocol = P>>(
        &'a self,
        algorithm: A,
        issuer: Option<&'a Iri>,
        method: Option<ReferenceOrOwnedRef<'m, M>>,
        bytes: &'a [u8],
    ) -> Self::Sign<'a, A>
    where
        A: 'a,
        A::Signature: 'a;
}
