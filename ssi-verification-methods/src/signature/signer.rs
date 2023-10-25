use iref::Iri;
use std::future::Future;

pub mod single_secret;

pub use single_secret::SingleSecretSigner;

use crate::{Referencable, ReferenceOrOwnedRef, SignatureAlgorithm, SignatureError};

/// Verification method signer.
/// 
/// `M` is the verification method type.
/// `B` is the cryptographic signature algorithm to be used with the verification method.
/// `P` is the signature protocol.
pub trait Signer<M: Referencable, B, P> {
    type Sign<'a, A: SignatureAlgorithm<M, MessageSignatureAlgorithm = B, Protocol = P>>: 'a
        + Future<Output = Result<A::Signature, SignatureError>>
    where
        Self: 'a,
        M: 'a,
        A: 'a,
        A::Signature: 'a;

    fn sign<'a, 'o: 'a, 'm: 'a, A: SignatureAlgorithm<M, MessageSignatureAlgorithm = B, Protocol = P>>(
        &'a self,
        algorithm: A,
        options: <A::Options as Referencable>::Reference<'o>,
        issuer: Option<&'a Iri>,
        method: Option<ReferenceOrOwnedRef<'m, M>>,
        bytes: &'a [u8],
    ) -> Self::Sign<'a, A>
    where
        A: 'a,
        A::Signature: 'a;
}
