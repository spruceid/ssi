pub mod single_secret;

pub use single_secret::SingleSecretSigner;
use ssi_crypto::{MessageSigner, SignatureProtocol};

use crate::Referencable;

/// Verification method signer.
///
/// `M` is the verification method type.
/// `B` is the cryptographic signature algorithm to be used with the verification method.
/// `P` is the signature protocol.
pub trait Signer<M: Referencable, A, P: SignatureProtocol<A> = ()> {
    type MessageSigner<'a>: MessageSigner<A, P>
    where
        Self: 'a,
        M: 'a;

    #[allow(async_fn_in_trait)]
    async fn for_method<'a>(&'a self, method: M::Reference<'a>) -> Option<Self::MessageSigner<'a>>;
}
