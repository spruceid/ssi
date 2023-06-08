use crate::{Verifiable, VerifiableWith};
use async_trait::async_trait;

/// Verifiable Credential decoder.
///
/// There exists multiple formats that encode VCs. For instance, VCs can be
/// encoded as JSON Web Tokens using a `vc` claim containing the VC data.
/// Another way is to use the Data Integrity mechanism that embeds the proof
/// inside the VC data.
///
/// Decoders are used to transform an input VC document in a given format into
/// a `Verifiable<C, P>` containing the VC data (`C`) and the proof (`P`).
#[async_trait]
pub trait Decoder<N, T> {
    type Credential: VerifiableWith<Self::Proof>;
    type Proof;

    type Error;

    async fn decode(
        &mut self,
        namespace: &mut N,
        document: T,
    ) -> Result<Verifiable<Self::Credential, Self::Proof>, Self::Error>;
}
