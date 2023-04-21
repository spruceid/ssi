use std::marker::PhantomData;

use rdf_types::{Generator, Namespace, Object, Quad, TryExportQuad};
use ssi_vc::Verifiable;
use treeldr_rust_prelude::RdfIterator;

pub mod suite;

pub use suite::{CryptographicSuite, CryptographicSuiteInput, LinkedDataCryptographicSuite};

/// Linked Data capable credential.
pub trait LinkedDataCredential<C> {
    /// Iterator over the RDF quads defined by the credential.
    type Quads<'a>: Iterator<Item = Quad>
    where
        Self: 'a,
        C: 'a;

    /// Returns an iterator over the RDF quads defined by the credential.
    fn quads<'a>(&'a self, context: &'a mut C) -> Self::Quads<'a>;

    /// Puts the RDF graph in canonical form using URDNA2015.
    fn canonical_form(&self, context: &mut C) -> Vec<Quad> {
        let quads: Vec<_> = self.quads(context).collect();
        ssi_rdf::urdna2015::normalize(quads.iter().map(Quad::as_quad_ref)).collect()
    }
}

pub struct LinkedDataCredentialContext<'n, L, C, N, G> {
    namespace: &'n mut N,
    generator: G,
    lc: PhantomData<(L, C)>,
}

impl<'n, L, C, N, G> LinkedDataCredentialContext<'n, L, C, N, G> {
    pub fn new(namespace: &'n mut N, generator: G) -> Self {
        Self {
            namespace,
            generator,
            lc: PhantomData,
        }
    }
}

/// Any Verifiable Credential that can be interpreted as an RDF graph is a `LinkedDataCredential`.
impl<'n, N: 'n + Namespace, G: Generator<N>, L, C, T>
    LinkedDataCredential<LinkedDataCredentialContext<'n, L, C, N, G>> for T
where
    N: Namespace + TryExportQuad<N::Id, N::Id, Object<N::Id, L>, N::Id>,
    T: ssi_vc::schema::cred::VerifiableCredential<C> + treeldr_rust_prelude::rdf::Quads<N, L>,
{
    type Quads<'a> = ExportQuads<'a, N, L, G, <T as treeldr_rust_prelude::rdf::Quads<N, L>>::Quads<'a>>
    where
        Self: 'a,
        LinkedDataCredentialContext<'n, L, C, N, G>: 'a;

    fn quads<'a>(
        &'a self,
        context: &'a mut LinkedDataCredentialContext<'n, L, C, N, G>,
    ) -> Self::Quads<'_> {
        ExportQuads(self.rdf_quads(context.namespace, &mut context.generator, None))
    }
}

/// Wrappers that turns an RDF `Quad<N::Id, N::Id, Object<N::Id, L>, N::Id>` into a `Quad` iterator.
pub struct ExportQuads<
    'a,
    N: Namespace,
    L,
    G,
    I: RdfIterator<N, Item = Quad<N::Id, N::Id, Object<N::Id, L>, N::Id>>,
>(treeldr_rust_prelude::rdf::iter::Bound<'a, 'a, 'a, I, N, G>);

impl<'a, N, L, G, I> Iterator for ExportQuads<'a, N, L, G, I>
where
    N: Namespace + TryExportQuad<N::Id, N::Id, Object<N::Id, L>, N::Id>,
    G: Generator<N>,
    I: RdfIterator<N, Item = Quad<N::Id, N::Id, Object<N::Id, L>, N::Id>>,
{
    type Item = Quad;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.0.next() {
                Some(quad) => {
                    let namespace = self.0.namespace_mut();
                    if let Ok(quad) = namespace.try_export_quad(quad) {
                        break Some(quad);
                    }
                }
                None => break None,
            }
        }
    }
}

/// Error raised when a proof verification fails.
#[derive(Debug, thiserror::Error)]
#[error("invalid proof")]
pub struct InvalidProof;

pub enum ProofValidity {
    Valid,
    Invalid,
}

impl ProofValidity {
    pub fn into_result(self) -> Result<(), InvalidProof> {
        match self {
            Self::Valid => Ok(()),
            Self::Invalid => Err(InvalidProof),
        }
    }
}

impl From<bool> for ProofValidity {
    fn from(value: bool) -> Self {
        if value {
            Self::Valid
        } else {
            Self::Invalid
        }
    }
}

impl From<ProofValidity> for bool {
    fn from(value: ProofValidity) -> Self {
        match value {
            ProofValidity::Valid => true,
            ProofValidity::Invalid => false,
        }
    }
}

pub enum Algorithm {
    /// Edwards-Curve Digital Signature Algorithm ([RFC8032]).
    ///
    /// [RFC8032]: <https://www.rfc-editor.org/rfc/rfc8032>
    EdDSA,
}

pub trait Signer {
    fn sign(&self, algorithm: Algorithm, bytes: &[u8]) -> Vec<u8>;
}

pub trait SignerProvider<M> {
    type Signer<'a>: Signer
    where
        Self: 'a;

    fn get_signer(&self, method: &M) -> Self::Signer<'_>;
}

/// Verifier.
pub trait Verifier {
    /// Verify the given `signed_bytes`, signed using the given `algorithm`,
    /// against the input `unsigned_bytes`.
    fn verify(&self, algorithm: Algorithm, unsigned_bytes: &[u8], signed_bytes: &[u8]) -> bool;
}

/// Verifier provider.
///
/// The implementor is in charge of retrieve verification methods as described
/// in <https://w3c.github.io/vc-data-integrity/#retrieve-verification-method>.
pub trait VerifierProvider<M> {
    /// Verifier type.
    type Verifier<'a>: Verifier
    where
        Self: 'a;

    /// Retrieve the verifier identified by the given verification `method`.
    fn get_verifier(&self, method: &M) -> Self::Verifier<'_>;
}

pub trait SignParams<M, S: CryptographicSuite<M>> {
    fn transform_params(&self) -> S::TransformationParameters;

    fn hash_params(&self) -> S::HashParameters;

    fn into_proof_params(self) -> S::ProofParameters;
}

/// Credential signing.
pub trait Sign<C>: Sized {
    fn sign<M, S: CryptographicSuite<M> + CryptographicSuiteInput<Self, M, C>>(
        self,
        suite: S,
        context: &mut C,
        signer_provider: &impl SignerProvider<M>,
        params: impl SignParams<M, S>,
    ) -> Result<Verifiable<Self, S::Proof>, (Self, S::Error)> {
        match suite.transform(context, &self, params.transform_params()) {
            Ok(transformed) => match suite.hash(transformed, params.hash_params()) {
                Ok(hash) => {
                    match suite.generate_proof(hash, signer_provider, params.into_proof_params()) {
                        Ok(proof) => Ok(Verifiable::new(self, proof)),
                        Err(e) => Err((self, e)),
                    }
                }
                Err(e) => Err((self, e)),
            },
            Err(e) => Err((self, e)),
        }
    }
}

impl<T: LinkedDataCredential<C>, C> Sign<C> for T {}

pub trait VerifyParams<M, S: CryptographicSuite<M>> {
    fn transform_params(&self) -> S::TransformationParameters;

    fn into_hash_params(self) -> S::HashParameters;
}

/// Credential verification.
pub trait Verify<T, P>: Sized {
    fn verify<M, C, S: CryptographicSuite<M, Proof = P> + CryptographicSuiteInput<T, M, C>>(
        &self,
        suite: S,
        context: &mut C,
        verifier_provider: &impl VerifierProvider<M>,
        params: impl VerifyParams<M, S>,
    ) -> Result<ProofValidity, S::Error>;
}

impl<T, P> Verify<T, P> for Verifiable<T, P> {
    fn verify<M, C, S: CryptographicSuite<M, Proof = P> + CryptographicSuiteInput<T, M, C>>(
        &self,
        suite: S,
        context: &mut C,
        verifier_provider: &impl VerifierProvider<M>,
        params: impl VerifyParams<M, S>,
    ) -> Result<ProofValidity, S::Error> {
        let transformed = suite.transform(context, self.credential(), params.transform_params())?;
        let hash = suite.hash(transformed, params.into_hash_params())?;
        suite.verify_proof(hash, verifier_provider, self.proof())
    }
}
