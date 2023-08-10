use pin_project::pin_project;
use rdf_types::{
    interpretation::TraversableInterpretation, BlankIdVocabularyMut, ReverseTermInterpretation,
    ReverseTermInterpretationMut,
};
use ssi_core::futures::{RefFutureBinder, SelfRefFuture, UnboundedRefFuture};
use ssi_rdf::DatasetWithEntryPoint;
use ssi_vc::Verifiable;
use ssi_verification_methods::{Referencable, SignatureError, Signer, VerificationMethodRef};
use std::{future::Future, hash::Hash, marker::PhantomData, pin::Pin, task};

use crate::{
    suite::{CryptographicSuiteInput, GenerateProof, HashError},
    CryptographicSuite, DataIntegrity, ProofConfiguration, UntypedProof,
};

#[derive(Debug, thiserror::Error)]
pub enum Error<T> {
    #[error("missing credential")]
    MissingCredentialId,

    #[error("input transformation failed: {0}")]
    Transform(T),

    #[error("hash failed: {0}")]
    HashFailed(#[from] HashError),

    #[error("proof generation failed: {0}")]
    ProofGenerationFailed(#[from] SignatureError),
}

impl<C: Sync, S: CryptographicSuite> DataIntegrity<C, S> {
    fn prepare_ld_signature<'a, V, I>(
        vocabulary: &'a mut V,
        interpretation: &'a mut I,
        credential: &C,
        suite: S,
        params: &ProofConfiguration<S::VerificationMethod>,
    ) -> Result<(S, S::Hashed), Error<S::TransformError>>
    where
        V: BlankIdVocabularyMut,
        I: TraversableInterpretation + ReverseTermInterpretationMut<BlankId = V::BlankId>,
        I::Resource: Eq + Hash,
        C: treeldr_rust_prelude::rdf::Quads<V, I>,
        S: CryptographicSuiteInput<DatasetWithEntryPoint<'a, V, I>>,
    {
        // Convert the `credential` to an RDF dataset.
        let (entry_point, quads) = credential.rdf_quads(vocabulary, interpretation, None);
        let dataset = quads.collect();

        // Assign a term to all resources.
        let mut generator =
            rdf_types::generator::Blank::new_with_prefix("_ssi-vc-ldp_".to_string());
        interpretation.assign_terms(|interpretation, id| {
            if interpretation.has_term(id) {
                None
            } else {
                Some(rdf_types::Term::Id(rdf_types::Id::Blank(
                    vocabulary.insert_owned_blank_id(generator.next_blank_id()),
                )))
            }
        });

        // Prepare the dataset for the crypto suite.
        let data = DatasetWithEntryPoint {
            vocabulary,
            interpretation,
            dataset,
            entry_point: entry_point.ok_or(Error::MissingCredentialId)?,
        };

        // Apply the crypto suite.
        let transformed = suite
            .transform(data, params.borrowed())
            .map_err(Error::Transform)?;
        let hash = suite.hash(transformed, params.borrowed())?;

        Ok((suite, hash))
    }

    /// Sign the given Linked Data credential with a Data Integrity
    /// cryptographic suite.
    //
    // # Why is this not an `async` function?
    //
    // For some reason the Rust compiler is unable to build a future that
    // returns a value of type `Verifiable<DataIntegrity<C, S>>`.
    // See: <https://github.com/rust-lang/rust/issues/103532>
    pub fn sign_ld<'max, 'a, V, I, T>(
        vocabulary: &'a mut V,
        interpretation: &'a mut I,
        signer: &'max T,
        credential: C,
        suite: S,
        params: ProofConfiguration<S::VerificationMethod>,
        options: S::Options,
    ) -> SignLinkedData<'max, C, S, T, S::TransformError>
    where
        V: BlankIdVocabularyMut,
        I: TraversableInterpretation + ReverseTermInterpretationMut<BlankId = V::BlankId>,
        I::Resource: Eq + Hash,
        C: treeldr_rust_prelude::rdf::Quads<V, I>,
        S: 'max + CryptographicSuiteInput<DatasetWithEntryPoint<'a, V, I>>,
        T: Signer<S::VerificationMethod, S::SignatureProtocol>,
    {
        let inner = match Self::prepare_ld_signature(
            vocabulary,
            interpretation,
            &credential,
            suite,
            &params,
        ) {
            Ok((suite, hash)) => {
                let sign = SelfRefFuture::new(
                    hash,
                    Binder {
                        suite: &suite,
                        params,
                        options,
                        signer,
                    },
                );

                SignLinkedDataInner::Ok(SignLinkedDataOk {
                    payload: Some((credential, suite)),
                    sign,
                    e: PhantomData,
                })
            }
            Err(e) => SignLinkedDataInner::Err(Some(e)),
        };

        SignLinkedData { inner }
    }
}

struct UnboundedGenerateProof<S, T>(PhantomData<(S, T)>);

impl<
        'max,
        S: CryptographicSuite,
        T: 'max + Signer<S::VerificationMethod, S::SignatureProtocol>,
    > UnboundedRefFuture<'max> for UnboundedGenerateProof<S, T>
where
    S::Hashed: 'max,
    S::VerificationMethod: 'max,
    S::Signature: 'max,
{
    type Owned = S::Hashed;

    type Bound<'a> = GenerateProof<'a, S, T> where 'max: 'a;

    type Output = Result<UntypedProof<S::VerificationMethod, S::Signature>, SignatureError>;
}

struct Binder<'s, 'a, S: CryptographicSuite, T> {
    suite: &'s S,
    params: ProofConfiguration<S::VerificationMethod>,
    options: S::Options,
    signer: &'a T,
}

impl<
        's,
        'max,
        S: CryptographicSuite,
        T: 'max + Signer<S::VerificationMethod, S::SignatureProtocol>,
    > RefFutureBinder<'max, UnboundedGenerateProof<S, T>> for Binder<'s, 'max, S, T>
where
    S::Hashed: 'max,
    S::VerificationMethod: 'max,
    S::Signature: 'max,
{
    fn bind<'a>(context: Self, hash: &'a S::Hashed) -> GenerateProof<'a, S, T>
    where
        'max: 'a,
    {
        context
            .suite
            .generate_proof(hash, context.signer, context.params, context.options)
    }
}

/// Future returned by the [`DataIntegrity::sign_ld`] method.
//
// # Why write the future by hand?
//
// For some reason the Rust compiler is unable to build a future that
// returns a value of type `Verifiable<DataIntegrity<C, S>>`.
// See: <https://github.com/rust-lang/rust/issues/103532>
#[pin_project]
pub struct SignLinkedData<'max, C, S, T, E>
where
    S: CryptographicSuite,
    S::VerificationMethod: 'max,
    T: 'max + Signer<S::VerificationMethod, S::SignatureProtocol>,
{
    #[pin]
    inner: SignLinkedDataInner<'max, C, S, T, E>,
}

impl<'max, C, S, T, E> Future for SignLinkedData<'max, C, S, T, E>
where
    S: CryptographicSuite,
    S::VerificationMethod: 'max,
    T: 'max + Signer<S::VerificationMethod, S::SignatureProtocol>,
    for<'m> <S::VerificationMethod as Referencable>::Reference<'m>: VerificationMethodRef<'m>, // TODO find a way to hide that bound, if possible.
{
    type Output = Result<Verifiable<DataIntegrity<C, S>>, Error<E>>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = self.project();
        this.inner.poll(cx)
    }
}

/// Private implementation of the `SignLinkedData` type.
#[pin_project(project = SignLinkedDataInnerProj)]
enum SignLinkedDataInner<'max, C, S, T, E>
where
    S: CryptographicSuite,
    S::VerificationMethod: 'max,
    T: 'max + Signer<S::VerificationMethod, S::SignatureProtocol>,
{
    Err(Option<Error<E>>),
    Ok(#[pin] SignLinkedDataOk<'max, C, S, T, E>),
}

impl<'max, C, S, T, E> Future for SignLinkedDataInner<'max, C, S, T, E>
where
    S: CryptographicSuite,
    S::VerificationMethod: 'max,
    T: 'max + Signer<S::VerificationMethod, S::SignatureProtocol>,
    for<'m> <S::VerificationMethod as Referencable>::Reference<'m>: VerificationMethodRef<'m>,
{
    type Output = Result<Verifiable<DataIntegrity<C, S>>, Error<E>>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        match self.project() {
            SignLinkedDataInnerProj::Ok(f) => f.poll(cx),
            SignLinkedDataInnerProj::Err(e) => task::Poll::Ready(Err(e.take().unwrap())),
        }
    }
}

/// Private implementation of the `SignLinkedData` type, with the signature
/// preparation succeded.
#[pin_project]
struct SignLinkedDataOk<'max, C, S, T, E>
where
    S: CryptographicSuite,
    S::Hashed: 'max,
    S::VerificationMethod: 'max,
    S::Signature: 'max,
    T: 'max + Signer<S::VerificationMethod, S::SignatureProtocol>,
{
    payload: Option<(C, S)>,

    #[pin]
    sign: SelfRefFuture<'max, UnboundedGenerateProof<S, T>>,

    e: PhantomData<E>,
}

impl<'max, C, S, T, E> Future for SignLinkedDataOk<'max, C, S, T, E>
where
    S: CryptographicSuite,
    S::VerificationMethod: 'max,
    T: 'max + Signer<S::VerificationMethod, S::SignatureProtocol>,
    for<'m> <S::VerificationMethod as Referencable>::Reference<'m>: VerificationMethodRef<'m>,
{
    type Output = Result<Verifiable<DataIntegrity<C, S>>, Error<E>>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = self.project();

        this.sign.poll(cx).map(|(result, hash)| {
            result
                .map(|proof| {
                    let (data, suite) = this.payload.take().unwrap();
                    Verifiable::new(DataIntegrity::new(data, hash), proof.into_typed(suite))
                })
                .map_err(Into::into)
        })
    }
}
