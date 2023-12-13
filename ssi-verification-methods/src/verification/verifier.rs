use crate::{
    ControllerProvider, Cow, EnsureAllowsVerificationMethod, ProofPurpose, Referencable,
    ReferenceOrOwnedRef, SignatureAlgorithm, VerificationError, VerificationMethod,
    VerificationMethodResolver,
};
use iref::Iri;
use pin_project::pin_project;
use ssi_core::futures::{RefFutureBinder, SelfRefFuture, UnboundedRefFuture};
use std::{future::Future, marker::PhantomData, pin::Pin, task};

/// Verifier.
pub trait Verifier<M: Referencable>: VerificationMethodResolver<M> + ControllerProvider {
    /// Verify the given `signature`, signed using the given `algorithm`,
    /// against the input `signing`.
    fn verify<'f, 'o: 'f, 'm: 'f, 's: 'f, A: SignatureAlgorithm<M>>(
        &'f self,
        algorithm: A,
        options: <A::Options as Referencable>::Reference<'o>,
        issuer: Option<&'f Iri>,
        method_reference: Option<ReferenceOrOwnedRef<'m, M>>,
        proof_purpose: ProofPurpose,
        signing_bytes: &'f [u8],
        signature: <A::Signature as Referencable>::Reference<'s>,
    ) -> Verify<'f, M, Self, A>
    where
        M: 'f + Referencable,
    {
        let resolution = self.resolve_verification_method(issuer, method_reference);

        Verify {
            verifier: self,
            options: <A::Options as Referencable>::apply_covariance(options),
            proof_purpose,
            data: Some(VerifyData {
                algorithm,
                signature: <A::Signature as Referencable>::apply_covariance(signature),
                signing_bytes,
            }),
            resolution,
            check_purpose: None,
        }
    }
}

#[pin_project]
pub struct Verify<'f, M: 'f + Referencable, V: 'f + ?Sized + Verifier<M>, A: SignatureAlgorithm<M>>
where
    A::Options: 'f,
{
    verifier: &'f V,

    options: <A::Options as Referencable>::Reference<'f>,

    proof_purpose: ProofPurpose,

    data: Option<VerifyData<'f, A, A::Signature>>,

    #[pin]
    resolution: V::ResolveVerificationMethod<'f>,

    #[pin]
    check_purpose: Option<SelfRefFuture<'f, UnboundedVerifyProofPurpose<M, V>>>,
}

struct UnboundedVerifyProofPurpose<M, C: ?Sized>(PhantomData<(M, C)>);

impl<'max, M: 'max + Referencable, C: 'max + ?Sized + ControllerProvider> UnboundedRefFuture<'max>
    for UnboundedVerifyProofPurpose<M, C>
{
    type Bound<'a> = VerifyProofPurpose<'a, M, C> where 'max: 'a;

    type Owned = Cow<'max, M>;

    type Output = Result<(), VerificationError>;
}

struct SetupVerifyProofPurpose<'a, V: ?Sized> {
    verifier: &'a V,
    proof_purpose: ProofPurpose,
}

impl<'max, M: 'max + Referencable, C: 'max + ?Sized + ControllerProvider>
    RefFutureBinder<'max, UnboundedVerifyProofPurpose<M, C>> for SetupVerifyProofPurpose<'max, C>
where
    M: VerificationMethod,
{
    fn bind<'a>(context: Self, method: &'a Cow<'max, M>) -> VerifyProofPurpose<'a, M, C>
    where
        'max: 'a,
    {
        match method.controller() {
            Some(controller_id) => {
                VerifyProofPurpose::Pending(context.verifier.ensure_allows_verification_method(
                    controller_id,
                    method.id(),
                    context.proof_purpose,
                ))
            }
            None => VerifyProofPurpose::Ok(PhantomData),
        }
    }
}

struct VerifyData<'f, A, S: 'f + Referencable> {
    algorithm: A,

    signature: S::Reference<'f>,

    signing_bytes: &'f [u8],
}

#[pin_project(project = VerifyProofPurposeProj)]
enum VerifyProofPurpose<'a, M: 'a + Referencable, V: 'a + ?Sized + ControllerProvider> {
    Ok(PhantomData<M>),
    Pending(#[pin] EnsureAllowsVerificationMethod<'a, V>),
}

impl<'a, M: 'a + Referencable, V: 'a + ?Sized + ControllerProvider> Future
    for VerifyProofPurpose<'a, M, V>
{
    type Output = Result<(), VerificationError>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        match self.project() {
            VerifyProofPurposeProj::Ok(_) => task::Poll::Ready(Ok(())),
            VerifyProofPurposeProj::Pending(f) => f.poll(cx),
        }
    }
}

impl<'f, M: 'f + Referencable, V: 'f + ?Sized + Verifier<M>, A: SignatureAlgorithm<M>> Future
    for Verify<'f, M, V, A>
where
    M: VerificationMethod,
{
    type Output = Result<bool, VerificationError>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let mut this = self.project();

        if this.check_purpose.is_none() {
            match this.resolution.poll(cx) {
                task::Poll::Pending => return task::Poll::Pending,
                task::Poll::Ready(Ok(method)) => this.check_purpose.set(Some(SelfRefFuture::new(
                    method,
                    SetupVerifyProofPurpose {
                        verifier: *this.verifier,
                        proof_purpose: *this.proof_purpose,
                    },
                ))),
                task::Poll::Ready(Err(e)) => return task::Poll::Ready(Err(e.into())),
            }
        }

        let check_purpose = this.check_purpose.as_pin_mut().unwrap();
        check_purpose.poll(cx).map(|(check_result, method)| {
            check_result.and_then(|()| {
                let data = this.data.take().unwrap();
                data.algorithm.verify(
                    *this.options,
                    data.signature,
                    method.as_reference(),
                    data.signing_bytes,
                )
            })
        })
    }
}
