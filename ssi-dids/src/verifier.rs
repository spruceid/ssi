use crate::{
    document::Document,
    resolution::{self, DerefError, DerefOptions, DerefOutput, Dereference, Resolve},
    DIDResolver, DID, DIDURL,
};
use pin_project::pin_project;
use ssi_core::futures::{RefFutureBinder, SelfRefFuture, UnboundedRefFuture};
use ssi_verification_methods::{
    ControllerError, GenericVerificationMethod, InvalidVerificationMethod, ProofPurposes,
    Referencable, ReferenceOrOwnedRef, VerificationMethodRef, VerificationMethodResolutionError,
};
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::task;

pub struct DIDVerifier<T> {
    resolver: T,
    options: resolution::Options,
}

impl<T> DIDVerifier<T> {
    pub fn new(resolver: T) -> Self {
        Self {
            resolver,
            options: resolution::Options::default(),
        }
    }

    pub fn new_with_options(resolver: T, options: resolution::Options) -> Self {
        Self { resolver, options }
    }

    pub fn resolver(&self) -> &T {
        &self.resolver
    }

    pub fn options(&self) -> &resolution::Options {
        &self.options
    }
}

impl ssi_verification_methods::Controller for Document {
    fn allows_verification_method(&self, id: &iref::Iri, proof_purposes: ProofPurposes) -> bool {
        DIDURL::new(id.as_bytes()).is_ok_and(|url| {
            self.verification_relationships
                .contains(&self.id, url, proof_purposes)
        })
    }
}

#[pin_project]
pub struct GetController<'a, T: ?Sized + DIDResolver> {
    #[pin]
    inner: GetControllerInner<'a, T>,
}

impl<'a, T: ?Sized + DIDResolver> GetController<'a, T> {
    fn pending(resolve: Resolve<'a, T>) -> Self {
        Self {
            inner: GetControllerInner::Pending(resolve),
        }
    }

    fn err(e: ControllerError) -> Self {
        Self {
            inner: GetControllerInner::Err(Some(e)),
        }
    }
}

impl<'a, T: ?Sized + DIDResolver> Future for GetController<'a, T> {
    type Output = Result<Option<Document>, ControllerError>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = self.project();
        match this.inner.project() {
            GetControllerProj::Pending(f) => f.poll(cx).map(|result| match result {
                Ok(output) => Ok(Some(output.document.into_document())),
                Err(resolution::Error::NotFound) => Ok(None),
                Err(e) => Err(ssi_verification_methods::ControllerError::InternalError(
                    e.to_string(),
                )),
            }),
            GetControllerProj::Err(e) => task::Poll::Ready(Err(e.take().unwrap())),
        }
    }
}

#[pin_project(project = GetControllerProj)]
enum GetControllerInner<'a, T: ?Sized + DIDResolver> {
    Pending(#[pin] Resolve<'a, T>),
    Err(Option<ControllerError>),
}

impl<T: DIDResolver> ssi_verification_methods::ControllerProvider for DIDVerifier<T> {
    type Controller<'a> = Document where Self: 'a;

    type GetController<'a> = GetController<'a, T> where Self: 'a;

    fn get_controller<'a>(&'a self, id: &'a iref::Iri) -> Self::GetController<'_> {
        if id.scheme().as_str() == "did" {
            match DID::new(id.as_bytes()) {
                Ok(did) => GetController::pending(self.resolver.resolve(did, self.options.clone())),
                Err(_) => GetController::err(ssi_verification_methods::ControllerError::Invalid),
            }
        } else {
            GetController::err(ssi_verification_methods::ControllerError::Invalid)
        }
    }
}

#[pin_project]
pub struct ResolveVerificationMethod<'a, M: 'a + Referencable, T: ?Sized + DIDResolver> {
    #[pin]
    inner: ResolveVerificationMethodInner<'a, T>,
    m: PhantomData<&'a M>,
}

impl<'a, M: 'a + Referencable, T: ?Sized + DIDResolver> ResolveVerificationMethod<'a, M, T> {
    fn dereference(resolver: &'a T, url: &'a DIDURL, options: DerefOptions) -> Self {
        Self {
            inner: ResolveVerificationMethodInner::Pending {
                method_id: url,
                dereference: SelfRefFuture::new(options, SetupDereference { resolver, url }),
            },
            m: PhantomData,
        }
    }

    fn err(e: VerificationMethodResolutionError) -> Self {
        Self {
            inner: ResolveVerificationMethodInner::Err(Some(e)),
            m: PhantomData,
        }
    }
}

impl<'a, M: 'a + Referencable, T: ?Sized + DIDResolver> Future
    for ResolveVerificationMethod<'a, M, T>
where
    M: TryFrom<GenericVerificationMethod, Error = InvalidVerificationMethod>,
{
    type Output = Result<ssi_verification_methods::Cow<'a, M>, VerificationMethodResolutionError>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = self.project();
        match this.inner.project() {
            ResolveVerificationMethodProj::Pending {
                method_id,
                dereference,
            } => {
                dereference.poll(cx).map(|(result, _)| match result {
                    Ok(deref) => match deref.content.into_verification_method() {
                        Ok(any_method) => Ok(ssi_verification_methods::Cow::Owned(M::try_from(
                            any_method.into(),
                        )?)),
                        Err(_) => {
                            // The IRI is not referring to a verification method.
                            Err(VerificationMethodResolutionError::InvalidKeyId(
                                method_id.to_string(),
                            ))
                        }
                    },
                    Err(e) => {
                        // Dereferencing failed for some reason.
                        Err(VerificationMethodResolutionError::InternalError(
                            e.to_string(),
                        ))
                    }
                })
            }
            ResolveVerificationMethodProj::Err(e) => task::Poll::Ready(Err(e.take().unwrap())),
        }
    }
}

#[pin_project(project = ResolveVerificationMethodProj)]
enum ResolveVerificationMethodInner<'a, T: 'a + ?Sized + DIDResolver> {
    Pending {
        method_id: &'a DIDURL,

        #[pin]
        dereference: SelfRefFuture<'a, UnboundedDereference<T>>,
    },
    Err(Option<VerificationMethodResolutionError>),
}

struct UnboundedDereference<T: ?Sized>(PhantomData<T>);

impl<'max, T: 'max + ?Sized + DIDResolver> UnboundedRefFuture<'max> for UnboundedDereference<T> {
    type Bound<'a> = Dereference<'a, T> where 'max: 'a;

    type Owned = DerefOptions;

    type Output = Result<DerefOutput, DerefError>;
}

struct SetupDereference<'a, T: ?Sized> {
    resolver: &'a T,
    url: &'a DIDURL,
}

impl<'max, T: 'max + ?Sized + DIDResolver> RefFutureBinder<'max, UnboundedDereference<T>>
    for SetupDereference<'max, T>
{
    fn bind<'a>(context: Self, options: &'a DerefOptions) -> Dereference<'a, T>
    where
        'max: 'a,
    {
        context.resolver.dereference(context.url, options)
    }
}

impl<T: DIDResolver, M> ssi_verification_methods::Verifier<M> for DIDVerifier<T>
where
    M: ssi_verification_methods::VerificationMethod,
    for<'a> M::Reference<'a>: VerificationMethodRef<'a>,
    M: TryFrom<GenericVerificationMethod, Error = InvalidVerificationMethod>,
{
}

// #[async_trait]
impl<T: DIDResolver, M> ssi_verification_methods::VerificationMethodResolver<M> for DIDVerifier<T>
where
    M: ssi_verification_methods::VerificationMethod,
    for<'a> M::Reference<'a>: VerificationMethodRef<'a>,
    M: TryFrom<GenericVerificationMethod, Error = InvalidVerificationMethod>,
{
    type ResolveVerificationMethod<'a> = ResolveVerificationMethod<'a, M, T> where Self: 'a, M: 'a;

    fn resolve_verification_method<'a, 'm: 'a>(
        &'a self,
        _issuer: Option<&'a iref::Iri>,
        method: Option<ReferenceOrOwnedRef<'m, M>>,
    ) -> Self::ResolveVerificationMethod<'a> {
        match method {
            Some(method) => {
                if method.id().scheme().as_str() == "did" {
                    match DIDURL::new(method.id().as_bytes()) {
                        Ok(url) => {
                            let options = self.options.clone().into();
                            ResolveVerificationMethod::dereference(&self.resolver, url, options)
                        }
                        Err(_) => {
                            // The IRI is not a valid DID URL.
                            ResolveVerificationMethod::err(
                                VerificationMethodResolutionError::InvalidKeyId(
                                    method.id().to_string(),
                                ),
                            )
                        }
                    }
                } else {
                    // Not a DID scheme.
                    ResolveVerificationMethod::err(
                        VerificationMethodResolutionError::UnsupportedKeyId(
                            method.id().to_string(),
                        ),
                    )
                }
            }
            None => ResolveVerificationMethod::err(
                VerificationMethodResolutionError::MissingVerificationMethod,
            ),
        }
    }
}
