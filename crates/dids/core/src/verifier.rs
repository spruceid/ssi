use crate::{document::Document, resolution, DIDResolver, DID, DIDURL};
use ssi_verification_methods::{
    ControllerError, GenericVerificationMethod, InvalidVerificationMethod, ProofPurposes,
    ReferenceOrOwnedRef, VerificationMethodResolutionError,
};

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

impl<T: DIDResolver> ssi_verification_methods::ControllerProvider for DIDVerifier<T> {
    type Controller<'a> = Document where Self: 'a;

    async fn get_controller<'a>(
        &'a self,
        id: &'a iref::Iri,
    ) -> Result<Option<Document>, ControllerError> {
        if id.scheme().as_str() == "did" {
            match DID::new(id.as_bytes()) {
                Ok(did) => match self.resolver.resolve_with(did, self.options.clone()).await {
                    Ok(output) => Ok(Some(output.document.into_document())),
                    Err(resolution::Error::NotFound) => Ok(None),
                    Err(e) => Err(ssi_verification_methods::ControllerError::InternalError(
                        e.to_string(),
                    )),
                },
                Err(_) => Err(ssi_verification_methods::ControllerError::Invalid),
            }
        } else {
            Err(ssi_verification_methods::ControllerError::Invalid)
        }
    }
}

// #[async_trait]
impl<T: DIDResolver, M> ssi_verification_methods::VerificationMethodResolver<M> for DIDVerifier<T>
where
    M: ssi_verification_methods::VerificationMethod,
    M: TryFrom<GenericVerificationMethod, Error = InvalidVerificationMethod>,
{
    // type ResolveVerificationMethod<'a> = ResolveVerificationMethod<'a, M, T> where Self: 'a, M: 'a;

    async fn resolve_verification_method<'a, 'm: 'a>(
        &'a self,
        _issuer: Option<&'a iref::Iri>,
        method: Option<ReferenceOrOwnedRef<'m, M>>,
    ) -> Result<ssi_verification_methods::Cow<'a, M>, VerificationMethodResolutionError> {
        match method {
            Some(method) => {
                if method.id().scheme().as_str() == "did" {
                    match DIDURL::new(method.id().as_bytes()) {
                        Ok(url) => {
                            match self.resolver.dereference(url).await {
                                Ok(deref) => match deref.content.into_verification_method() {
                                    Ok(any_method) => Ok(ssi_verification_methods::Cow::Owned(
                                        M::try_from(any_method.into())?,
                                    )),
                                    Err(_) => {
                                        // The IRI is not referring to a verification method.
                                        Err(VerificationMethodResolutionError::InvalidKeyId(
                                            method.id().to_string(),
                                        ))
                                    }
                                },
                                Err(e) => {
                                    // Dereferencing failed for some reason.
                                    Err(VerificationMethodResolutionError::InternalError(
                                        e.to_string(),
                                    ))
                                }
                            }
                            // ResolveVerificationMethod::dereference(&self.resolver, url, options)
                        }
                        Err(_) => {
                            // The IRI is not a valid DID URL.
                            Err(VerificationMethodResolutionError::InvalidKeyId(
                                method.id().to_string(),
                            ))
                        }
                    }
                } else {
                    // Not a DID scheme.
                    Err(VerificationMethodResolutionError::UnsupportedKeyId(
                        method.id().to_string(),
                    ))
                }
            }
            None => Err(VerificationMethodResolutionError::MissingVerificationMethod),
        }
    }
}
