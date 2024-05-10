use std::{borrow::Cow, marker::PhantomData};

use crate::{document::Document, resolution, DIDResolver, DID, DIDURL};
use iref::Iri;
use ssi_claims_core::ProofValidationError;
use ssi_jwk::JWK;
use ssi_jws::JWSVerifier;
use ssi_verification_methods_core::{
    ControllerError, ControllerProvider, GenericVerificationMethod, InvalidVerificationMethod,
    MaybeJwkVerificationMethod, ProofPurposes, ReferenceOrOwnedRef, VerificationMethod,
    VerificationMethodCow, VerificationMethodResolutionError, VerificationMethodResolver,
};

pub struct VerificationMethodDIDResolver<T, M> {
    resolver: T,
    options: resolution::Options,
    method: PhantomData<M>,
}

impl<T, M> VerificationMethodDIDResolver<T, M> {
    pub fn new(resolver: T) -> Self {
        Self {
            resolver,
            options: resolution::Options::default(),
            method: PhantomData,
        }
    }

    pub fn new_with_options(resolver: T, options: resolution::Options) -> Self {
        Self {
            resolver,
            options,
            method: PhantomData,
        }
    }

    pub fn resolver(&self) -> &T {
        &self.resolver
    }

    pub fn options(&self) -> &resolution::Options {
        &self.options
    }
}

impl ssi_verification_methods_core::Controller for Document {
    fn allows_verification_method(&self, id: &iref::Iri, proof_purposes: ProofPurposes) -> bool {
        DIDURL::new(id.as_bytes()).is_ok_and(|url| {
            self.verification_relationships
                .contains(&self.id, url, proof_purposes)
        })
    }
}

impl<T: DIDResolver, M> ControllerProvider for VerificationMethodDIDResolver<T, M> {
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
                    Err(e) => Err(ControllerError::InternalError(e.to_string())),
                },
                Err(_) => Err(ControllerError::Invalid),
            }
        } else {
            Err(ControllerError::Invalid)
        }
    }
}

// #[async_trait]
impl<T: DIDResolver, M> VerificationMethodResolver for VerificationMethodDIDResolver<T, M>
where
    M: VerificationMethod,
    M: TryFrom<GenericVerificationMethod, Error = InvalidVerificationMethod>,
{
    type Method = M;

    async fn resolve_verification_method<'a, 'm: 'a>(
        &'a self,
        _issuer: Option<&'a iref::Iri>,
        method: Option<ReferenceOrOwnedRef<'m, M>>,
    ) -> Result<VerificationMethodCow<'a, M>, VerificationMethodResolutionError> {
        match method {
            Some(method) => {
                if method.id().scheme().as_str() == "did" {
                    match DIDURL::new(method.id().as_bytes()) {
                        Ok(url) => {
                            match self.resolver.dereference(url).await {
                                Ok(deref) => match deref.content.into_verification_method() {
                                    Ok(any_method) => Ok(
                                        ssi_verification_methods_core::VerificationMethodCow::Owned(
                                            M::try_from(any_method.into())?,
                                        ),
                                    ),
                                    Err(_) => {
                                        // The IRI is not referring to a verification method.
                                        Err(VerificationMethodResolutionError::NotAVerificationMethod(
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

impl<T: DIDResolver, M> JWSVerifier for VerificationMethodDIDResolver<T, M>
where
    M: MaybeJwkVerificationMethod
        + TryFrom<GenericVerificationMethod, Error = InvalidVerificationMethod>,
{
    async fn fetch_public_jwk(
        &self,
        key_id: Option<&str>,
    ) -> Result<Cow<JWK>, ProofValidationError> {
        let vm = match key_id {
            Some(id) => match Iri::new(id) {
                Ok(iri) => Some(ReferenceOrOwnedRef::Reference(iri)),
                Err(_) => return Err(ProofValidationError::MissingPublicKey),
            },
            None => None,
        };

        self.resolve_verification_method(None, vm)
            .await?
            .try_to_jwk()
            .map(Cow::into_owned)
            .map(Cow::Owned)
            .ok_or(ProofValidationError::MissingPublicKey)
    }
}
