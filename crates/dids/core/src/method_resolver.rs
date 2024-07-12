use std::{borrow::Cow, marker::PhantomData};

use crate::{document::Document, resolution, DIDResolver, DID, DIDURL};
use iref::Iri;
use ssi_claims_core::ProofValidationError;
use ssi_jwk::{JWKResolver, JWK};
use ssi_verification_methods_core::{
    ControllerError, ControllerProvider, GenericVerificationMethod, InvalidVerificationMethod,
    MaybeJwkVerificationMethod, ProofPurposes, ReferenceOrOwnedRef, VerificationMethod,
    VerificationMethodResolutionError, VerificationMethodResolver, VerificationMethodSet,
};

pub struct VerificationMethodDIDResolver<T, M> {
    resolver: T,
    options: resolution::Options,
    method: PhantomData<M>,
}

impl<T: Default, M> Default for VerificationMethodDIDResolver<T, M> {
    fn default() -> Self {
        Self::new(T::default())
    }
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

impl<T: DIDResolver, M> DIDResolver for VerificationMethodDIDResolver<T, M> {
    async fn resolve_representation<'a>(
        &'a self,
        did: &'a DID,
        options: resolution::Options,
    ) -> Result<resolution::Output<Vec<u8>>, resolution::Error> {
        T::resolve_representation(&self.resolver, did, options).await
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

    async fn resolve_verification_method_with(
        &self,
        _issuer: Option<&iref::Iri>,
        method: Option<ReferenceOrOwnedRef<'_, M>>,
        options: ssi_verification_methods_core::ResolutionOptions,
    ) -> Result<Cow<M>, VerificationMethodResolutionError> {
        let mut deref_options = self.options.clone();

        if let Some(set) = options.accept {
            if let Some(ty) = set.pick() {
                deref_options.parameters.public_key_format = Some(ty.to_owned());
            }
        }

        match method {
            Some(method) => {
                if method.id().scheme().as_str() == "did" {
                    match DIDURL::new(method.id().as_bytes()) {
                        Ok(url) => {
                            match self.resolver.dereference_with(url, deref_options).await {
                                Ok(deref) => match deref.content.into_verification_method() {
                                    Ok(any_method) => {
                                        Ok(Cow::Owned(M::try_from(any_method.into())?))
                                    }
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

impl<T: DIDResolver, M> JWKResolver for VerificationMethodDIDResolver<T, M>
where
    M: MaybeJwkVerificationMethod
        + VerificationMethodSet
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

        let options = ssi_verification_methods_core::ResolutionOptions {
            accept: Some(Box::new(M::type_set())),
        };

        self.resolve_verification_method_with(None, vm, options)
            .await?
            .try_to_jwk()
            .map(Cow::into_owned)
            .map(Cow::Owned)
            .ok_or(ProofValidationError::MissingPublicKey)
    }
}
