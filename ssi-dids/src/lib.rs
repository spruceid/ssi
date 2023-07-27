//! # Decentralized Identifiers (DIDs)
//!
//! As specified by [Decentralized Identifiers (DIDs) v1.0 - Core architecture,
//! data model, and representations][did-core].
//!
//! [did-core]: https://www.w3.org/TR/did-core/
mod did;
pub mod document;
pub mod resolution;

use async_trait::async_trait;
pub use did::*;
pub use document::Document;
pub use resolution::DIDResolver;
use ssi_verification_methods::VerificationMethodRef;

pub struct Provider<T> {
    resolver: T,
    options: resolution::Options,
}

impl ssi_verification_methods::Controller for Document {
    fn allows_verification_method(
        &self,
        id: iref::Iri,
        proof_purposes: ssi_crypto::ProofPurposes,
    ) -> bool {
        DIDURL::new(id.as_bytes()).is_ok_and(|url| {
            self.verification_relationships
                .contains(&self.id, url, proof_purposes)
        })
    }
}

#[async_trait]
impl<T: Send + DIDResolver> ssi_verification_methods::ControllerProvider for Provider<T> {
    type Controller<'a> = Document where Self: 'a;

    async fn get_controller(
        &self,
        id: iref::Iri<'_>,
    ) -> Result<Option<Self::Controller<'_>>, ssi_verification_methods::ControllerError> {
        if id.scheme() == "did" {
            match DID::new(id.as_bytes()) {
                Ok(did) => match self.resolver.resolve(did, self.options.clone()).await {
                    Ok(output) => Ok(Some(output.document.into_document())),
                    Err(resolution::Error::NotFound) => Ok(None),
                    Err(e) => Err(ssi_verification_methods::ControllerError::InternalError(
                        Box::new(e),
                    )),
                },
                Err(_) => Err(ssi_verification_methods::ControllerError::Invalid),
            }
        } else {
            Err(ssi_verification_methods::ControllerError::Invalid)
        }
    }
}

#[async_trait]
impl<T: Send + DIDResolver, M> ssi_crypto::Verifier<ssi_verification_methods::Reference<M>>
    for Provider<T>
where
    M: Send
        + Sync
        + TryFrom<document::AnyVerificationMethod>
        + ssi_verification_methods::VerificationMethod,
    M::Error: Send,
    for<'a> M::Context<'a>: Send,
    for<'a> M::Reference<'a>: Send + ssi_verification_methods::VerificationMethodRef<'a, M>,
    for<'a> <M::Signature as ssi_crypto::Signature>::Reference<'a>: Send,
{
    async fn verify<'c, 'm, 's>(
        &self,
        context: M::Context<'c>,
        method: ssi_verification_methods::ReferenceRef<'m, M>,
        proof_purpose: ssi_crypto::ProofPurpose,
        signing_bytes: &[u8],
        signature: <M::Signature as ssi_crypto::Signature>::Reference<'s>,
    ) -> Result<bool, ssi_crypto::VerificationError>
    where
        M: 'async_trait,
    {
        if method.iri().scheme() == "did" {
            match DIDURL::new(method.iri().as_bytes()) {
                Ok(url) => {
                    let options = self.options.clone().into();
                    match self.resolver.dereference(url, &options).await {
                        Ok(deref) => {
                            match deref.content.into_verification_method() {
                                Ok(any_method) => match M::try_from(any_method) {
                                    Ok(m) => {
                                        m.verify(
                                            self,
                                            context,
                                            proof_purpose,
                                            signing_bytes,
                                            signature,
                                        )
                                        .await
                                    }
                                    Err(_) => {
                                        // Wrong verification method type, or invalid method data.
                                        Err(ssi_crypto::VerificationError::InvalidKeyId(
                                            method.iri().to_string(),
                                        ))
                                    }
                                },
                                Err(_) => {
                                    // The IRI is not referring to a verification method.
                                    Err(ssi_crypto::VerificationError::InvalidKeyId(
                                        method.iri().to_string(),
                                    ))
                                }
                            }
                        }
                        Err(e) => {
                            // Dereferencing failed for some reason.
                            Err(ssi_crypto::VerificationError::InternalError(Box::new(e)))
                        }
                    }
                }
                Err(_) => {
                    // The IRI is not a valid DID URL.
                    Err(ssi_crypto::VerificationError::InvalidKeyId(
                        method.iri().to_string(),
                    ))
                }
            }
        } else {
            // Not a DID scheme.
            Err(ssi_crypto::VerificationError::UnsupportedKeyId(
                method.iri().to_string(),
            ))
        }
    }
}

#[async_trait]
impl<T: Send + DIDResolver, M> ssi_crypto::Verifier<ssi_verification_methods::ReferenceOrOwned<M>>
    for Provider<T>
where
    M: Send
        + Sync
        + TryFrom<document::AnyVerificationMethod>
        + ssi_verification_methods::VerificationMethod,
    M::Error: Send,
    for<'a> M::Context<'a>: Send,
    for<'a> M::Reference<'a>: Send + ssi_verification_methods::VerificationMethodRef<'a, M>,
    for<'a> <M::Signature as ssi_crypto::Signature>::Reference<'a>: Send,
{
    async fn verify<'c: 'async_trait, 'm: 'async_trait, 's: 'async_trait>(
        &self,
        context: M::Context<'c>,
        method: ssi_verification_methods::ReferenceOrOwnedRef<'m, M>,
        proof_purpose: ssi_crypto::ProofPurpose,
        signing_bytes: &[u8],
        signature: <M::Signature as ssi_crypto::Signature>::Reference<'s>,
    ) -> Result<bool, ssi_crypto::VerificationError>
    where
        M: 'async_trait,
    {
        match method {
            ssi_verification_methods::ReferenceOrOwnedRef::Reference(r) => {
                <Self as ssi_crypto::Verifier<ssi_verification_methods::Reference<M>>>::verify(
                    self,
                    context,
                    r,
                    proof_purpose,
                    signing_bytes,
                    signature,
                )
                .await
            }
            ssi_verification_methods::ReferenceOrOwnedRef::Owned(m) => {
                // No need to dereference.
                m.verify(self, context, proof_purpose, signing_bytes, signature)
                    .await
            }
        }
    }
}
