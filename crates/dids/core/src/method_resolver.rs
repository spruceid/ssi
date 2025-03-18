use crate::{
    document::Document,
    resolution::{self, DerefError},
    DidResolver, DID, DIDURL,
};
use ssi_crypto::Verifier;
use ssi_verification_methods_core::{
    Accept, ControllerError, ControllerProvider, ProofPurposes, VerificationMethodInterpreter,
};

#[derive(Debug, Default)]
pub struct DidVerificationMethodResolver<T, I> {
    resolver: T,
    interpreter: I,
    options: resolution::Options,
}

impl<T, I> DidVerificationMethodResolver<T, I> {
    pub fn new(resolver: T, interpreter: I) -> Self {
        Self {
            resolver,
            options: resolution::Options::default(),
            interpreter,
        }
    }

    pub fn new_with_options(resolver: T, interpreter: I, options: resolution::Options) -> Self {
        Self {
            resolver,
            interpreter,
            options,
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

impl<T: DidResolver, I> DidResolver for DidVerificationMethodResolver<T, I> {
    async fn resolve_representation<'a>(
        &'a self,
        did: &'a DID,
        options: resolution::Options,
    ) -> Result<resolution::Output<Vec<u8>>, resolution::Error> {
        T::resolve_representation(&self.resolver, did, options).await
    }
}

impl<T: DidResolver, I> ControllerProvider for DidVerificationMethodResolver<T, I> {
    type Controller<'a>
        = Document
    where
        Self: 'a;

    async fn get_controller<'a>(
        &'a self,
        id: &'a iref::Iri,
    ) -> Result<Option<Document>, ControllerError> {
        if id.scheme().as_str() == "did" {
            match DID::new(id.as_bytes()) {
                Ok(did) => match self.resolver.resolve_with(did, self.options.clone()).await {
                    Ok(output) => Ok(Some(output.document.into_document())),
                    Err(resolution::Error::NotFound) => Ok(None),
                    Err(e) => Err(ControllerError::internal(e)),
                },
                Err(_) => Err(ControllerError::Invalid),
            }
        } else {
            Err(ControllerError::Invalid)
        }
    }
}

impl<T: DidResolver, I: VerificationMethodInterpreter> Verifier
    for DidVerificationMethodResolver<T, I>
{
    type VerifyingKey = I::VerifyingKey;

    async fn get_verifying_key_with(
        &self,
        id: Option<&[u8]>,
        options: &ssi_crypto::Options,
    ) -> Result<Option<Self::VerifyingKey>, ssi_crypto::Error> {
        let mut deref_options = self.options.clone();

        if let Some(Accept(vm_types)) = options.get() {
            if let Some(ty) = vm_types.first() {
                deref_options.parameters.public_key_format = Some(ty.as_ref().to_owned());
            }
        }

        let Some(id) = id else { return Ok(None) };

        let Ok(did_url) = DIDURL::new(id) else {
            return Ok(None);
        };

        let deref = match self.resolver.dereference_with(did_url, deref_options).await {
            Ok(deref) => deref,
            Err(DerefError::NotFound) => return Ok(None),
            Err(e) => return Err(ssi_crypto::Error::internal(e)),
        };

        let vm = deref
            .content
            .into_verification_method()
            .map_err(|_| ssi_crypto::Error::KeyInvalid)?;

        self.interpreter.interpret(vm.into()).map(Some)
    }
}
