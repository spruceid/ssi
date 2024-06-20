use std::{borrow::Cow, marker::PhantomData};

use ssi_verification_methods::{InvalidVerificationMethod, VerificationMethod};

pub struct AnyResolver<R, M>(R, PhantomData<M>);

impl<R, M> AnyResolver<R, M> {
    pub fn new(resolver: R) -> Self {
        Self(resolver, PhantomData)
    }
}

impl<R, M> ssi_verification_methods::VerificationMethodResolver for AnyResolver<R, M>
where
    R: ssi_verification_methods::VerificationMethodResolver<
        Method = ssi_verification_methods::AnyMethod,
    >,
    M: VerificationMethod
        + TryFrom<ssi_verification_methods::AnyMethod, Error = InvalidVerificationMethod>
        + Into<ssi_verification_methods::AnyMethod>,
{
    type Method = M;

    async fn resolve_verification_method_with(
        &self,
        issuer: Option<&iref::Iri>,
        method: Option<ssi_verification_methods::ReferenceOrOwnedRef<'_, Self::Method>>,
        options: ssi_verification_methods::ResolutionOptions,
    ) -> Result<Cow<Self::Method>, ssi_verification_methods::VerificationMethodResolutionError>
    {
        let method = method.map(|m| match m {
            ssi_verification_methods::ReferenceOrOwnedRef::Reference(uri) => {
                ssi_verification_methods::ReferenceOrOwned::Reference(uri.to_owned())
            }
            ssi_verification_methods::ReferenceOrOwnedRef::Owned(m) => {
                ssi_verification_methods::ReferenceOrOwned::Owned(m.clone().into())
            }
        });

        let any_method = self
            .0
            .resolve_verification_method_with(
                issuer,
                method.as_ref().map(|m| m.borrowed()),
                options,
            )
            .await?
            .into_owned();
        any_method.try_into().map(Cow::Owned).map_err(
            ssi_verification_methods::VerificationMethodResolutionError::InvalidVerificationMethod,
        )
    }
}
