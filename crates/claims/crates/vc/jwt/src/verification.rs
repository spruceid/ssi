use iref::{Iri, IriBuf};
use ssi_claims_core::{ProofValidity, VerifiableWith};
use ssi_core::{covariance_rule, Referencable};
use ssi_jwk::JWK;
use ssi_verification_methods::{
    ProofPurpose, ReferenceOrOwnedRef, VerificationError, VerificationMethod, Verifier,
};

use crate::{
    signing::{VcJwtSignatureAlgorithm, VcJwtSignatureRef},
    Proof, VcJwt,
};

impl<C, V> VerifiableWith<V> for VcJwt<C>
where
    V: Verifier<AnyJwkMethod>,
{
    type Error = VerificationError;

    async fn verify_with<'a>(
        &'a self,
        verifier: &'a V,
        proof: &'a Proof,
    ) -> Result<ProofValidity, VerificationError> {
        let signature = VcJwtSignatureRef {
            header: &self.header,
            signature_bytes: &proof.signature,
        };

        verifier
            .verify(
                VcJwtSignatureAlgorithm::default(),
                (),
                proof.issuer.id(),
                proof.issuer.method_reference(),
                ProofPurpose::Assertion,
                &self.payload,
                signature,
            )
            .await
            .map(Into::into)
    }
}

pub struct AnyJwkMethod {
    /// Key identifier.
    pub id: IriBuf,

    /// Key controller, if any.
    pub controller: Option<IriBuf>,

    /// Public key.
    pub public_key_jwk: Box<JWK>,
}

impl Referencable for AnyJwkMethod {
    type Reference<'a> = AnyJwkMethodRef<'a>;

    fn as_reference(&self) -> Self::Reference<'_> {
        AnyJwkMethodRef {
            id: self.id.as_iri(),
            controller: self.controller.as_ref().map(IriBuf::as_iri),
            public_key_jwk: &self.public_key_jwk,
        }
    }

    covariance_rule!();
}

impl VerificationMethod for AnyJwkMethod {
    fn id(&self) -> &Iri {
        self.id.as_iri()
    }

    fn controller(&self) -> Option<&Iri> {
        self.controller.as_ref().map(IriBuf::as_iri)
    }

    fn ref_id(r: Self::Reference<'_>) -> &Iri {
        r.id
    }

    fn ref_controller(r: Self::Reference<'_>) -> Option<&Iri> {
        r.controller
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AnyJwkMethodRef<'a> {
    pub id: &'a Iri,

    pub controller: Option<&'a Iri>,

    pub public_key_jwk: &'a JWK,
}

/// Issuer.
pub struct Issuer {
    /// Issuer URI.
    pub id: Option<IriBuf>,

    /// Key identifier.
    pub key_id: Option<String>,
}

impl Issuer {
    pub fn new(id: Option<IriBuf>, key_id: Option<String>) -> Self {
        Self { id, key_id }
    }

    pub fn id(&self) -> Option<&Iri> {
        self.id.as_ref().map(IriBuf::as_iri)
    }

    pub fn method_reference(&self) -> Option<ReferenceOrOwnedRef<AnyJwkMethod>> {
        let key_id = self.key_id.as_deref()?;
        Some(ReferenceOrOwnedRef::Reference(Iri::new(key_id).ok()?))
    }
}
