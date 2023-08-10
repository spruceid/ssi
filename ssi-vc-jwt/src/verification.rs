use std::{future::Future, pin::Pin, task};

use pin_project::pin_project;
use ssi_jwk::JWK;
use ssi_vc::{ProofValidity, VerifiableWith};
use ssi_verification_methods::{
    covariance_rule, ProofPurpose, Referencable, ReferenceOrOwnedRef, VerificationError,
    VerificationMethod, VerificationMethodRef, Verifier,
};
use treeldr_rust_prelude::iref::{Iri, IriBuf};

use crate::{
    signing::{VcJwtSignatureAlgorithm, VcJwtSignatureRef},
    Proof, VcJwt,
};

impl<C: Sync> VerifiableWith for VcJwt<C> {
    type Proof = Proof;
    type Method = AnyJwkMethod;

    type VerifyWith<'a, V: 'a + Verifier<Self::Method>> = VerifyWith<'a, V> where Self: 'a;

    fn verify_with<'a, V: Verifier<Self::Method>>(
        &'a self,
        verifier: &'a V,
        proof: &'a Proof,
    ) -> Self::VerifyWith<'a, V> {
        let signature = VcJwtSignatureRef {
            header: &self.header,
            signature_bytes: &proof.signature,
        };

        VerifyWith(verifier.verify(
            VcJwtSignatureAlgorithm::default(),
            proof.issuer.id(),
            proof.issuer.method_reference(),
            ProofPurpose::Assertion,
            &self.payload,
            signature,
        ))
    }
}

#[pin_project]
pub struct VerifyWith<'a, V: Verifier<AnyJwkMethod>>(
    #[pin] ssi_verification_methods::Verify<'a, AnyJwkMethod, V, VcJwtSignatureAlgorithm>,
);

impl<'a, V: Verifier<AnyJwkMethod>> Future for VerifyWith<'a, V> {
    type Output = Result<ProofValidity, VerificationError>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = self.project();
        this.0.poll(cx).map_ok(Into::into)
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
    fn id(&self) -> Iri<'_> {
        self.id.as_iri()
    }

    fn controller(&self) -> Option<Iri<'_>> {
        self.controller.as_ref().map(IriBuf::as_iri)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AnyJwkMethodRef<'a> {
    pub id: Iri<'a>,

    pub controller: Option<Iri<'a>>,

    pub public_key_jwk: &'a JWK,
}

impl<'a> VerificationMethodRef<'a> for AnyJwkMethodRef<'a> {
    fn id(&self) -> Iri<'a> {
        self.id
    }

    fn controller(&self) -> Option<Iri<'a>> {
        self.controller
    }
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

    pub fn id(&self) -> Option<Iri> {
        self.id.as_ref().map(IriBuf::as_iri)
    }

    pub fn method_reference(&self) -> Option<ReferenceOrOwnedRef<AnyJwkMethod>> {
        let key_id = self.key_id.as_deref()?;
        Some(ReferenceOrOwnedRef::Reference(Iri::new(key_id).ok()?))
    }
}
