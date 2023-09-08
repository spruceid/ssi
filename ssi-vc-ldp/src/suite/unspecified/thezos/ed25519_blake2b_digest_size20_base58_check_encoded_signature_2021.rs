use std::marker::PhantomData;
use std::pin::Pin;
use std::task;

use futures::Future;
use linked_data::LinkedData;
use pin_project::pin_project;
use ssi_core::futures::{RefFutureBinder, SelfRefFuture, UnboundedRefFuture};
use ssi_crypto::{MessageSignatureError, MessageSigner};
use ssi_jwk::{Algorithm, JWK};
use ssi_verification_methods::{
    covariance_rule, Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021, Referencable,
    SignatureError, VerificationError,
};
use static_iref::iri;

use crate::{
    impl_rdf_input_urdna2015,
    suite::{sha256_hash, HashError, JwsSignature, JwsSignatureRef},
    CryptographicSuite, ProofConfigurationRef,
};

/// Proof type used with [did:tz](https://github.com/spruceid/did-tezos/) `tz1` addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021;

impl_rdf_input_urdna2015!(Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021);

impl CryptographicSuite for Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021 {
    type Transformed = String;
    type Hashed = [u8; 64];

    type VerificationMethod = Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021;

    type Signature = JwsSignature;

    type SignatureProtocol = ();

    type SignatureAlgorithm = SignatureAlgorithm;

    type Options = Options;

    fn iri(&self) -> &iref::Iri {
        iri!("https://w3id.org/security#Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021")
    }

    fn cryptographic_suite(&self) -> Option<&str> {
        None
    }

    fn hash(
        &self,
        data: String,
        proof_configuration: ProofConfigurationRef<Self::VerificationMethod, Self::Options>,
    ) -> Result<Self::Hashed, HashError> {
        Ok(sha256_hash(data.as_bytes(), self, proof_configuration))
    }

    fn setup_signature_algorithm(&self) -> Self::SignatureAlgorithm {
        SignatureAlgorithm
    }
}

pub struct SignatureAlgorithm;

impl
    ssi_verification_methods::SignatureAlgorithm<
        Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021,
    > for SignatureAlgorithm
{
    type Options = Options;

    type Signature = JwsSignature;

    type Protocol = ();

    type Sign<'a, S: 'a + MessageSigner<Self::Protocol>> = SignWith<'a, S>;

    fn sign<'a, S: 'a + MessageSigner<Self::Protocol>>(
        &self,
        options: OptionsRef<'a>,
        _method: &Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021,
        bytes: &'a [u8],
        signer: S,
    ) -> Self::Sign<'a, S> {
        let header = ssi_jws::Header::new_unencoded(
            Algorithm::EdBlake2b,
            options.public_key_jwk.key_id.clone(),
        );
        let signing_bytes = header.encode_signing_bytes(bytes);

        SignWith {
            header: Some(header),
            sign: SelfRefFuture::new(signing_bytes, Binder { signer }),
        }
    }

    fn verify(
        &self,
        options: OptionsRef,
        signature: JwsSignatureRef,
        method: &Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021,
        bytes: &[u8],
    ) -> Result<bool, VerificationError> {
        if method.matches_public_key(options.public_key_jwk)? {
            let (header, _, signature) = signature
                .jws
                .decode()
                .map_err(|_| VerificationError::InvalidSignature)?;
            let signing_bytes = header.encode_signing_bytes(bytes);
            Ok(ssi_jws::verify_bytes(
                header.algorithm,
                &signing_bytes,
                options.public_key_jwk,
                &signature,
            ).is_ok())
        } else {
            Ok(false)
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, LinkedData)]
#[ld(prefix("sec" = "https://w3id.org/security#"))]
pub struct Options {
    #[serde(rename = "publicKeyJwk")]
    #[ld("sec:publicKeyJwk")]
    pub public_key_jwk: Box<JWK>,
}

impl Options {
    pub fn new(public_key_jwk: JWK) -> Self {
        Self {
            public_key_jwk: Box::new(public_key_jwk),
        }
    }
}

impl Referencable for Options {
    type Reference<'a> = OptionsRef<'a>;

    fn as_reference(&self) -> Self::Reference<'_> {
        OptionsRef {
            public_key_jwk: &self.public_key_jwk,
        }
    }

    covariance_rule!();
}

#[derive(Debug, Clone, Copy, serde::Serialize, LinkedData)]
#[ld(prefix("sec" = "https://w3id.org/security#"))]
pub struct OptionsRef<'a> {
    #[serde(rename = "publicKeyJwk")]
    #[ld("sec:publicKeyJwk")]
    pub public_key_jwk: &'a JWK,
}

struct UnboundSign<S>(PhantomData<S>);

impl<'a, S: 'a + MessageSigner> UnboundedRefFuture<'a> for UnboundSign<S> {
    type Owned = Vec<u8>;

    type Bound<'r> = S::Sign<'r> where 'a: 'r;

    type Output = Result<Vec<u8>, MessageSignatureError>;
}

struct Binder<S> {
    // signing_bytes: Vec<u8>
    signer: S,
}

impl<'a, S: 'a + MessageSigner> RefFutureBinder<'a, UnboundSign<S>> for Binder<S> {
    fn bind<'r>(context: Self, value: &'r Vec<u8>) -> S::Sign<'r>
    where
        'a: 'r,
    {
        context.signer.sign((), value)
    }
}

#[pin_project]
pub struct SignWith<'a, S: 'a + MessageSigner> {
    header: Option<ssi_jws::Header>,

    #[pin]
    sign: SelfRefFuture<'a, UnboundSign<S>>,
}

impl<'a, S: 'a + MessageSigner> Future for SignWith<'a, S> {
    type Output = Result<JwsSignature, SignatureError>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = self.project();
        this.sign.poll(cx).map(|(r, _)| match r {
            Ok(signature) => {
                let header = this.header.take().unwrap();
                let jws = ssi_jws::CompactJWSString::encode_detached(header, &signature);
                Ok(JwsSignature::new(jws))
            }
            Err(e) => Err(e.into()),
        })
    }
}
