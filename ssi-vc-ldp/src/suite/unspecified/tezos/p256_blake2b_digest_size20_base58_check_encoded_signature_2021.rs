use super::{Options, OptionsRef};
use ssi_crypto::MessageSigner;
use ssi_jwk::Algorithm;
use ssi_verification_methods::{
    P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021, VerificationError,
};
use static_iref::iri;

use crate::{
    impl_rdf_input_urdna2015,
    suite::{sha256_hash, HashError, JwsSignature, JwsSignatureRef, SignIntoDetachedJws},
    CryptographicSuite, ProofConfigurationRef,
};

/// Proof type used with [did:tz](https://github.com/spruceid/did-tezos/) `tz3` addresses.
pub struct P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021;

impl_rdf_input_urdna2015!(P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021);

impl CryptographicSuite for P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021 {
    type Transformed = String;

    type Hashed = [u8; 64];

    type VerificationMethod = P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021;

    type Signature = JwsSignature;

    type SignatureProtocol = ();

    type SignatureAlgorithm = SignatureAlgorithm;

    type Options = Options;

    fn iri(&self) -> &iref::Iri {
        iri!("https://w3id.org/security#P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021")
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

// #[derive(Debug, Clone, serde::Serialize, serde::Deserialize, LinkedData)]
// #[ld(prefix("sec" = "https://w3id.org/security#"))]
// pub struct Signature {
//     /// JSON Web Signature.
//     #[ld("sec:jwk")]
//     pub jws: CompactJWSString,

//     /// Signing key.
//     #[ld("sec:publicKeyJwk")]
//     pub public_key_jwk: Box<JWK>,
// }

// impl From<Signature> for AnySignature {
//     fn from(value: Signature) -> Self {
//         AnySignature {
//             jws: Some(value.jws),
//             public_key_jwk: Some(value.public_key_jwk),
//             ..Default::default()
//         }
//     }
// }

// impl Referencable for Signature {
//     type Reference<'a> = SignatureRef<'a> where Self: 'a;

//     fn as_reference(&self) -> Self::Reference<'_> {
//         SignatureRef {
//             jws: &self.jws,
//             public_key_jwk: &self.public_key_jwk,
//         }
//     }

//     covariance_rule!();
// }

// #[derive(Debug, Clone, Copy)]
// pub struct SignatureRef<'a> {
//     /// JSON Web Signature.
//     pub jws: &'a CompactJWSStr,

//     /// Signing key.
//     pub public_key_jwk: &'a JWK,
// }

// impl<'a> From<SignatureRef<'a>> for AnySignatureRef<'a> {
//     fn from(value: SignatureRef<'a>) -> Self {
//         AnySignatureRef {
//             jws: Some(value.jws),
//             public_key_jwk: Some(value.public_key_jwk),
//             ..Default::default()
//         }
//     }
// }

// impl<'a> TryFrom<AnySignatureRef<'a>> for SignatureRef<'a> {
//     type Error = InvalidSignature;

//     fn try_from(value: AnySignatureRef<'a>) -> Result<Self, Self::Error> {
//         Ok(Self {
//             jws: value.jws.ok_or(InvalidSignature::MissingValue)?,
//             public_key_jwk: value.public_key_jwk.ok_or(InvalidSignature::MissingPublicKey)?
//         })
//     }
// }

pub struct SignatureAlgorithm;

impl
    ssi_verification_methods::SignatureAlgorithm<
        P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021,
    > for SignatureAlgorithm
{
    type Options = Options;

    type Signature = JwsSignature;

    type Protocol = ();

    type Sign<'a, S: 'a + MessageSigner<Self::Protocol>> = SignIntoDetachedJws<'a, S>;

    fn sign<'a, S: 'a + MessageSigner<Self::Protocol>>(
        &self,
        options: OptionsRef<'a>,
        _method: &P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021,
        bytes: &'a [u8],
        signer: S,
    ) -> Self::Sign<'a, S> {
        let header = ssi_jws::Header::new_unencoded(
            Algorithm::ESBlake2b,
            options.public_key_jwk.key_id.clone(),
        );
        SignIntoDetachedJws::new(header, bytes, signer)
    }

    fn verify(
        &self,
        options: OptionsRef,
        signature: JwsSignatureRef,
        method: &P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021,
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
            )
            .is_ok())
        } else {
            Ok(false)
        }
    }
}
