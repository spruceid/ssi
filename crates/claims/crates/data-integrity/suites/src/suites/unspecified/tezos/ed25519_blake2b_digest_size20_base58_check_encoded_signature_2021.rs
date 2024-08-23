use super::{Options, TezosV2Context};
use iref::Iri;
use k256::sha2::Sha256;
use ssi_data_integrity_core::{
    canonicalization::{CanonicalizeClaimsAndConfiguration, HashCanonicalClaimsAndConfiguration},
    signing::DetachedJwsRecoverySigning,
    suite::AddProofContext,
    StandardCryptographicSuite, TypeRef,
};
use ssi_verification_methods::Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021;
use static_iref::iri;

use crate::try_from_type;

/// Proof type used with [did:tz](https://github.com/spruceid/did-tezos/) `tz1` addresses.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021;

impl Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021 {
    pub const NAME: &'static str = "Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021";

    pub const IRI: &'static Iri =
        iri!("https://w3id.org/security#Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021");
}

impl StandardCryptographicSuite for Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021 {
    type Configuration = AddProofContext<TezosV2Context>;

    type Transformation = CanonicalizeClaimsAndConfiguration;

    type Hashing = HashCanonicalClaimsAndConfiguration<Sha256>;

    type VerificationMethod = Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021;

    type SignatureAlgorithm = DetachedJwsRecoverySigning<ssi_crypto::algorithm::EdBlake2b>;

    type ProofOptions = Options;

    fn type_(&self) -> TypeRef {
        TypeRef::Other(Self::NAME)
    }
}

try_from_type!(Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021);
