use super::{Options, TezosV2Context};
use iref::Iri;
use k256::sha2::Sha256;
use ssi_data_integrity_core::{
    canonicalization::{CanonicalizeClaimsAndConfiguration, HashCanonicalClaimsAndConfiguration},
    signing::DetachedJwsRecoverySigning,
    suite::AddProofContext,
    StandardCryptographicSuite, TypeRef,
};
use ssi_verification_methods::P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021;
use static_iref::iri;

use crate::try_from_type;

/// Proof type used with [did:tz](https://github.com/spruceid/did-tezos/) `tz3` addresses.
#[derive(Debug, Default, Clone, Copy)]
pub struct P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021;

impl P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021 {
    pub const NAME: &'static str = "P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021";

    pub const IRI: &'static Iri =
        iri!("https://w3id.org/security#P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021");
}

impl StandardCryptographicSuite for P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021 {
    type Configuration = AddProofContext<TezosV2Context>;

    type Transformation = CanonicalizeClaimsAndConfiguration;

    type Hashing = HashCanonicalClaimsAndConfiguration<Sha256>;

    type VerificationMethod = P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021;

    type SignatureAlgorithm = DetachedJwsRecoverySigning<ssi_crypto::algorithm::ESBlake2b>;

    type ProofOptions = Options;

    fn type_(&self) -> TypeRef {
        TypeRef::Other(Self::NAME)
    }
}

try_from_type!(P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021);
