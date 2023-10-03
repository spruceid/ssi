use ssi_vc_ldp::suite::aleo_signature_2021;
use ssi_verification_methods::{
    verification_method_union, AleoMethod2021, BlockchainVerificationMethod2021,
    EcdsaSecp256k1RecoveryMethod2020, EcdsaSecp256k1VerificationKey2019,
    EcdsaSecp256r1VerificationKey2019, Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021,
    Ed25519VerificationKey2018, Ed25519VerificationKey2020, Eip712Method2021,
    GenericVerificationMethod, InvalidVerificationMethod, JsonWebKey2020, Multikey,
    P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021, RsaVerificationKey2018,
    SolanaMethod2021, TezosMethod2021,
};

verification_method_union! {
    pub enum AnyMethod, AnyMethodRef, AnyMethodType {
        /// Deprecated verification method for the `RsaSignature2018` suite.
        RsaVerificationKey2018,

        /// Deprecated verification method for the `Ed25519Signature2018` suite.
        Ed25519VerificationKey2018,

        /// Deprecated verification method for the `Ed25519Signature2020` suite.
        Ed25519VerificationKey2020,

        EcdsaSecp256k1VerificationKey2019,

        EcdsaSecp256k1RecoveryMethod2020,

        EcdsaSecp256r1VerificationKey2019,

        /// `JsonWebKey2020`.
        JsonWebKey2020,

        /// `Multikey`.
        Multikey,

        Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021,

        P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021,

        TezosMethod2021,

        AleoMethod2021,

        BlockchainVerificationMethod2021,

        Eip712Method2021,

        SolanaMethod2021
    }
}

impl TryFrom<AnyMethod> for aleo_signature_2021::VerificationMethod {
    type Error = InvalidVerificationMethod;

    fn try_from(value: AnyMethod) -> Result<Self, Self::Error> {
        match value {
            AnyMethod::AleoMethod2021(m) => Ok(Self::AleoMethod2021(m)),
            AnyMethod::BlockchainVerificationMethod2021(m) => {
                Ok(Self::BlockchainVerificationMethod2021(m))
            }
            m => Err(InvalidVerificationMethod::invalid_type_name(
                ssi_verification_methods::TypedVerificationMethod::type_(&m),
            )),
        }
    }
}

impl From<aleo_signature_2021::VerificationMethod> for AnyMethod {
    fn from(value: aleo_signature_2021::VerificationMethod) -> Self {
        match value {
            aleo_signature_2021::VerificationMethod::AleoMethod2021(m) => Self::AleoMethod2021(m),
            aleo_signature_2021::VerificationMethod::BlockchainVerificationMethod2021(m) => {
                Self::BlockchainVerificationMethod2021(m)
            }
        }
    }
}

impl<'a> TryFrom<AnyMethodRef<'a>> for aleo_signature_2021::VerificationMethodRef<'a> {
    type Error = InvalidVerificationMethod;

    fn try_from(value: AnyMethodRef<'a>) -> Result<Self, Self::Error> {
        match value {
            AnyMethodRef::AleoMethod2021(m) => Ok(Self::AleoMethod2021(m)),
            AnyMethodRef::BlockchainVerificationMethod2021(m) => {
                Ok(Self::BlockchainVerificationMethod2021(m))
            }
            m => todo!(),
        }
    }
}

impl<'a> From<aleo_signature_2021::VerificationMethodRef<'a>> for AnyMethodRef<'a> {
    fn from(value: aleo_signature_2021::VerificationMethodRef<'a>) -> Self {
        match value {
            aleo_signature_2021::VerificationMethodRef::AleoMethod2021(m) => {
                Self::AleoMethod2021(m)
            }
            aleo_signature_2021::VerificationMethodRef::BlockchainVerificationMethod2021(m) => {
                Self::BlockchainVerificationMethod2021(m)
            }
        }
    }
}