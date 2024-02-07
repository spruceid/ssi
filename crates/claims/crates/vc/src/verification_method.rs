use ssi_vc_data_integrity::suite::{
    aleo_signature_2021, eip712_signature_2021, ethereum_eip712_signature_2021,
    ethereum_personal_signature_2021,
};
use ssi_verification_methods::{
    verification_method_union, AleoMethod2021, BlockchainVerificationMethod2021,
    EcdsaSecp256k1RecoveryMethod2020, EcdsaSecp256k1VerificationKey2019,
    EcdsaSecp256r1VerificationKey2019, Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021,
    Ed25519VerificationKey2018, Ed25519VerificationKey2020, Eip712Method2021,
    InvalidVerificationMethod, JsonWebKey2020, Multikey,
    P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021, RsaVerificationKey2018,
    SolanaMethod2021, TezosMethod2021, TypedVerificationMethod,
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
            m => Err(InvalidVerificationMethod::invalid_type_name(
                AnyMethod::ref_type(m),
            )),
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

impl TryFrom<AnyMethod> for ethereum_eip712_signature_2021::VerificationMethod {
    type Error = InvalidVerificationMethod;

    fn try_from(value: AnyMethod) -> Result<Self, Self::Error> {
        match value {
            AnyMethod::EcdsaSecp256k1VerificationKey2019(m) => {
                Ok(Self::EcdsaSecp256k1VerificationKey2019(m))
            }
            AnyMethod::EcdsaSecp256k1RecoveryMethod2020(m) => {
                Ok(Self::EcdsaSecp256k1RecoveryMethod2020(m))
            }
            AnyMethod::JsonWebKey2020(m) => Ok(Self::JsonWebKey2020(m)),
            _ => Err(InvalidVerificationMethod::UnsupportedMethodType),
        }
    }
}

impl From<ethereum_eip712_signature_2021::VerificationMethod> for AnyMethod {
    fn from(value: ethereum_eip712_signature_2021::VerificationMethod) -> Self {
        match value {
            ethereum_eip712_signature_2021::VerificationMethod::EcdsaSecp256k1VerificationKey2019(m) => Self::EcdsaSecp256k1VerificationKey2019(m),
            ethereum_eip712_signature_2021::VerificationMethod::EcdsaSecp256k1RecoveryMethod2020(m) => Self::EcdsaSecp256k1RecoveryMethod2020(m),
            ethereum_eip712_signature_2021::VerificationMethod::JsonWebKey2020(m) => Self::JsonWebKey2020(m)
        }
    }
}

impl<'a> TryFrom<AnyMethodRef<'a>> for ethereum_eip712_signature_2021::VerificationMethodRef<'a> {
    type Error = InvalidVerificationMethod;

    fn try_from(value: AnyMethodRef<'a>) -> Result<Self, Self::Error> {
        match value {
            AnyMethodRef::EcdsaSecp256k1VerificationKey2019(m) => {
                Ok(Self::EcdsaSecp256k1VerificationKey2019(m))
            }
            AnyMethodRef::EcdsaSecp256k1RecoveryMethod2020(m) => {
                Ok(Self::EcdsaSecp256k1RecoveryMethod2020(m))
            }
            AnyMethodRef::JsonWebKey2020(m) => Ok(Self::JsonWebKey2020(m)),
            _ => Err(InvalidVerificationMethod::UnsupportedMethodType),
        }
    }
}

impl<'a> From<ethereum_eip712_signature_2021::VerificationMethodRef<'a>> for AnyMethodRef<'a> {
    fn from(value: ethereum_eip712_signature_2021::VerificationMethodRef<'a>) -> Self {
        match value {
            ethereum_eip712_signature_2021::VerificationMethodRef::EcdsaSecp256k1VerificationKey2019(m) => Self::EcdsaSecp256k1VerificationKey2019(m),
            ethereum_eip712_signature_2021::VerificationMethodRef::EcdsaSecp256k1RecoveryMethod2020(m) => Self::EcdsaSecp256k1RecoveryMethod2020(m),
            ethereum_eip712_signature_2021::VerificationMethodRef::JsonWebKey2020(m) => Self::JsonWebKey2020(m)
        }
    }
}

impl TryFrom<AnyMethod> for eip712_signature_2021::VerificationMethod {
    type Error = InvalidVerificationMethod;

    fn try_from(value: AnyMethod) -> Result<Self, Self::Error> {
        match value {
            AnyMethod::EcdsaSecp256k1VerificationKey2019(m) => {
                Ok(Self::EcdsaSecp256k1VerificationKey2019(m))
            }
            AnyMethod::EcdsaSecp256k1RecoveryMethod2020(m) => {
                Ok(Self::EcdsaSecp256k1RecoveryMethod2020(m))
            }
            AnyMethod::Eip712Method2021(m) => Ok(Self::Eip712Method2021(m)),
            _ => Err(InvalidVerificationMethod::UnsupportedMethodType),
        }
    }
}

impl From<eip712_signature_2021::VerificationMethod> for AnyMethod {
    fn from(value: eip712_signature_2021::VerificationMethod) -> Self {
        match value {
            eip712_signature_2021::VerificationMethod::EcdsaSecp256k1VerificationKey2019(m) => {
                Self::EcdsaSecp256k1VerificationKey2019(m)
            }
            eip712_signature_2021::VerificationMethod::EcdsaSecp256k1RecoveryMethod2020(m) => {
                Self::EcdsaSecp256k1RecoveryMethod2020(m)
            }
            eip712_signature_2021::VerificationMethod::Eip712Method2021(m) => {
                Self::Eip712Method2021(m)
            }
        }
    }
}

impl<'a> TryFrom<AnyMethodRef<'a>> for eip712_signature_2021::VerificationMethodRef<'a> {
    type Error = InvalidVerificationMethod;

    fn try_from(value: AnyMethodRef<'a>) -> Result<Self, Self::Error> {
        match value {
            AnyMethodRef::EcdsaSecp256k1VerificationKey2019(m) => {
                Ok(Self::EcdsaSecp256k1VerificationKey2019(m))
            }
            AnyMethodRef::EcdsaSecp256k1RecoveryMethod2020(m) => {
                Ok(Self::EcdsaSecp256k1RecoveryMethod2020(m))
            }
            AnyMethodRef::Eip712Method2021(m) => Ok(Self::Eip712Method2021(m)),
            _ => Err(InvalidVerificationMethod::UnsupportedMethodType),
        }
    }
}

impl<'a> From<eip712_signature_2021::VerificationMethodRef<'a>> for AnyMethodRef<'a> {
    fn from(value: eip712_signature_2021::VerificationMethodRef<'a>) -> Self {
        match value {
            eip712_signature_2021::VerificationMethodRef::EcdsaSecp256k1VerificationKey2019(m) => {
                Self::EcdsaSecp256k1VerificationKey2019(m)
            }
            eip712_signature_2021::VerificationMethodRef::EcdsaSecp256k1RecoveryMethod2020(m) => {
                Self::EcdsaSecp256k1RecoveryMethod2020(m)
            }
            eip712_signature_2021::VerificationMethodRef::Eip712Method2021(m) => {
                Self::Eip712Method2021(m)
            }
        }
    }
}

impl TryFrom<AnyMethod> for ethereum_personal_signature_2021::VerificationMethod {
    type Error = InvalidVerificationMethod;

    fn try_from(value: AnyMethod) -> Result<Self, Self::Error> {
        match value {
            AnyMethod::EcdsaSecp256k1VerificationKey2019(m) => {
                Ok(Self::EcdsaSecp256k1VerificationKey2019(m))
            }
            AnyMethod::EcdsaSecp256k1RecoveryMethod2020(m) => {
                Ok(Self::EcdsaSecp256k1RecoveryMethod2020(m))
            }
            _ => Err(InvalidVerificationMethod::UnsupportedMethodType),
        }
    }
}

impl From<ethereum_personal_signature_2021::VerificationMethod> for AnyMethod {
    fn from(value: ethereum_personal_signature_2021::VerificationMethod) -> Self {
        match value {
            ethereum_personal_signature_2021::VerificationMethod::EcdsaSecp256k1VerificationKey2019(m) => Self::EcdsaSecp256k1VerificationKey2019(m),
            ethereum_personal_signature_2021::VerificationMethod::EcdsaSecp256k1RecoveryMethod2020(m) => Self::EcdsaSecp256k1RecoveryMethod2020(m)
        }
    }
}

impl<'a> TryFrom<AnyMethodRef<'a>> for ethereum_personal_signature_2021::VerificationMethodRef<'a> {
    type Error = InvalidVerificationMethod;

    fn try_from(value: AnyMethodRef<'a>) -> Result<Self, Self::Error> {
        match value {
            AnyMethodRef::EcdsaSecp256k1VerificationKey2019(m) => {
                Ok(Self::EcdsaSecp256k1VerificationKey2019(m))
            }
            AnyMethodRef::EcdsaSecp256k1RecoveryMethod2020(m) => {
                Ok(Self::EcdsaSecp256k1RecoveryMethod2020(m))
            }
            _ => Err(InvalidVerificationMethod::UnsupportedMethodType),
        }
    }
}

impl<'a> From<ethereum_personal_signature_2021::VerificationMethodRef<'a>> for AnyMethodRef<'a> {
    fn from(value: ethereum_personal_signature_2021::VerificationMethodRef<'a>) -> Self {
        match value {
            ethereum_personal_signature_2021::VerificationMethodRef::EcdsaSecp256k1VerificationKey2019(m) => Self::EcdsaSecp256k1VerificationKey2019(m),
            ethereum_personal_signature_2021::VerificationMethodRef::EcdsaSecp256k1RecoveryMethod2020(m) => Self::EcdsaSecp256k1RecoveryMethod2020(m)
        }
    }
}
