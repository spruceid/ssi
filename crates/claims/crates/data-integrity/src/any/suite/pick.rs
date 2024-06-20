use ssi_jwk::JWK;
use ssi_verification_methods::{AnyMethod, ReferenceOrOwned};

use crate::AnySuite;

impl AnySuite {
    #[allow(unused)]
    pub fn pick(
        jwk: &JWK,
        verification_method: Option<&ReferenceOrOwned<AnyMethod>>,
    ) -> Option<Self> {
        if let Some(vm) = verification_method {
            #[cfg(feature = "w3c")]
            if vm.id().starts_with("did:jwk:") {
                return Some(Self::JsonWebSignature2020);
            }
        }

        use ssi_jwk::Algorithm;
        let algorithm = jwk.get_algorithm()?;
        match algorithm {
            #[cfg(all(feature = "w3c", feature = "rsa"))]
            Algorithm::RS256 => Some(Self::RsaSignature2018),
            #[cfg(feature = "w3c")]
            Algorithm::PS256 => Some(Self::JsonWebSignature2020),
            #[cfg(feature = "w3c")]
            Algorithm::ES384 => Some(Self::JsonWebSignature2020),
            #[cfg(feature = "aleo")]
            Algorithm::AleoTestnet1Signature => Some(Self::AleoSignature2021),
            Algorithm::EdDSA | Algorithm::EdBlake2b => match verification_method {
                #[cfg(feature = "solana")]
                Some(vm)
                    if (vm.id().starts_with("did:sol:") || vm.id().starts_with("did:pkh:sol:"))
                        && vm.id().ends_with("#SolanaMethod2021") =>
                {
                    Some(Self::SolanaSignature2021)
                }
                #[cfg(feature = "tezos")]
                Some(vm)
                    if vm.id().starts_with("did:tz:") || vm.id().starts_with("did:pkh:tz:") =>
                {
                    if vm.id().ends_with("#TezosMethod2021") {
                        return Some(Self::TezosSignature2021);
                    }

                    #[cfg(feature = "ed25519")]
                    return Some(Self::Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021);

                    None
                }
                #[cfg(all(feature = "w3c", feature = "ed25519"))]
                _ => Some(Self::Ed25519Signature2018),
                #[cfg(not(all(feature = "w3c", feature = "ed25519")))]
                _ => {
                    // missing `ed25519` or `tezos` or `solana`.
                    None
                }
            },
            Algorithm::ES256 | Algorithm::ESBlake2b => match verification_method {
                #[cfg(feature = "tezos")]
                Some(vm)
                    if vm.id().starts_with("did:tz:") || vm.id().starts_with("did:pkh:tz:") =>
                {
                    if vm.id().ends_with("#TezosMethod2021") {
                        return Some(Self::TezosSignature2021);
                    }

                    #[cfg(feature = "secp256r1")]
                    return Some(Self::P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021);

                    None
                }
                #[cfg(all(feature = "w3c", feature = "secp256r1"))]
                _ => Some(Self::EcdsaSecp256r1Signature2019),
                #[allow(unreachable_patterns)]
                _ => {
                    // missing `secp256r1` or `tezos` features.
                    None
                }
            },
            Algorithm::ES256K | Algorithm::ESBlake2bK => match verification_method {
                #[cfg(any(feature = "tezos", feature = "dif"))]
                #[allow(unreachable_code)]
                Some(vm)
                    if vm.id().starts_with("did:tz:") || vm.id().starts_with("did:pkh:tz:") =>
                {
                    #[cfg(feature = "tezos")]
                    if vm.id().ends_with("#TezosMethod2021") {
                        return Some(Self::TezosSignature2021);
                    }

                    #[cfg(all(feature = "dif", feature = "secp256k1"))]
                    return Some(Self::EcdsaSecp256k1RecoverySignature2020);

                    None
                }
                #[cfg(all(feature = "w3c", feature = "secp256k1"))]
                _ => Some(Self::EcdsaSecp256k1Signature2019),
                #[allow(unreachable_patterns)]
                _ => None,
            },
            Algorithm::ES256KR => {
                // #[allow(clippy::if_same_then_else)]
                #[cfg(all(feature = "w3c", feature = "eip712"))]
                if use_eip712sig(jwk) {
                    return Some(Self::EthereumEip712Signature2021);
                }
                #[cfg(all(feature = "ethereum", feature = "secp256k1"))]
                if use_epsig(jwk) {
                    return Some(Self::EthereumPersonalSignature2021);
                }

                match verification_method {
                    #[cfg(all(feature = "ethereum", feature = "eip712"))]
                    Some(vm)
                        if (vm.id().starts_with("did:ethr:")
                            || vm.id().starts_with("did:pkh:eth:"))
                            && vm.id().ends_with("#Eip712Method2021") =>
                    {
                        Some(Self::Eip712Signature2021)
                    }

                    #[cfg(all(feature = "dif", feature = "secp256k1"))]
                    _ => Some(Self::EcdsaSecp256k1RecoverySignature2020),
                    #[allow(unreachable_patterns)]
                    _ => None,
                }
            }
            _ => None,
        }
    }
}

#[cfg(all(feature = "w3c", feature = "eip712"))]
fn use_eip712sig(key: &JWK) -> bool {
    // deprecated: allow using unregistered "signTypedData" key operation value to indicate using EthereumEip712Signature2021
    if let Some(ref key_ops) = key.key_operations {
        if key_ops.contains(&"signTypedData".to_string()) {
            return true;
        }
    }
    false
}

#[cfg(all(feature = "ethereum", feature = "secp256k1"))]
fn use_epsig(key: &JWK) -> bool {
    // deprecated: allow using unregistered "signPersonalMessage" key operation value to indicate using EthereumPersonalSignature2021
    if let Some(ref key_ops) = key.key_operations {
        if key_ops.contains(&"signPersonalMessage".to_string()) {
            return true;
        }
    }
    false
}
