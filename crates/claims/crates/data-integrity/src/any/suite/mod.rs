mod unknown;
pub use unknown::*;

use crate::macros;

mod pick;

macros::crypto_suites! {
    /// W3C RSA Signature Suite 2018.
    ///
    /// See: <https://w3c-ccg.github.io/lds-rsa2018/>
    #[cfg(all(feature = "w3c", feature = "rsa"))]
    rsa_signature_2018: RsaSignature2018,

    /// W3C Ed25519 Signature 2018.
    ///
    /// See: <https://w3c-ccg.github.io/lds-ed25519-2018/>
    #[cfg(all(feature = "w3c", feature = "ed25519"))]
    ed25519_signature_2018: Ed25519Signature2018,

    /// W3C Ed25519 Signature 2020.
    ///
    /// See: <https://w3c.github.io/vc-di-eddsa/#the-ed25519signature2020-suite>
    #[cfg(all(feature = "w3c", feature = "ed25519"))]
    ed25519_signature_2020: Ed25519Signature2020,

    /// W3C EdDSA Cryptosuite v2022.
    ///
    /// See: <https://w3c.github.io/vc-di-eddsa/>
    #[cfg(all(feature = "w3c", feature = "ed25519"))]
    ed_dsa_2022: EdDsa2022,

    /// W3C Ecdsa Secp256k1 Signature 2019.
    ///
    /// See: <https://w3c-ccg.github.io/lds-ecdsa-secp256k1-2019/>
    #[cfg(all(feature = "w3c", feature = "secp256k1"))]
    ecdsa_secp_256k1_signature2019: EcdsaSecp256k1Signature2019,

    /// W3C Ecdsa Secp256r1 Signature 2019.
    ///
    /// See: <https://www.w3.org/community/reports/credentials/CG-FINAL-di-ecdsa-2019-20220724/#ecdsasecp256r1signature2019>
    #[cfg(all(feature = "w3c", feature = "secp256r1"))]
    ecdsa_secp_256r1_signature2019: EcdsaSecp256r1Signature2019,

    /// W3C JSON Web Signature 2020.
    ///
    /// See: <https://w3c-ccg.github.io/lds-jws2020/>
    #[cfg(feature = "w3c")]
    json_web_signature_2020: JsonWebSignature2020,

    #[cfg(all(feature = "w3c", feature = "eip712"))]
    ethereum_eip712_signature_2021: EthereumEip712Signature2021,

    #[cfg(all(feature = "w3c", feature = "eip712"))]
    ethereum_eip712_signature_2021_v0_1: EthereumEip712Signature2021v0_1,

    /// DIF Ecdsa Secp256k1 Recovery Signature 2020.
    ///
    /// See: <https://identity.foundation/EcdsaSecp256k1RecoverySignature2020/>
    #[cfg(all(feature = "dif", feature = "secp256k1"))]
    ecdsa_secp256k1_recovery_signature2020: EcdsaSecp256k1RecoverySignature2020,

    /// Unspecified Solana Signature 2021.
    #[cfg(feature = "solana")]
    solana_signature_2021: SolanaSignature2021,

    /// Unspecified Aleo Signature 2021.
    #[cfg(feature = "aleo")]
    aleo_signature_2021: AleoSignature2021,

    /// Unspecified Tezos Ed25519 Blake2b, digest size 20, base 58 check encoded, Signature 2021.
    #[cfg(all(feature = "tezos", feature = "ed25519"))]
    ed25519_blake2b_digest_size20_base58_check_encoded_signature_2021: Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021,

    /// Unspecified Tezos P256 Blake2b, digest size 20, base 58 check encoded, Signature 2021.
    #[cfg(all(feature = "tezos", feature = "secp256r1"))]
    p256_blake2b_digest_size20_base58_check_encoded_signature_2021: P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021,

    /// Unspecified Tezos JCS Signature 2021.
    #[cfg(feature = "tezos")]
    tezos_jcs_signature_2021: TezosJcsSignature2021,

    /// Unspecified Tezos Signature 2021.
    #[cfg(feature = "tezos")]
    tezos_signature_2021: TezosSignature2021,

    #[cfg(all(feature = "ethereum", feature = "eip712"))]
    eip712_signature_2021: Eip712Signature2021,

    #[cfg(all(feature = "ethereum", feature = "secp256k1"))]
    ethereum_personal_signature_2021: EthereumPersonalSignature2021,

    #[cfg(all(feature = "ethereum", feature = "secp256k1"))]
    ethereum_personal_signature_2021_v0_1: EthereumPersonalSignature2021v0_1
}

impl AnyProofOptions {
    #[cfg(all(feature = "w3c", feature = "eip712"))]
    pub fn eip712(
        &self,
    ) -> Option<&ssi_data_integrity_suites::ethereum_eip712_signature_2021::Eip712Options> {
        match self {
            Self::EthereumEip712Signature2021(o) => o.eip712.as_ref(),
            _ => None,
        }
    }

    #[cfg(all(feature = "w3c", feature = "eip712"))]
    pub fn eip712_mut(
        &mut self,
    ) -> Option<&mut ssi_data_integrity_suites::ethereum_eip712_signature_2021::Eip712Options> {
        match self {
            Self::EthereumEip712Signature2021(o) => o.eip712.as_mut(),
            _ => None,
        }
    }

    #[cfg(all(feature = "w3c", feature = "eip712"))]
    pub fn eip712_v0_1(
        &self,
    ) -> Option<&ssi_data_integrity_suites::ethereum_eip712_signature_2021::v0_1::Eip712Options>
    {
        match self {
            Self::EthereumEip712Signature2021v0_1(o) => o.eip712.as_ref(),
            _ => None,
        }
    }

    #[cfg(all(feature = "w3c", feature = "eip712"))]
    pub fn eip712_v0_1_mut(
        &mut self,
    ) -> Option<&mut ssi_data_integrity_suites::ethereum_eip712_signature_2021::v0_1::Eip712Options>
    {
        match self {
            Self::EthereumEip712Signature2021v0_1(o) => o.eip712.as_mut(),
            _ => None,
        }
    }
}
