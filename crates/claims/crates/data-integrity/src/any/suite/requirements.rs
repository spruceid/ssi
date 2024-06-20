use crate::AnySuite;

impl AnySuite {
    #[cfg(feature = "eip712")]
    pub fn requires_eip712(&self) -> bool {
        #[cfg(feature = "w3c")]
        if matches!(self, Self::EthereumEip712Signature2021) {
            return true;
        }

        false
    }

    #[cfg(feature = "eip712")]
    pub fn requires_eip712_v0_1(&self) -> bool {
        #[cfg(feature = "w3c")]
        if matches!(self, Self::EthereumEip712Signature2021v0_1) {
            return true;
        }

        false
    }

    pub fn requires_public_key_jwk(&self) -> bool {
        #[cfg(all(feature = "tezos", feature = "ed25519"))]
        if matches!(
            self,
            Self::Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021
        ) {
            return true;
        }

        #[cfg(all(feature = "tezos", feature = "secp256r1"))]
        if matches!(
            self,
            Self::P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021
        ) {
            return true;
        }

        #[cfg(feature = "tezos")]
        if matches!(self, Self::TezosSignature2021) {
            return true;
        }

        false
    }

    pub fn requires_public_key_multibase(&self) -> bool {
        #[cfg(feature = "tezos")]
        if matches!(self, Self::TezosJcsSignature2021) {
            return true;
        }

        false
    }
}
