use core::fmt;
use serde::{Deserialize, Serialize};
use ssi_crypto::{
    algorithm::{ES256OrES384, SignatureAlgorithmInstance, SignatureAlgorithmType},
    UnsupportedAlgorithm,
};

macro_rules! algorithms {
    ($(
        $(#[doc = $doc:tt])*
        $(#[doc($doc_tag:ident)])?
        $(#[serde $serde:tt])?
        $id:ident: $name:literal
    ),*) => {
        /// Signature algorithm.
        #[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Hash, Eq)]
        pub enum Algorithm {
            $(
                $(#[doc = $doc])*
                $(#[doc($doc_tag)])?
                $(#[serde $serde])?
                #[serde(rename = $name)]
                $id,
            )*
            /// No signature.
            ///
            /// Per the specs it should only be `none` but `None` is kept for backwards
            /// compatibility.
            #[serde(alias = "None", rename = "none")]
            None
        }

        impl Algorithm {
            pub fn as_str(&self) -> &'static str {
                match self {
                    $(
                        Self::$id => $name,
                    )*
                    Self::None => "none"
                }
            }

            pub fn into_str(self) -> &'static str {
                match self {
                    $(
                        Self::$id => $name,
                    )*
                    Self::None => "none"
                }
            }
        }

        impl From<Algorithm> for ssi_crypto::Algorithm {
            fn from(a: Algorithm) -> Self {
                match a {
                    $(Algorithm::$id => Self::$id,)*
                    Algorithm::None => Self::None
                }
            }
        }

        impl From<Algorithm> for ssi_crypto::AlgorithmInstance {
            fn from(a: Algorithm) -> Self {
                match a {
                    $(Algorithm::$id => Self::$id,)*
                    Algorithm::None => Self::None
                }
            }
        }

        $(
            impl From<ssi_crypto::algorithm::$id> for Algorithm {
                fn from(_: ssi_crypto::algorithm::$id) -> Self {
                    Self::$id
                }
            }

            impl TryFrom<Algorithm> for ssi_crypto::algorithm::$id {
                type Error = UnsupportedAlgorithm;

                fn try_from(value: Algorithm) -> Result<Self, Self::Error> {
                    match value {
                        Algorithm::$id => Ok(Self),
                        other => Err(UnsupportedAlgorithm(other.into()))
                    }
                }
            }
        )*

        impl TryFrom<ssi_crypto::Algorithm> for Algorithm {
            type Error = UnsupportedAlgorithm;

            fn try_from(a: ssi_crypto::Algorithm) -> Result<Self, Self::Error> {
                match a {
                    $(ssi_crypto::Algorithm::$id => Ok(Self::$id),)*
                    ssi_crypto::Algorithm::None => Ok(Self::None),
                    other => Err(UnsupportedAlgorithm(other))
                }
            }
        }

        impl TryFrom<ssi_crypto::AlgorithmInstance> for Algorithm {
            type Error = UnsupportedAlgorithm;

            fn try_from(a: ssi_crypto::AlgorithmInstance) -> Result<Self, Self::Error> {
                match a {
                    $(ssi_crypto::AlgorithmInstance::$id => Ok(Self::$id),)*
                    ssi_crypto::AlgorithmInstance::None => Ok(Self::None),
                    other => Err(UnsupportedAlgorithm(other.algorithm()))
                }
            }
        }
    };
}

algorithms! {
    /// HMAC using SHA-256.
    ///
    /// See: <https://www.rfc-editor.org/rfc/rfc7518.txt>
    HS256: "HS256",

    /// HMAC using SHA-384.
    ///
    /// See: <https://www.rfc-editor.org/rfc/rfc7518.txt>
    HS384: "HS384",

    /// HMAC using SHA-512.
    ///
    /// See: <https://www.rfc-editor.org/rfc/rfc7518.txt>
    HS512: "HS512",

    /// RSASSA-PKCS1-v1_5 using SHA-256.
    ///
    /// See: <https://www.rfc-editor.org/rfc/rfc7518.txt>
    RS256: "RS256",

    /// RSASSA-PKCS1-v1_5 using SHA-384.
    ///
    /// See: <https://www.rfc-editor.org/rfc/rfc7518.txt>
    RS384: "RS384",

    /// RSASSA-PKCS1-v1_5 using SHA-512.
    ///
    /// See: <https://www.rfc-editor.org/rfc/rfc7518.txt>
    RS512: "RS512",

    /// RSASSA-PSS using SHA-256 and MGF1 with SHA-256.
    ///
    /// See: <https://www.rfc-editor.org/rfc/rfc7518.txt>
    PS256: "PS256",

    /// RSASSA-PSS using SHA-384 and MGF1 with SHA-384.
    ///
    /// See: <https://www.rfc-editor.org/rfc/rfc7518.txt>
    PS384: "PS384",

    /// RSASSA-PSS using SHA-512 and MGF1 with SHA-512.
    ///
    /// See: <https://www.rfc-editor.org/rfc/rfc7518.txt>
    PS512: "PS512",

    /// Edwards-curve Digital Signature Algorithm (EdDSA) using SHA-256.
    ///
    /// The following curves are defined for use with `EdDSA`:
    ///  - `Ed25519`
    ///  - `Ed448`
    ///
    /// See: <https://www.rfc-editor.org/rfc/rfc8037>
    EdDSA: "EdDSA",

    /// EdDSA using SHA-256 and Blake2b as pre-hash function.
    EdBlake2b: "EdBlake2b", // TODO Blake2b is supposed to replace SHA-256

    /// ECDSA using P-256 and SHA-256.
    ///
    /// See: <https://www.rfc-editor.org/rfc/rfc7518.txt>
    ES256: "ES256",

    /// ECDSA using P-384 and SHA-384.
    ///
    /// See: <https://www.rfc-editor.org/rfc/rfc7518.txt>
    ES384: "ES384",

    /// ECDSA using secp256k1 (K-256) and SHA-256.
    ///
    /// See: <https://datatracker.ietf.org/doc/html/rfc8812>
    ES256K: "ES256K",

    /// ECDSA using secp256k1 (K-256) and SHA-256 with a recovery bit.
    ///
    /// `ES256K-R` is similar to `ES256K` with the recovery bit appended, making
    /// the signature 65 bytes instead of 64. The recovery bit is used to
    /// extract the public key from the signature.
    ///
    /// See: <https://github.com/decentralized-identity/EcdsaSecp256k1RecoverySignature2020#es256k-r>
    ES256KR: "ES256K-R",

    /// ECDSA using secp256k1 (K-256) and Keccak-256.
    ///
    /// Like `ES256K` but using Keccak-256 instead of SHA-256.
    ESKeccakK: "ESKeccakK",

    /// ECDSA using secp256k1 (K-256) and Keccak-256 with a recovery bit.
    ///
    /// Like `ES256K-R` but using Keccak-256 instead of SHA-256.
    ESKeccakKR: "ESKeccakKR",

    /// ECDSA using P-256 and Blake2b.
    ESBlake2b: "ESBlake2b",

    /// ECDSA using secp256k1 (K-256) and Blake2b.
    ESBlake2bK: "ESBlake2bK",

    #[doc(hidden)]
    AleoTestnet1Signature: "AleoTestnet1Signature"
}

impl Algorithm {
    /// Checks if this algorithm is compatible with the `other` algorithm.
    ///
    /// An algorithm `A` is compatible with `B` if `A` can be used to verify a
    /// signature created from `B`.
    pub fn is_compatible_with(&self, other: Self) -> bool {
        match self {
            Self::ES256K | Self::ES256KR | Self::ESKeccakK | Self::ESKeccakKR => matches!(
                other,
                Self::ES256K | Self::ES256KR | Self::ESKeccakK | Self::ESKeccakKR
            ),
            a => *a == other,
        }
    }
}

impl SignatureAlgorithmType for Algorithm {
    type Instance = Self;
}

impl SignatureAlgorithmInstance for Algorithm {
    type Algorithm = Self;

    fn algorithm(&self) -> Self {
        *self
    }
}

impl Default for Algorithm {
    fn default() -> Self {
        Self::None
    }
}

impl AsRef<str> for Algorithm {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(f)
    }
}

impl From<ssi_crypto::algorithm::AnyBlake2b> for Algorithm {
    fn from(value: ssi_crypto::algorithm::AnyBlake2b) -> Self {
        match value {
            ssi_crypto::algorithm::AnyBlake2b::ESBlake2b => Self::ESBlake2b,
            ssi_crypto::algorithm::AnyBlake2b::ESBlake2bK => Self::ESBlake2bK,
            ssi_crypto::algorithm::AnyBlake2b::EdBlake2b => Self::EdBlake2b,
        }
    }
}

impl TryFrom<Algorithm> for ssi_crypto::algorithm::AnyBlake2b {
    type Error = UnsupportedAlgorithm;

    fn try_from(value: Algorithm) -> Result<Self, Self::Error> {
        match value {
            Algorithm::ESBlake2b => Ok(Self::ESBlake2b),
            Algorithm::ESBlake2bK => Ok(Self::ESBlake2bK),
            Algorithm::EdBlake2b => Ok(Self::EdBlake2b),
            other => Err(UnsupportedAlgorithm(other.into())),
        }
    }
}

impl From<ES256OrES384> for Algorithm {
    fn from(value: ES256OrES384) -> Self {
        match value {
            ES256OrES384::ES256 => Self::ES256,
            ES256OrES384::ES384 => Self::ES384,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Algorithm;

    #[test]
    fn none_serializes() {
        assert_eq!(
            serde_json::to_string(&Algorithm::None).unwrap(),
            r#""none""#
        )
    }

    #[test]
    fn none_deserializes() {
        assert_eq!(
            serde_json::from_str::<Algorithm>(r#""none""#).unwrap(),
            Algorithm::None
        );
        assert_eq!(
            serde_json::from_str::<Algorithm>(r#""None""#).unwrap(),
            Algorithm::None
        )
    }
}
