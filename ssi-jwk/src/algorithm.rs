use core::fmt;

use serde::{Serialize, Deserialize};

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
                $id
            ),*
        }

        impl Algorithm {
            pub fn as_str(&self) -> &'static str {
                match self {
                    $(
                        Self::$id => $name
                    ),*
                }
            }

            pub fn into_str(self) -> &'static str {
                match self {
                    $(
                        Self::$id => $name
                    ),*
                }
            }
        }

        $(
            $(#[doc = $doc])*
            #[derive(Debug, Default, Clone, Copy, PartialEq, Hash, Eq)]
            pub struct $id;

            impl TryFrom<Algorithm> for $id {
                type Error = UnsupportedAlgorithm;
                
                fn try_from(a: Algorithm) -> Result<Self, Self::Error> {
                    match a {
                        Algorithm::$id => Ok(Self),
                        a => Err(UnsupportedAlgorithm(a))
                    }
                }
            }

            impl From<$id> for Algorithm {
                fn from(_a: $id) -> Self {
                    Self::$id
                }
            }
        )*
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
    
    /// ECDSA using secp256k1 (K-256) and Keccak-256 with a recovery bit.
    /// 
    /// Like `ES256K-R` but using Keccak-256 instead of SHA-256.
    ESKeccakKR: "ESKeccakKR",

    /// ECDSA using P-256 and Blake2b.
    ESBlake2b: "ESBlake2b",

    /// ECDSA using secp256k1 (K-256) and Blake2b.
    ESBlake2bK: "ESBlake2bK",
    
    #[doc(hidden)]
    AleoTestnet1Signature: "AleoTestnet1Signature",
    
    /// No signature.
    /// 
    /// Per the specs it should only be `none` but `None` is kept for backwards
    /// compatibility.
    #[serde(alias = "None")]
    None: "none"
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

#[derive(Debug, thiserror::Error)]
pub enum AlgorithmError {
    /// Missing algorithm.
    #[error("missing algorithm")]
    Missing,

    /// Unsupported algorithm.
    #[error("unsupported signature algorithm `{0}`")]
    Unsupported(Algorithm)
}

impl From<AlgorithmError> for ssi_crypto::MessageSignatureError {
    fn from(value: AlgorithmError) -> Self {
        match value {
            AlgorithmError::Missing => Self::MissingAlgorithm,
            AlgorithmError::Unsupported(a) => Self::UnsupportedAlgorithm(a.to_string())
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("unsupported signature algorithm `{0}`")]
pub struct UnsupportedAlgorithm(pub Algorithm);

impl From<UnsupportedAlgorithm> for ssi_crypto::MessageSignatureError {
    fn from(value: UnsupportedAlgorithm) -> Self {
        Self::UnsupportedAlgorithm(value.0.to_string())
    }
}

/// ECDSA using secp256k1 (K-256) and SHA-256, with or without recovery bit.
pub enum AnyES256K {
    /// ECDSA using secp256k1 (K-256) and SHA-256, without recovery bit.
    ES256K,

    /// ECDSA using secp256k1 (K-256) and SHA-256, with recovery bit.
    ES256KR
}

impl TryFrom<Algorithm> for AnyES256K {
    type Error = UnsupportedAlgorithm;

    fn try_from(value: Algorithm) -> Result<Self, Self::Error> {
        match value {
            Algorithm::ES256K => Ok(Self::ES256K),
            Algorithm::ES256KR => Ok(Self::ES256KR),
            other => Err(UnsupportedAlgorithm(other))
        }
    }
}

impl From<AnyES256K> for Algorithm {
    fn from(value: AnyES256K) -> Self {
        match value {
            AnyES256K::ES256K => Self::ES256K,
            AnyES256K::ES256KR => Self::ES256KR
        }
    }
}

impl From<ES256K> for AnyES256K {
    fn from(_value: ES256K) -> Self {
        Self::ES256K
    }
}

impl From<ES256KR> for AnyES256K {
    fn from(_value: ES256KR) -> Self {
        Self::ES256KR
    }
}