use core::fmt;

use serde::{Deserialize, Serialize};

pub trait SignatureAlgorithmType {
    type Instance: SignatureAlgorithmInstance<Algorithm = Self>;
}

pub trait SignatureAlgorithmInstance {
    type Algorithm;

    fn algorithm(&self) -> Self::Algorithm;
}

macro_rules! algorithms {
    ($(
        $(#[doc = $doc:tt])*
        $(#[doc($doc_tag:ident)])?
        $(#[serde $serde:tt])?
        $id:ident $( ($arg:ty) )? : $name:literal
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
            #[serde(alias = "None")]
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

        impl SignatureAlgorithmType for Algorithm {
            type Instance = AlgorithmInstance;
        }

        #[derive(Debug, Clone)]
        pub enum AlgorithmInstance {
            $(
                $(#[doc = $doc])*
                $(#[doc($doc_tag)])?
                $(#[serde $serde])?
                $id $( ($arg) )?,
            )*
            /// No signature
            None
        }

        impl AlgorithmInstance {
            pub fn algorithm(&self) -> Algorithm {
                match self {
                    $(Self::$id $( (algorithms!(@ignore_arg $arg)) )? => Algorithm::$id,)*
                    Self::None => Algorithm::None
                }
            }
        }

        impl SignatureAlgorithmInstance for AlgorithmInstance {
            type Algorithm = Algorithm;

            fn algorithm(&self) -> Algorithm {
                self.algorithm()
            }
        }

        $(
            $(#[doc = $doc])*
            #[derive(Debug, Default, Clone, Copy, PartialEq, Hash, Eq)]
            pub struct $id;

            algorithms!(@instance $id $($arg)?);

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
    { @instance $id:ident } => {
        impl SignatureAlgorithmType for $id {
            type Instance = Self;
        }

        impl SignatureAlgorithmInstance for $id {
            type Algorithm = $id;

            fn algorithm(&self) -> $id {
                *self
            }
        }

        impl TryFrom<AlgorithmInstance> for $id {
            type Error = UnsupportedAlgorithm;

            fn try_from(a: AlgorithmInstance) -> Result<Self, Self::Error> {
                match a {
                    AlgorithmInstance::$id => Ok(Self),
                    other => Err(UnsupportedAlgorithm(other.algorithm()))
                }
            }
        }

        impl From<$id> for AlgorithmInstance {
            fn from(_: $id) -> Self {
                Self::$id
            }
        }
    };
    { @instance $id:ident $arg:ty } => {
        impl SignatureAlgorithmType for $id {
            type Instance = $arg;
        }

        impl SignatureAlgorithmInstance for $arg {
            type Algorithm = $id;

            fn algorithm(&self) -> $id {
                $id
            }
        }

        impl TryFrom<AlgorithmInstance> for $arg {
            type Error = UnsupportedAlgorithm;

            fn try_from(a: AlgorithmInstance) -> Result<Self, Self::Error> {
                match a {
                    AlgorithmInstance::$id(arg) => Ok(arg),
                    other => Err(UnsupportedAlgorithm(other.algorithm()))
                }
            }
        }

        impl From<$arg> for AlgorithmInstance {
            fn from(value: $arg) -> Self {
                Self::$id(value)
            }
        }
    };
    { @ignore_arg $arg:ty } => { _ };
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

    /// BBS scheme.
    Bbs(BbsInstance): "BBS",
    // Bbs: "BBS",

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
    Unsupported(Algorithm),
}

#[derive(Debug, thiserror::Error)]
#[error("unsupported signature algorithm `{0}`")]
pub struct UnsupportedAlgorithm(pub Algorithm);

/// ECDSA using secp256k1 (K-256) and SHA-256, with or without recovery bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AnyES256K {
    /// ECDSA using secp256k1 (K-256) and SHA-256, without recovery bit.
    ES256K,

    /// ECDSA using secp256k1 (K-256) and SHA-256, with recovery bit.
    ES256KR,
}

impl SignatureAlgorithmType for AnyES256K {
    type Instance = Self;
}

impl SignatureAlgorithmInstance for AnyES256K {
    type Algorithm = AnyES256K;

    fn algorithm(&self) -> AnyES256K {
        *self
    }
}

impl TryFrom<Algorithm> for AnyES256K {
    type Error = UnsupportedAlgorithm;

    fn try_from(value: Algorithm) -> Result<Self, Self::Error> {
        match value {
            Algorithm::ES256K => Ok(Self::ES256K),
            Algorithm::ES256KR => Ok(Self::ES256KR),
            other => Err(UnsupportedAlgorithm(other)),
        }
    }
}

impl From<AnyES256K> for Algorithm {
    fn from(value: AnyES256K) -> Self {
        match value {
            AnyES256K::ES256K => Self::ES256K,
            AnyES256K::ES256KR => Self::ES256KR,
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

/// ECDSA using secp256k1 (K-256) and SHA-256, with or without recovery bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AnyESKeccakK {
    /// ECDSA using secp256k1 (K-256) and Keccak-256.
    ///
    /// Like `ES256K` but using Keccak-256 instead of SHA-256.
    ESKeccakK,

    /// ECDSA using secp256k1 (K-256) and Keccak-256 with a recovery bit.
    ///
    /// Like `ES256K-R` but using Keccak-256 instead of SHA-256.
    ESKeccakKR,
}

impl SignatureAlgorithmType for AnyESKeccakK {
    type Instance = Self;
}

impl SignatureAlgorithmInstance for AnyESKeccakK {
    type Algorithm = AnyESKeccakK;

    fn algorithm(&self) -> AnyESKeccakK {
        *self
    }
}

impl TryFrom<Algorithm> for AnyESKeccakK {
    type Error = UnsupportedAlgorithm;

    fn try_from(value: Algorithm) -> Result<Self, Self::Error> {
        match value {
            Algorithm::ESKeccakK => Ok(Self::ESKeccakK),
            Algorithm::ESKeccakKR => Ok(Self::ESKeccakKR),
            other => Err(UnsupportedAlgorithm(other)),
        }
    }
}

impl From<AnyESKeccakK> for Algorithm {
    fn from(value: AnyESKeccakK) -> Self {
        match value {
            AnyESKeccakK::ESKeccakK => Self::ESKeccakK,
            AnyESKeccakK::ESKeccakKR => Self::ESKeccakKR,
        }
    }
}

impl From<AnyESKeccakK> for AlgorithmInstance {
    fn from(value: AnyESKeccakK) -> Self {
        match value {
            AnyESKeccakK::ESKeccakK => Self::ESKeccakK,
            AnyESKeccakK::ESKeccakKR => Self::ESKeccakKR,
        }
    }
}

impl From<ESKeccakK> for AnyESKeccakK {
    fn from(_value: ESKeccakK) -> Self {
        Self::ESKeccakK
    }
}

impl From<ESKeccakKR> for AnyESKeccakK {
    fn from(_value: ESKeccakKR) -> Self {
        Self::ESKeccakKR
    }
}

/// ECDSA using secp256k1 (K-256) and SHA-256, with or without recovery bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AnyES {
    /// ECDSA using secp256k1 (K-256) and SHA-256, without recovery bit.
    ES256K,

    /// ECDSA using secp256k1 (K-256) and SHA-256, with recovery bit.
    ES256KR,

    ESKeccakK,

    /// ECDSA using secp256k1 (K-256) and Keccak-256 with a recovery bit.
    ///
    /// Like `ES256K-R` but using Keccak-256 instead of SHA-256.
    ESKeccakKR,
}

impl SignatureAlgorithmType for AnyES {
    type Instance = Self;
}

impl SignatureAlgorithmInstance for AnyES {
    type Algorithm = AnyES;

    fn algorithm(&self) -> AnyES {
        *self
    }
}

impl TryFrom<Algorithm> for AnyES {
    type Error = UnsupportedAlgorithm;

    fn try_from(value: Algorithm) -> Result<Self, Self::Error> {
        match value {
            Algorithm::ES256K => Ok(Self::ES256K),
            Algorithm::ES256KR => Ok(Self::ES256KR),
            other => Err(UnsupportedAlgorithm(other)),
        }
    }
}

impl From<AnyES> for Algorithm {
    fn from(value: AnyES) -> Self {
        match value {
            AnyES::ES256K => Self::ES256K,
            AnyES::ES256KR => Self::ES256KR,
            AnyES::ESKeccakK => Self::ESKeccakK,
            AnyES::ESKeccakKR => Self::ESKeccakKR,
        }
    }
}

impl From<ES256K> for AnyES {
    fn from(_value: ES256K) -> Self {
        Self::ES256K
    }
}

impl From<ES256KR> for AnyES {
    fn from(_value: ES256KR) -> Self {
        Self::ES256KR
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AnyBlake2b {
    EdBlake2b,
    ESBlake2bK,
    ESBlake2b,
}

impl SignatureAlgorithmType for AnyBlake2b {
    type Instance = Self;
}

impl SignatureAlgorithmInstance for AnyBlake2b {
    type Algorithm = Self;

    fn algorithm(&self) -> AnyBlake2b {
        *self
    }
}

impl From<AnyBlake2b> for Algorithm {
    fn from(value: AnyBlake2b) -> Self {
        match value {
            AnyBlake2b::EdBlake2b => Self::EdBlake2b,
            AnyBlake2b::ESBlake2bK => Self::ESBlake2bK,
            AnyBlake2b::ESBlake2b => Self::ESBlake2b,
        }
    }
}

impl From<AnyBlake2b> for AlgorithmInstance {
    fn from(value: AnyBlake2b) -> Self {
        match value {
            AnyBlake2b::EdBlake2b => Self::EdBlake2b,
            AnyBlake2b::ESBlake2bK => Self::ESBlake2bK,
            AnyBlake2b::ESBlake2b => Self::ESBlake2b,
        }
    }
}

impl TryFrom<Algorithm> for AnyBlake2b {
    type Error = UnsupportedAlgorithm;

    fn try_from(value: Algorithm) -> Result<Self, Self::Error> {
        match value {
            Algorithm::EdBlake2b => Ok(Self::EdBlake2b),
            Algorithm::ESBlake2bK => Ok(Self::ESBlake2bK),
            Algorithm::ESBlake2b => Ok(Self::ESBlake2b),
            a => Err(UnsupportedAlgorithm(a)),
        }
    }
}

impl TryFrom<AlgorithmInstance> for AnyBlake2b {
    type Error = UnsupportedAlgorithm;

    fn try_from(value: AlgorithmInstance) -> Result<Self, Self::Error> {
        match value {
            AlgorithmInstance::EdBlake2b => Ok(Self::EdBlake2b),
            AlgorithmInstance::ESBlake2bK => Ok(Self::ESBlake2bK),
            AlgorithmInstance::ESBlake2b => Ok(Self::ESBlake2b),
            a => Err(UnsupportedAlgorithm(a.algorithm())),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ES256OrES384 {
    ES256,
    ES384,
}

impl ES256OrES384 {
    pub fn name(&self) -> &'static str {
        match self {
            Self::ES256 => "ES256",
            Self::ES384 => "ES384",
        }
    }
}

impl SignatureAlgorithmType for ES256OrES384 {
    type Instance = Self;
}

impl SignatureAlgorithmInstance for ES256OrES384 {
    type Algorithm = Self;

    fn algorithm(&self) -> Self {
        *self
    }
}

impl fmt::Display for ES256OrES384 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.name().fmt(f)
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

impl From<ES256OrES384> for AlgorithmInstance {
    fn from(value: ES256OrES384) -> Self {
        match value {
            ES256OrES384::ES256 => Self::ES256,
            ES256OrES384::ES384 => Self::ES384,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BbsInstance(pub Box<BbsParameters>);

#[derive(Debug, Clone)]
pub enum BbsParameters {
    Baseline {
        header: [u8; 64],
    },
    Blind {
        header: [u8; 64],
        commitment_with_proof: Option<Vec<u8>>,
        signer_blind: Option<[u8; 32]>,
    },
}
