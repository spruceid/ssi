//! <table>
//!     <thead>
//!         <tr>
//!             <th rowspan="2">
//!                 Key Type
//!             </th>
//!             <th colspan="4">
//!                 Algorithm
//!             </th>
//!         </tr>
//!         <tr>
//!             <th>
//!                 Name
//!             </th>
//!             <th>
//!                 Recovery bit
//!             </th>
//!             <th>
//!                 Digest Function
//!             </th>
//!             <th>
//!                 Signature Function
//!             </th>
//!         </tr>
//!     </thead>
//!     <tbody>
//!         <tr>
//!             <td rowspan="2">P-256</td>
//!             <td>ES256</td>
//!             <td></td>
//!             <td>SHA-256</td>
//!             <td rowspan="8">ECDSA</td>
//!         </tr>
//!         <tr>
//!             <td>ESBlake2b</td>
//!             <td></td>
//!             <td>Blake2b</td>
//!         </tr>
//!         <tr>
//!             <td>P-384</td>
//!             <td>ES384</td>
//!             <td></td>
//!             <td>SHA-384</td>
//!         </tr>
//!         <tr>
//!             <td rowspan="5">K-256</td>
//!             <td>ES256K</td>
//!             <td></td>
//!             <td rowspan="2">SHA-256</td>
//!         </tr>
//!         <tr>
//!             <td>ES256KR</td>
//!             <td>✓</td>
//!         </tr>
//!         <tr>
//!             <td>ESBlake2bK</td>
//!             <td></td>
//!             <td>Blake2b</td>
//!         </tr>
//!         <tr>
//!             <td>ESKeccakK</td>
//!             <td></td>
//!             <td rowspan="2">Keccak-256</td>
//!         </tr>
//!         <tr>
//!             <td>ESKeccakKR</td>
//!             <td>✓</td>
//!         </tr>
//!         <tr>
//!             <td>Ed25519</td>
//!             <td rowspan="2">EdDSA</td>
//!             <td rowspan="2"></td>
//!             <td rowspan="2">SHA-256</td>
//!             <td rowspan="2">EdDSA</td>
//!         </tr>
//!         <tr>
//!             <td>Ed448</td>
//!         </tr>
//!         <tr>
//!             <td rowspan="3">Bytes</td>
//!             <td>HS256</td>
//!             <td></td>
//!             <td>SHA-256</td>
//!             <td rowspan="3">HMAC</td>
//!         </tr>
//!         <tr>
//!             <td>HS384</td>
//!             <td></td>
//!             <td>SHA-384</td>
//!         </tr>
//!         <tr>
//!             <td>HS512</td>
//!             <td></td>
//!             <td>SHA-512</td>
//!         </tr>
//!         <tr>
//!             <td rowspan="6">RSA</td>
//!             <td>PS256</td>
//!             <td></td>
//!             <td>SHA-256</td>
//!             <td>RSASSA-PSS with MGF1+SHA-256</td>
//!         </tr>
//!         <tr>
//!             <td>PS384</td>
//!             <td></td>
//!             <td>SHA-384</td>
//!             <td>RSASSA-PSS with MGF1+SHA-384</td>
//!         </tr>
//!         <tr>
//!             <td>PS512</td>
//!             <td></td>
//!             <td>SHA-512</td>
//!             <td>RSASSA-PSS with MGF1+SHA-512</td>
//!         </tr>
//!         <tr>
//!             <td>RS256</td>
//!             <td></td>
//!             <td>SHA-256</td>
//!             <td rowspan="3">RSASSA-PKCS1 v1.5</td>
//!         </tr>
//!         <tr>
//!             <td>RS384</td>
//!             <td></td>
//!             <td>SHA-384</td>
//!         </tr>
//!         <tr>
//!             <td>RS512</td>
//!             <td></td>
//!             <td>SHA-512</td>
//!         </tr>
//!     </tbody>
//! </table>
use core::fmt;

use serde::{Deserialize, Serialize};

pub mod bbs;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SignatureFunction {
    /// BBS.
    Bbs,

    /// ECDSA
    EcDsa,

    /// EdDSA
    EdDsa,

    /// HMAC
    Hmac,

    /// RSASSA-PSS with MGF1+SHA-256
    RsaSsaPssMgf1Sha256,

    /// RSASSA-PSS with MGF1+SHA-384
    RsaSsaPssMgf1Sha384,

    /// RSASSA-PSS with MGF1+SHA-512
    RsaSsaPssMgf1Sha512,

    /// RSASSA-PKCS1 v1.5
    RsaSsaPkcs1v1_5,
}

impl SignatureFunction {
    pub fn is_rsa(self) -> bool {
        matches!(
            self,
            Self::RsaSsaPssMgf1Sha256
                | Self::RsaSsaPssMgf1Sha384
                | Self::RsaSsaPssMgf1Sha512
                | Self::RsaSsaPkcs1v1_5
        )
    }
}

/// Digest function.
pub enum DigestFunction {
    /// SHA-256
    Sha256,

    /// SHA-384
    Sha384,

    /// SHA-512
    Sha512,

    /// Blake2b
    Blake2b,

    /// Keccak-256
    Keccak256,
}

macro_rules! algorithms {
    ($(
        $(#[doc = $doc:tt])*
        $(#[doc($doc_tag:ident)])?
        $(#[serde $serde:tt])?
        $id:ident $( ($arg:ty) )? : $name:literal ($digest:ident, $signature:ident)
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
            None,
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

            pub fn digest_function(&self) -> Option<DigestFunction> {
                match self {
                    $(
                        Self::$id => Some(DigestFunction::$digest),
                    )*
                    Self::None => None
                }
            }

            pub fn signature_function(&self) -> Option<SignatureFunction> {
                match self {
                    $(
                        Self::$id => Some(SignatureFunction::$signature),
                    )*
                    Self::None => None
                }
            }

            pub fn functions(&self) -> Option<(SignatureFunction, DigestFunction)> {
                match self {
                    $(
                        Self::$id => Some((SignatureFunction::$signature, DigestFunction::$digest)),
                    )*
                    Self::None => None
                }
            }
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
    };
    { @ignore_arg $arg:ty } => { _ };
}

algorithms! {
    /// HMAC using SHA-256.
    ///
    /// See: <https://www.rfc-editor.org/rfc/rfc7518.txt>
    HS256: "HS256" (Sha256, Hmac),

    /// HMAC using SHA-384.
    ///
    /// See: <https://www.rfc-editor.org/rfc/rfc7518.txt>
    HS384: "HS384" (Sha384, Hmac),

    /// HMAC using SHA-512.
    ///
    /// See: <https://www.rfc-editor.org/rfc/rfc7518.txt>
    HS512: "HS512" (Sha512, Hmac),

    /// RSASSA-PKCS1-v1_5 using SHA-256.
    ///
    /// See: <https://www.rfc-editor.org/rfc/rfc7518.txt>
    RS256: "RS256" (Sha256, RsaSsaPkcs1v1_5),

    /// RSASSA-PKCS1-v1_5 using SHA-384.
    ///
    /// See: <https://www.rfc-editor.org/rfc/rfc7518.txt>
    RS384: "RS384" (Sha384, RsaSsaPkcs1v1_5),

    /// RSASSA-PKCS1-v1_5 using SHA-512.
    ///
    /// See: <https://www.rfc-editor.org/rfc/rfc7518.txt>
    RS512: "RS512" (Sha512, RsaSsaPkcs1v1_5),

    /// RSASSA-PSS using SHA-256 and MGF1 with SHA-256.
    ///
    /// See: <https://www.rfc-editor.org/rfc/rfc7518.txt>
    PS256: "PS256" (Sha256, RsaSsaPssMgf1Sha256),

    /// RSASSA-PSS using SHA-384 and MGF1 with SHA-384.
    ///
    /// See: <https://www.rfc-editor.org/rfc/rfc7518.txt>
    PS384: "PS384" (Sha256, RsaSsaPssMgf1Sha384),

    /// RSASSA-PSS using SHA-512 and MGF1 with SHA-512.
    ///
    /// See: <https://www.rfc-editor.org/rfc/rfc7518.txt>
    PS512: "PS512" (Sha512, RsaSsaPssMgf1Sha512),

    /// Edwards-curve Digital Signature Algorithm (EdDSA) using SHA-256.
    ///
    /// The following curves are defined for use with `EdDSA`:
    ///  - `Ed25519`
    ///  - `Ed448`
    ///
    /// See: <https://www.rfc-editor.org/rfc/rfc8037>
    EdDsa: "EdDSA" (Sha256, EdDsa),

    /// EdDSA using Blake2b.
    EdBlake2b: "EdBlake2b" (Blake2b, EdDsa),

    /// ECDSA using P-256 and SHA-256.
    ///
    /// See: <https://www.rfc-editor.org/rfc/rfc7518.txt>
    ES256: "ES256" (Sha256, EcDsa),

    /// ECDSA using P-384 and SHA-384.
    ///
    /// See: <https://www.rfc-editor.org/rfc/rfc7518.txt>
    ES384: "ES384" (Sha384, EcDsa),

    /// ECDSA using secp256k1 (K-256) and SHA-256.
    ///
    /// See: <https://datatracker.ietf.org/doc/html/rfc8812>
    ES256K: "ES256K" (Sha256, EcDsa),

    /// ECDSA using secp256k1 (K-256) and SHA-256 with a recovery bit.
    ///
    /// `ES256K-R` is similar to `ES256K` with the recovery bit appended, making
    /// the signature 65 bytes instead of 64. The recovery bit is used to
    /// extract the public key from the signature.
    ///
    /// See: <https://github.com/decentralized-identity/EcdsaSecp256k1RecoverySignature2020#es256k-r>
    ES256KR: "ES256K-R" (Sha256, EcDsa),

    /// ECDSA using secp256k1 (K-256) and Keccak-256.
    ///
    /// Like `ES256K` but using Keccak-256 instead of SHA-256.
    ESKeccakK: "ESKeccakK" (Keccak256, EcDsa),

    /// ECDSA using secp256k1 (K-256) and Keccak-256 with a recovery bit.
    ///
    /// Like `ES256K-R` but using Keccak-256 instead of SHA-256.
    ESKeccakKR: "ESKeccakKR" (Keccak256, EcDsa),

    /// ECDSA using P-256 and Blake2b.
    ESBlake2b: "ESBlake2b" (Blake2b, EcDsa),

    /// ECDSA using secp256k1 (K-256) and Blake2b.
    ESBlake2bK: "ESBlake2bK" (Blake2b, EcDsa),

    /// BBS scheme.
    Bbs(bbs::BbsInstance): "BBS" (Sha256, Bbs)
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
