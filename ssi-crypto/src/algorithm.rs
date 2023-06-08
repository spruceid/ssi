pub enum Algorithm {
    /// HMAC using SHA256.
    HS256,

    /// HMAC using SHA384.
    HS384,

    /// HMAC using SHA512.
    HS512,

    /// RSASSA-PKCS1-v1_5 using SHA-256.
    RS256,

    /// RSASSA-PKCS1-v1_5 using SHA-384.
    RS384,

    /// RSASSA-PKCS1-v1_5 using SHA-512.
    RS512,

    /// RSASSA-PSS using SHA-256 and MGF1 with SHA-256.
    PS256,

    /// RSASSA-PSS using SHA-384 and MGF1 with SHA-384.
    PS384,

    /// RSASSA-PSS using SHA-512 and MGF1 with SHA-512.
    PS512,

    /// Edwards-Curve Digital Signature Algorithm ([RFC8032]).
    ///
    /// [RFC8032]: <https://www.rfc-editor.org/rfc/rfc8032>
    EdDSA,

    EdBlake2b,

    /// ECDSA using P-256 and SHA-256.
    ES256,

    /// ECDSA using P-384 and SHA-384.
    ES384,

    /// ECDSA using secp256k1.
    ES256K,

    /// <https://github.com/decentralized-identity/EcdsaSecp256k1RecoverySignature2020#es256k-r>
    ES256KR,

    /// like ES256K-R but using Keccak-256 instead of SHA-256
    ESKeccakKR,

    ESBlake2b,

    ESBlake2bK,
}

#[derive(Debug, thiserror::Error)]
#[error("unsupported cryptographic algorithm")]
pub struct UnsupportedAlgorithm;
