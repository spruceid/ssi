use spki::{der::Decode, ObjectIdentifier};

use super::{KeyConversionError, PublicKey};

impl PublicKey {
    /// Parses a DER-encoded X.509 `SubjectPublicKeyInfo` (SPKI) as defined in
    /// [RFC 5280 § 4.1.2.7] into a public key.
    ///
    /// [RFC 5280 § 4.1.2.7]: <https://tools.ietf.org/html/rfc5280#section-4.1.2.7>
    pub fn from_spki_der_bytes(bytes: &[u8]) -> Result<Self, KeyConversionError> {
        let spki = spki::SubjectPublicKeyInfoOwned::from_der(bytes)
            .map_err(|_| KeyConversionError::Invalid)?;
        Self::from_spki(&spki)
    }

    /// Converts an SPKI into a public key.
    pub fn from_spki(spki: &spki::SubjectPublicKeyInfoOwned) -> Result<Self, KeyConversionError> {
        match spki.algorithm.oid {
            OID_ECDSA => {
                let Some(params) = &spki.algorithm.parameters else {
                    return Err(KeyConversionError::Invalid);
                };

                let curve = params
                    .decode_as::<ObjectIdentifier>()
                    .map_err(|_| KeyConversionError::Invalid)?;

                match curve {
                    #[cfg(feature = "secp256r1")]
                    OID_ECDSA_CURVE_P256 => {
                        Self::from_ecdsa_p256_sec1_bytes(spki.subject_public_key.raw_bytes())
                    }
                    #[cfg(feature = "secp384r1")]
                    OID_ECDSA_CURVE_P384 => {
                        Self::from_ecdsa_p384_sec1_bytes(spki.subject_public_key.raw_bytes())
                    }
                    #[cfg(feature = "secp256k1")]
                    OID_ECDSA_CURVE_K256 => {
                        Self::from_ecdsa_k256_sec1_bytes(spki.subject_public_key.raw_bytes())
                    }
                    _ => Err(KeyConversionError::Unsupported),
                }
            }
            #[cfg(feature = "ed25519")]
            OID_ED25519 => Self::from_ed25519_bytes(spki.subject_public_key.raw_bytes()),
            #[cfg(feature = "rsa")]
            OID_RSA => Self::from_rsa_pkcs1_der(spki.subject_public_key.raw_bytes()),
            _ => Err(KeyConversionError::Unsupported),
        }
    }
}

/// RSA public key.
///
/// See: <https://www.rfc-editor.org/rfc/rfc3447#appendix-A.1>
#[cfg(feature = "rsa")]
const OID_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// ECDSA public key.
///
/// See: <https://www.rfc-editor.org/rfc/rfc5480#section-2.1.1>
const OID_ECDSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

/// ECDSA P-256 (secp256r1) curve.
///
/// See: <https://www.rfc-editor.org/rfc/rfc5480#section-2.1.1.1>
#[cfg(feature = "secp256r1")]
const OID_ECDSA_CURVE_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

/// ECDSA P-384 (secp384r1) curve.
///
/// See: <https://www.rfc-editor.org/rfc/rfc5480#section-2.1.1.1>
#[cfg(feature = "secp384r1")]
const OID_ECDSA_CURVE_P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");

/// ECDSA K-256 (secp256k1) curve.
///
/// See: <https://www.secg.org/sec2-v2.pdf>
#[cfg(feature = "secp256k1")]
const OID_ECDSA_CURVE_K256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.10");

/// Ed25519 public key.
///
/// See: <https://www.rfc-editor.org/rfc/rfc8410#section-3>
#[cfg(feature = "ed25519")]
const OID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
