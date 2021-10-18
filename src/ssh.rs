use crate::jwk::{Base64urlUInt, Params as JWKParams, JWK};
use sshkeys::PublicKeyKind;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SSHKeyToJWKError {
    #[error("SSH key: {0}")]
    SSHKey(#[from] sshkeys::Error),
    #[error("Unsupported ssh-dsa key")]
    UnsupportedDsaKey,
    #[error("P-256 parse error: {0}")]
    P256Parse(String),
    #[error("Unsupported ECDSA key type: {0}")]
    UnsupportedEcdsaKey(String),
    #[error("Missing features: {0}")]
    MissingFeatures(&'static str),
}

fn pk_to_jwk_rsa(pk: &sshkeys::RsaPublicKey) -> JWK {
    JWK::from(JWKParams::RSA(crate::jwk::RSAParams {
        exponent: Some(Base64urlUInt(pk.e.clone())),
        modulus: Some(Base64urlUInt(pk.n.clone())),
        ..Default::default()
    }))
}

fn pk_to_jwk_ecdsa(pk: &sshkeys::EcdsaPublicKey) -> Result<JWK, SSHKeyToJWKError> {
    match pk.curve.kind {
        sshkeys::CurveKind::Nistp256 => {
            #[cfg(not(feature = "p256"))]
            {
                Err(SSHKeyToJWKError::MissingFeatures("p256"))
            }
            #[cfg(feature = "p256")]
            {
                crate::jwk::p256_parse(&pk.key)
                    .map_err(|e| SSHKeyToJWKError::P256Parse(e.to_string()))
            }
        }
        _ => Err(SSHKeyToJWKError::UnsupportedEcdsaKey(
            pk.curve.identifier.to_string(),
        )),
    }
}

fn pk_to_jwk_ed25519(pk: &sshkeys::Ed25519PublicKey) -> JWK {
    JWK::from(JWKParams::OKP(crate::jwk::OctetParams {
        curve: "Ed25519".to_string(),
        public_key: Base64urlUInt(pk.key.clone()),
        private_key: None,
    }))
}

/// Convert a SSH public key to a JWK.
pub fn ssh_pkk_to_jwk(pkk: &PublicKeyKind) -> Result<JWK, SSHKeyToJWKError> {
    // https://datatracker.ietf.org/doc/html/rfc4253#section-6.6
    // https://datatracker.ietf.org/doc/html/rfc5656#section-3.1
    // https://datatracker.ietf.org/doc/html/draft-ietf-curdle-ssh-ed25519-02#section-4
    let jwk = match pkk {
        PublicKeyKind::Rsa(pk) => pk_to_jwk_rsa(pk),
        PublicKeyKind::Dsa(_) => return Err(SSHKeyToJWKError::UnsupportedDsaKey),
        PublicKeyKind::Ecdsa(pk) => pk_to_jwk_ecdsa(pk)?,
        PublicKeyKind::Ed25519(pk) => pk_to_jwk_ed25519(pk),
    };
    Ok(jwk)
}
