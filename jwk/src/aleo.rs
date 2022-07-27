//! Functionality related to [Aleo] blockchain network.
//!
//! Required crate feature: `aleosig`
//!
//! [Aleo]: https://developer.aleo.org/testnet/getting_started/overview#the-network
//!
//! This module provides [sign] and [verify] functions for Aleo signatures
//! using static parameters ([COM_PARAMS], [ENC_PARAMS], [SIG_PARAMS])
//! and a [JWK-based keypair representation](OKP_CURVE).

use crate::{Base64urlUInt, OctetParams, Params, JWK};
use thiserror::Error;

use blake2::Blake2s;
use snarkvm_algorithms::{
    commitment::{PedersenCommitmentParameters, PedersenCompressedCommitment},
    encryption::{GroupEncryption, GroupEncryptionParameters},
    signature::{Schnorr, SchnorrParameters},
};
use snarkvm_curves::edwards_bls12::{EdwardsAffine, EdwardsProjective};
use snarkvm_dpc::{
    account::{Address, PrivateKey},
    testnet1::instantiated::Components,
};
use snarkvm_parameters::{
    global::{
        AccountCommitmentParameters, AccountEncryptionParameters, AccountSignatureParameters,
    },
    Parameter,
};
use snarkvm_utilities::{FromBytes, ToBytes};

/// An error resulting from attempting to [generate a JWK Aleo private key](generate_private_key_jwk).
#[derive(Error, Debug)]
pub enum AleoGeneratePrivateKeyError {
    #[error("Unable to generate new key: {0}")]
    NewKey(#[source] snarkvm_dpc::AccountError),
    #[error("Unable to base58-decode new key: {0}")]
    DecodePrivateKey(#[source] bs58::decode::Error),
    #[error("Unable to convert private key to account address: {0}")]
    PrivateKeyToAddress(#[source] snarkvm_dpc::AccountError),
    #[error("Unable to write account address as bytes: {0}")]
    WriteAddress(#[source] std::io::Error),
}

/// An error resulting from attempting to convert a [JWK] to an Aleo private key.
///
/// The expected JWK format is described in [OKP_CURVE].
#[derive(Error, Debug)]
pub enum ParsePrivateKeyError {
    #[error("Unexpected JWK OKP curve: {0}")]
    UnexpectedCurve(String),
    #[error("Unexpected JWK key type. Expected \"OKP\"")]
    ExpectedOKP,
    #[error("Missing private key (\"d\") OKP JWK parameter")]
    MissingPrivateKey,
    #[error("Unable to deserialize private key: {0}")]
    PrivateKeyFromStr(#[source] snarkvm_dpc::AccountError),
    #[error("Unable to convert JWK to account address: {0}")]
    JWKToAddress(#[source] ParseAddressError),
    #[error("Unable to convert private key to account address: {0}")]
    PrivateKeyToAddress(#[source] snarkvm_dpc::AccountError),
    #[error("Address mismatch. Computed: {}, expected: {}", .computed, .expected)]
    AddressMismatch {
        computed: Address<Components>,
        expected: Address<Components>,
    },
}

/// An error resulting from attempting to convert a [JWK] to an Aleo account address.
///
/// The expected JWK format is described in [OKP_CURVE].
#[derive(Error, Debug)]
pub enum ParseAddressError {
    #[error("Unexpected JWK OKP curve: {0}")]
    UnexpectedCurve(String),
    #[error("Unexpected JWK key type. Expected \"OKP\"")]
    ExpectedOKP,
    #[error("Unable to read address from bytes: {0}")]
    ReadAddress(#[source] std::io::Error),
}

lazy_static::lazy_static! {
    /// Aleo account signature parameters
    pub static ref SIG_PARAMS: Schnorr<EdwardsAffine, Blake2s> = {
        SchnorrParameters::read_le(AccountSignatureParameters::load_bytes().unwrap().as_slice())
            .unwrap()
            .into()
    };

    /// Aleo account commitment parameters
    pub static ref COM_PARAMS: PedersenCompressedCommitment<EdwardsProjective, 8, 192> = {
            let com_params_bytes = AccountCommitmentParameters::load_bytes().unwrap();
        PedersenCommitmentParameters::read_le(com_params_bytes.as_slice())
            .unwrap()
            .into()
    };

    /// Aleo account encryption parameters
    pub static ref ENC_PARAMS: GroupEncryption<EdwardsProjective, EdwardsAffine, Blake2s> = {
        let enc_params_bytes = AccountEncryptionParameters::load_bytes()
                .unwrap();
        GroupEncryptionParameters::read_le(
            enc_params_bytes
                .as_slice(),
        )
        .unwrap()
        .into()
    };
}

/// Unregistered JWK OKP curve for Aleo private keys in Aleo Testnet 1
///
/// OKP key type is defined in [RFC 8037].
///
/// [RFC 8037]: https://datatracker.ietf.org/doc/html/rfc8037
///
/// This curve type is intended to be used for Aleo private keys as follows:
///
/// - key type ("kty"): "OKP"
/// - private key ("d") parameter: base64url-encoded Aleo private key (without Base58 encoding)
/// - public key ("x") parameter: base64url-encoded Aleo account address (without Base58 encoding)
///
/// An Aleo private key JWK is expected to contain an account address in the public key ("x")
/// parameter that corresponds to the private key ("d") parameter,
/// using [SIG_PARAMS], [COM_PARAMS] and [ENC_PARAMS].
///
/// An Aleo public key JWK contains the public key ("x") parameter and MUST not contain a private
/// key ("d") parameter. An Aleo public key JWK is usable for verification of signatures using
/// [ENC_PARAMS].
pub const OKP_CURVE: &str = "AleoTestnet1Key";

/// Generate an Aleo private key in [unofficial JWK format][OKP_CURVE]. **CPU-intensive (slow)**.
///
/// Uses [SIG_PARAMS], [COM_PARAMS], and [ENC_PARAMS].
pub fn generate_private_key_jwk() -> Result<JWK, AleoGeneratePrivateKeyError> {
    let mut rng = rand::rngs::OsRng {};
    let sig_params = SIG_PARAMS.clone();
    let com_params = COM_PARAMS.clone();
    let enc_params = ENC_PARAMS.clone();
    let private_key = PrivateKey::<Components>::new(&sig_params, &com_params, &mut rng)
        .map_err(AleoGeneratePrivateKeyError::NewKey)?;
    let private_key_bytes = bs58::decode(private_key.to_string())
        .into_vec()
        .map_err(AleoGeneratePrivateKeyError::DecodePrivateKey)?;
    let address = Address::from_private_key(&sig_params, &com_params, &enc_params, &private_key)
        .map_err(AleoGeneratePrivateKeyError::PrivateKeyToAddress)?;
    let mut public_key_bytes = Vec::new();
    address
        .write_le(&mut public_key_bytes)
        .map_err(AleoGeneratePrivateKeyError::WriteAddress)?;
    Ok(JWK::from(Params::OKP(OctetParams {
        curve: OKP_CURVE.to_string(),
        public_key: Base64urlUInt(public_key_bytes),
        private_key: Some(Base64urlUInt(private_key_bytes)),
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_private_key_jwk() {
        let key: JWK =
            serde_json::from_str(include_str!("../tests/aleotestnet1-2021-11-22.json")).unwrap();
        let private_key = aleo_jwk_to_private_key(&key).unwrap();
        let private_key_str = private_key.to_string();
        assert_eq!(
            private_key_str,
            "APrivateKey1w7oJWmo86D26Efs6hBfz8xK7M4ww2jmA5WT3QdmYefVnZdS"
        );
        let address = Address::from_private_key(
            &SIG_PARAMS.clone(),
            &COM_PARAMS.clone(),
            &ENC_PARAMS.clone(),
            &private_key,
        )
        .unwrap();
        assert_eq!(
            address.to_string(),
            "aleo1al8unplh8vtsuwna0h6u2t6g0hvr7t0tnfkem2we5gj7t70aeuxsd94hsy"
        );
    }
}
