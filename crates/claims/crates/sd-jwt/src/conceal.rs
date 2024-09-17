use std::borrow::Borrow;

use base64::Engine;
use rand::{thread_rng, CryptoRng, RngCore};
use serde::Serialize;
use serde_json::Value;
use ssi_claims_core::SignatureError;
use ssi_core::JsonPointer;
use ssi_jws::JwsSigner;
use ssi_jwt::JWTClaims;

use crate::{
    DecodedDisclosure, Disclosure, DisclosureDescription, SdAlg, SdJwtBuf, SdJwtPayload,
    ARRAY_CLAIM_ITEM_PROPERTY_NAME, SD_CLAIM_NAME,
};

/// Error that can occur during concealing.
#[derive(Debug, thiserror::Error)]
pub enum ConcealError {
    /// Serialization failed.
    #[error(transparent)]
    Serialization(#[from] serde_json::Error),

    /// Concealed JSON value is not an object.
    #[error("concealed JSON value is not an object")]
    NotAnObject,

    /// Tried to conceal the root object.
    #[error("cannot conceal root")]
    CannotConcealRoot,

    /// Value to conceal not found.
    #[error("value not found")]
    NotFound,

    /// The `_sd` entry is not an array.
    #[error("the `_sd` entry is not an array")]
    SdEntryNotAnArray,
}

/// JWT claims concealing methods.
pub trait ConcealJwtClaims {
    /// Conceals these JWT claims.
    fn conceal(
        &self,
        sd_alg: SdAlg,
        pointers: &[impl Borrow<JsonPointer>],
    ) -> Result<(SdJwtPayload, Vec<DecodedDisclosure<'static>>), ConcealError>;

    /// Conceals these JWT claims with the given `rng`.
    fn conceal_with(
        &self,
        sd_alg: SdAlg,
        pointers: &[impl Borrow<JsonPointer>],
        rng: impl CryptoRng + RngCore,
    ) -> Result<(SdJwtPayload, Vec<DecodedDisclosure<'static>>), ConcealError>;

    /// Conceals and signs these JWT claims.
    #[allow(async_fn_in_trait)]
    async fn conceal_and_sign(
        &self,
        sd_alg: SdAlg,
        pointers: &[impl Borrow<JsonPointer>],
        signer: impl JwsSigner,
    ) -> Result<SdJwtBuf, SignatureError>;

    /// Conceals and signs these JWT claims with the given `rng`.
    #[allow(async_fn_in_trait)]
    async fn conceal_and_sign_with(
        &self,
        sd_alg: SdAlg,
        pointers: &[impl Borrow<JsonPointer>],
        signer: impl JwsSigner,
        rng: impl CryptoRng + RngCore,
    ) -> Result<SdJwtBuf, SignatureError>;
}

impl<T: Serialize> ConcealJwtClaims for JWTClaims<T> {
    fn conceal(
        &self,
        sd_alg: SdAlg,
        pointers: &[impl Borrow<JsonPointer>],
    ) -> Result<(SdJwtPayload, Vec<DecodedDisclosure<'static>>), ConcealError> {
        SdJwtPayload::conceal(self, sd_alg, pointers)
    }

    fn conceal_with(
        &self,
        sd_alg: SdAlg,
        pointers: &[impl Borrow<JsonPointer>],
        rng: impl CryptoRng + RngCore,
    ) -> Result<(SdJwtPayload, Vec<DecodedDisclosure<'static>>), ConcealError> {
        SdJwtPayload::conceal_with(self, sd_alg, pointers, rng)
    }

    async fn conceal_and_sign(
        &self,
        sd_alg: SdAlg,
        pointers: &[impl Borrow<JsonPointer>],
        signer: impl JwsSigner,
    ) -> Result<SdJwtBuf, SignatureError> {
        SdJwtBuf::conceal_and_sign(self, sd_alg, pointers, signer).await
    }

    async fn conceal_and_sign_with(
        &self,
        sd_alg: SdAlg,
        pointers: &[impl Borrow<JsonPointer>],
        signer: impl JwsSigner,
        rng: impl CryptoRng + RngCore,
    ) -> Result<SdJwtBuf, SignatureError> {
        SdJwtBuf::conceal_and_sign_with(self, sd_alg, pointers, signer, rng).await
    }
}

impl SdJwtPayload {
    /// Conceal a value using the given JSON pointers, returning a SD-JWT
    /// payload and disclosures.
    pub fn conceal<T: Serialize>(
        value: &T,
        sd_alg: SdAlg,
        pointers: &[impl Borrow<JsonPointer>],
    ) -> Result<(Self, Vec<DecodedDisclosure<'static>>), ConcealError> {
        Self::conceal_with(value, sd_alg, pointers, thread_rng())
    }

    /// Conceal a value using the given JSON pointers, returning a SD-JWT
    /// payload and disclosures.
    pub fn conceal_with<T: Serialize>(
        value: &T,
        sd_alg: SdAlg,
        pointers: &[impl Borrow<JsonPointer>],
        rng: impl CryptoRng + RngCore,
    ) -> Result<(Self, Vec<DecodedDisclosure<'static>>), ConcealError> {
        match serde_json::to_value(value)? {
            Value::Object(obj) => Self::conceal_claims(obj, rng, sd_alg, pointers),
            _ => Err(ConcealError::NotAnObject),
        }
    }

    /// Conceal a JSON object using the given JSON pointers, returning a SD-JWT
    /// payload and disclosures.
    pub fn conceal_claims(
        mut claims: serde_json::Map<String, Value>,
        mut rng: impl CryptoRng + RngCore,
        sd_alg: SdAlg,
        pointers: &[impl Borrow<JsonPointer>],
    ) -> Result<(Self, Vec<DecodedDisclosure<'static>>), ConcealError> {
        let mut disclosures = Vec::with_capacity(pointers.len());

        // We sort the pointers here in order to visit parent pointers *after*
        // child pointers (e.g. `/foo` after `/foo/bar`). Pointers are sorted
        // parents-first in `sorted_pointers`, so we iterate over it in reverse.
        let mut sorted_pointers: Vec<_> = pointers.iter().map(Borrow::borrow).collect();
        sorted_pointers.sort_unstable();

        for pointer in sorted_pointers.into_iter().rev() {
            disclosures.push(conceal_object_at(&mut claims, &mut rng, sd_alg, pointer)?);
        }

        let concealed = Self { sd_alg, claims };

        Ok((concealed, disclosures))
    }
}

fn generate_salt(rng: &mut (impl CryptoRng + RngCore)) -> String {
    // TODO: link to rfc wrt suggested bit size of salt
    const DEFAULT_SALT_SIZE: usize = 128 / 8;
    let mut salt_bytes = [0u8; DEFAULT_SALT_SIZE];
    rng.fill_bytes(&mut salt_bytes);
    base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(salt_bytes)
}

fn conceal_at(
    value: &mut Value,
    rng: &mut (impl CryptoRng + RngCore),
    sd_alg: SdAlg,
    pointer: &JsonPointer,
) -> Result<DecodedDisclosure<'static>, ConcealError> {
    match value {
        Value::Object(object) => conceal_object_at(object, rng, sd_alg, pointer),
        Value::Array(array) => conceal_array_at(array, rng, sd_alg, pointer),
        _ => Err(ConcealError::CannotConcealRoot),
    }
}

fn conceal_object_at(
    object: &mut serde_json::Map<String, Value>,
    rng: &mut (impl CryptoRng + RngCore),
    sd_alg: SdAlg,
    pointer: &JsonPointer,
) -> Result<DecodedDisclosure<'static>, ConcealError> {
    let (token, rest) = pointer
        .split_first()
        .ok_or(ConcealError::CannotConcealRoot)?;

    let key = token.to_decoded();

    if rest.is_empty() {
        let value = object.remove(&*key).ok_or(ConcealError::NotFound)?;

        let disclosure = DecodedDisclosure::from_parts(
            generate_salt(rng),
            DisclosureDescription::ObjectEntry {
                key: key.into_owned(),
                value,
            },
        );

        add_disclosure(object, sd_alg, &disclosure.encoded)?;
        Ok(disclosure)
    } else {
        let value = object.get_mut(&*key).ok_or(ConcealError::NotFound)?;

        conceal_at(value, rng, sd_alg, rest)
    }
}

fn conceal_array_at(
    array: &mut [Value],
    rng: &mut (impl CryptoRng + RngCore),
    sd_alg: SdAlg,
    pointer: &JsonPointer,
) -> Result<DecodedDisclosure<'static>, ConcealError> {
    let (token, rest) = pointer
        .split_first()
        .ok_or(ConcealError::CannotConcealRoot)?;

    let i = token.as_array_index().ok_or(ConcealError::NotFound)?;

    let value = array.get_mut(i).ok_or(ConcealError::NotFound)?;

    if rest.is_empty() {
        let disclosure = DecodedDisclosure::from_parts(
            generate_salt(rng),
            DisclosureDescription::ArrayItem(value.take()),
        );

        *value = new_concealed_array_item(sd_alg, &disclosure.encoded);
        Ok(disclosure)
    } else {
        conceal_at(value, rng, sd_alg, pointer)
    }
}

fn new_concealed_array_item(sd_alg: SdAlg, disclosure: &Disclosure) -> Value {
    let mut object = serde_json::Map::new();
    object.insert(
        ARRAY_CLAIM_ITEM_PROPERTY_NAME.into(),
        sd_alg.hash(disclosure).into(),
    );
    Value::Object(object)
}

fn add_disclosure(
    object: &mut serde_json::Map<String, Value>,
    sd_alg: SdAlg,
    disclosure: &Disclosure,
) -> Result<(), ConcealError> {
    let sd = object
        .entry(SD_CLAIM_NAME.to_owned())
        .or_insert_with(|| Value::Array(Vec::new()))
        .as_array_mut()
        .ok_or(ConcealError::SdEntryNotAnArray)?;

    sd.push(sd_alg.hash(disclosure).into());
    Ok(())
}
