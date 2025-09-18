use core::fmt;
use std::{collections::BTreeMap, fmt::Debug};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ssi_core::de::DeserializeTyped;
use ssi_verification_methods::{ReferenceOrOwned, ReferenceOrOwnedRef};

use crate::Type;

use super::{CryptographicSuite, StandardCryptographicSuite};

pub trait DebugCryptographicSuite: CryptographicSuite + Debug {
    fn fmt_prepared_claims(claims: &Self::PreparedClaims, f: &mut fmt::Formatter) -> fmt::Result;

    fn fmt_verification_method(
        verification_method: &Self::VerificationMethod,
        f: &mut fmt::Formatter,
    ) -> fmt::Result;

    fn fmt_verification_method_ref(
        verification_method: &ReferenceOrOwnedRef<Self::VerificationMethod>,
        f: &mut fmt::Formatter,
    ) -> fmt::Result;

    fn fmt_proof_options(options: &Self::ProofOptions, f: &mut fmt::Formatter) -> fmt::Result;

    fn fmt_signature(signature: &Self::Signature, f: &mut fmt::Formatter) -> fmt::Result;
}

impl<S: CryptographicSuite + Debug> DebugCryptographicSuite for S
where
    Self::PreparedClaims: Debug,
    Self::VerificationMethod: Debug,
    Self::ProofOptions: Debug,
    Self::Signature: Debug,
{
    fn fmt_prepared_claims(claims: &Self::PreparedClaims, f: &mut fmt::Formatter) -> fmt::Result {
        claims.fmt(f)
    }

    fn fmt_verification_method(
        verification_method: &Self::VerificationMethod,
        f: &mut fmt::Formatter,
    ) -> fmt::Result {
        verification_method.fmt(f)
    }

    fn fmt_verification_method_ref(
        verification_method: &ReferenceOrOwnedRef<Self::VerificationMethod>,
        f: &mut fmt::Formatter,
    ) -> fmt::Result {
        verification_method.fmt(f)
    }

    fn fmt_proof_options(options: &Self::ProofOptions, f: &mut fmt::Formatter) -> fmt::Result {
        options.fmt(f)
    }

    fn fmt_signature(signature: &Self::Signature, f: &mut fmt::Formatter) -> fmt::Result {
        signature.fmt(f)
    }
}

pub trait CloneCryptographicSuite: CryptographicSuite {
    fn clone_prepared_claims(claims: &Self::PreparedClaims) -> Self::PreparedClaims;

    fn clone_verification_method(
        verification_method: &Self::VerificationMethod,
    ) -> Self::VerificationMethod;

    fn clone_verification_method_ref(
        verification_method: &ReferenceOrOwned<Self::VerificationMethod>,
    ) -> ReferenceOrOwned<Self::VerificationMethod>;

    fn clone_verification_method_ref_ref(
        verification_method: ReferenceOrOwnedRef<Self::VerificationMethod>,
    ) -> ReferenceOrOwned<Self::VerificationMethod>;

    fn clone_proof_options(options: &Self::ProofOptions) -> Self::ProofOptions;

    fn clone_signature(signature: &Self::Signature) -> Self::Signature;
}

impl<S: CryptographicSuite> CloneCryptographicSuite for S
where
    Self::PreparedClaims: Clone,
    Self::VerificationMethod: Clone,
    Self::ProofOptions: Clone,
    Self::Signature: Clone,
{
    fn clone_prepared_claims(claims: &Self::PreparedClaims) -> Self::PreparedClaims {
        claims.clone()
    }

    fn clone_verification_method(
        verification_method: &Self::VerificationMethod,
    ) -> Self::VerificationMethod {
        verification_method.clone()
    }

    fn clone_verification_method_ref(
        verification_method: &ReferenceOrOwned<Self::VerificationMethod>,
    ) -> ReferenceOrOwned<Self::VerificationMethod> {
        verification_method.clone()
    }

    fn clone_verification_method_ref_ref(
        verification_method: ReferenceOrOwnedRef<Self::VerificationMethod>,
    ) -> ReferenceOrOwned<Self::VerificationMethod> {
        verification_method.cloned()
    }

    fn clone_proof_options(options: &Self::ProofOptions) -> Self::ProofOptions {
        options.clone()
    }

    fn clone_signature(signature: &Self::Signature) -> Self::Signature {
        signature.clone()
    }
}

pub trait SerializeCryptographicSuite: CryptographicSuite {
    fn serialize_type<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.type_().serialize(serializer)
    }

    fn serialize_verification_method<S: Serializer>(
        verification_method: &Self::VerificationMethod,
        serializer: S,
    ) -> Result<S::Ok, S::Error>;

    fn serialize_verification_method_ref<S: Serializer>(
        verification_method: &ReferenceOrOwned<Self::VerificationMethod>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>;

    fn serialize_verification_method_ref_ref<S: Serializer>(
        verification_method: &ReferenceOrOwnedRef<Self::VerificationMethod>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>;

    fn serialize_proof_options<S: Serializer>(
        proof_options: &Self::ProofOptions,
        serializer: S,
    ) -> Result<S::Ok, S::Error>;

    fn serialize_signature<S: Serializer>(
        signature: &Self::Signature,
        serializer: S,
    ) -> Result<S::Ok, S::Error>;
}

impl<T: CryptographicSuite> SerializeCryptographicSuite for T
where
    Self::VerificationMethod: Serialize,
    Self::ProofOptions: Serialize,
    Self::Signature: Serialize,
{
    fn serialize_verification_method<S: Serializer>(
        verification_method: &Self::VerificationMethod,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        verification_method.serialize(serializer)
    }

    fn serialize_verification_method_ref<S: Serializer>(
        verification_method: &ReferenceOrOwned<Self::VerificationMethod>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        verification_method.serialize(serializer)
    }

    fn serialize_verification_method_ref_ref<S: Serializer>(
        verification_method: &ReferenceOrOwnedRef<Self::VerificationMethod>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        verification_method.serialize(serializer)
    }

    fn serialize_proof_options<S: Serializer>(
        proof_options: &Self::ProofOptions,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        proof_options.serialize(serializer)
    }

    fn serialize_signature<S: Serializer>(
        signature: &Self::Signature,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        signature.serialize(serializer)
    }
}

pub trait DeserializeCryptographicSuite<'de>:
    CryptographicSuite<
        VerificationMethod: Deserialize<'de>,
        ProofOptions: Deserialize<'de>,
        Signature: Deserialize<'de>,
    > + TryFrom<Type>
{
    fn deserialize_verification_method<D: Deserializer<'de>>(
        &self,
        deserializer: D,
    ) -> Result<Self::VerificationMethod, D::Error>;

    fn deserialize_proof_options<D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self::ProofOptions, D::Error>;

    fn deserialize_signature<D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self::Signature, D::Error>;
}

#[derive(Deserialize)]
pub struct ExtraPropertiesPreparedProof<S: CryptographicSuite> {
    #[serde(flatten)]
    #[serde(bound(deserialize = "S::ProofOptions: Deserialize<'de>"))]
    pub options: S::ProofOptions,
    #[serde(flatten)]
    pub extra_properties: BTreeMap<String, json_syntax::Value>,
}

#[derive(Deserialize)]
pub struct ExtraPropertiesFinalizedProof<S: CryptographicSuite> {
    #[serde(flatten)]
    #[serde(bound(deserialize = "S::ProofOptions: Deserialize<'de>"))]
    pub options: S::ProofOptions,
    #[serde(flatten)]
    #[serde(bound(deserialize = "S::Signature: Deserialize<'de>"))]
    pub signature: S::Signature,
    #[serde(flatten)]
    pub extra_properties: BTreeMap<String, json_syntax::Value>,
}

pub trait DeserializeCryptographicSuiteMultiplexing<'de>:
    DeserializeCryptographicSuite<'de>
{
    fn deserialize_extra_properties_finalized_proof(
        &self,
        other: json_syntax::Object,
    ) -> Result<ExtraPropertiesFinalizedProof<Self>, json_syntax::DeserializeError> {
        ExtraPropertiesFinalizedProof::<Self>::deserialize(json_syntax::Value::Object(other))
    }

    fn deserialize_extra_properties_prepared_proof(
        &self,
        other: json_syntax::Object,
    ) -> Result<ExtraPropertiesPreparedProof<Self>, json_syntax::DeserializeError> {
        ExtraPropertiesPreparedProof::<Self>::deserialize(json_syntax::Value::Object(other))
    }
}

impl<'de, T> DeserializeCryptographicSuiteMultiplexing<'de> for T where
    T: DeserializeCryptographicSuite<'de> + StandardCryptographicSuite
{
}

impl<'de, S: CryptographicSuite + TryFrom<Type>> DeserializeCryptographicSuite<'de> for S
where
    Self::VerificationMethod: Deserialize<'de>,
    Self::ProofOptions: Deserialize<'de>,
    Self::Signature: Deserialize<'de>,
{
    fn deserialize_verification_method<D: Deserializer<'de>>(
        &self,
        deserializer: D,
    ) -> Result<Self::VerificationMethod, D::Error> {
        Self::VerificationMethod::deserialize_typed(self, deserializer)
    }

    fn deserialize_proof_options<D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self::ProofOptions, D::Error> {
        Self::ProofOptions::deserialize(deserializer)
    }

    fn deserialize_signature<D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self::Signature, D::Error> {
        Self::Signature::deserialize(deserializer)
    }
}

pub trait DeserializeCryptographicSuiteOwned:
    CryptographicSuite + for<'de> DeserializeCryptographicSuiteMultiplexing<'de>
{
}

impl<S> DeserializeCryptographicSuiteOwned for S where
    S: for<'de> DeserializeCryptographicSuiteMultiplexing<'de>
{
}

pub struct VerificationMethodOf<S: CryptographicSuite>(pub S::VerificationMethod);

impl<S: CryptographicSuite> VerificationMethodOf<S> {
    pub fn unwrap(self) -> S::VerificationMethod {
        self.0
    }
}

impl<'de, T: DeserializeCryptographicSuite<'de>> DeserializeTyped<'de, T>
    for VerificationMethodOf<T>
{
    fn deserialize_typed<S>(type_: &T, deserializer: S) -> Result<Self, S::Error>
    where
        S: serde::Deserializer<'de>,
    {
        type_
            .deserialize_verification_method(deserializer)
            .map(Self)
    }
}

pub struct VerificationMethodRefOf<'a, S: CryptographicSuite>(
    pub ReferenceOrOwnedRef<'a, S::VerificationMethod>,
);

impl<S: DebugCryptographicSuite> fmt::Debug for VerificationMethodRefOf<'_, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        S::fmt_verification_method_ref(&self.0, f)
    }
}

pub struct OptionsOf<S: CryptographicSuite>(pub S::ProofOptions);

pub struct OptionsRefOf<'a, S: CryptographicSuite>(pub &'a S::ProofOptions);

impl<S: DebugCryptographicSuite> fmt::Debug for OptionsRefOf<'_, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        S::fmt_proof_options(self.0, f)
    }
}

pub struct SignatureOf<S: CryptographicSuite>(pub S::Signature);

pub struct SignatureRefOf<'a, S: CryptographicSuite>(pub &'a S::Signature);

impl<S: DebugCryptographicSuite> fmt::Debug for SignatureRefOf<'_, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        S::fmt_signature(self.0, f)
    }
}
