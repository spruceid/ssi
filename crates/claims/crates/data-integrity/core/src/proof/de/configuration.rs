use crate::{
    suite::bounds::{DeserializeCryptographicSuiteMultiplexing, VerificationMethodOf},
    CryptosuiteString, ProofConfiguration, Type,
};
use serde::de::{Error, MapAccess};
use ssi_core::de::WithType;
use std::marker::PhantomData;

use super::{Field, RefOrValue, ReplayMap, TypeField};

impl<'de, T> ProofConfiguration<T>
where
    T: DeserializeCryptographicSuiteMultiplexing<'de>,
{
    fn deserialize_with_type<S>(type_: Type, mut deserializer: S) -> Result<Self, S::Error>
    where
        S: serde::de::MapAccess<'de>,
    {
        let suite: T = type_
            .try_into()
            .map_err(|_| serde::de::Error::custom("unexpected cryptosuite"))?;

        let mut context = None;
        let mut created = None;
        let mut verification_method = None;
        let mut proof_purpose = None;
        let mut expires = None;
        let mut domains = None;
        let mut challenge = None;
        let mut nonce = None;

        let mut other = json_syntax::Object::new();

        while let Some(key) = deserializer.next_key::<Field>()? {
            match key {
                Field::Context => context = Some(deserializer.next_value()?),
                Field::Created => created = Some(deserializer.next_value()?),
                Field::VerificationMethod => {
                    verification_method = Some({
                        deserializer
                            .next_value_seed(
                                WithType::<T, RefOrValue<VerificationMethodOf<T>>>::new(&suite),
                            )?
                    })
                }
                Field::ProofPurpose => proof_purpose = Some(deserializer.next_value()?),
                Field::Expires => expires = Some(deserializer.next_value()?),
                Field::Domains => domains = Some(deserializer.next_value()?),
                Field::Challenge => challenge = Some(deserializer.next_value()?),
                Field::Nonce => nonce = Some(deserializer.next_value()?),
                Field::Other(key) => {
                    other.insert(key.into(), deserializer.next_value::<json_syntax::Value>()?);
                }
            }
        }

        let interim_extra_properties = suite
            .deserialize_extra_properties_prepared_proof(other)
            .map_err(S::Error::custom)?;

        Ok(Self {
            context,
            type_: suite,
            created,
            verification_method: verification_method
                .map(|v| v.map(VerificationMethodOf::unwrap).into())
                .ok_or_else(|| serde::de::Error::custom("missing `verificationMethod` property"))?,
            proof_purpose: proof_purpose
                .ok_or_else(|| serde::de::Error::custom("missing `proofPurpose` property"))?,
            expires,
            domains: domains.unwrap_or_default(),
            challenge,
            nonce,
            options: interim_extra_properties.options,
            extra_properties: interim_extra_properties.extra_properties,
        })
    }
}

impl<'de, T> serde::Deserialize<'de> for ProofConfiguration<T>
where
    T: DeserializeCryptographicSuiteMultiplexing<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(ProofConfigurationVisitor(PhantomData))
    }
}

struct ProofConfigurationVisitor<T>(PhantomData<T>);

impl<'de, T> serde::de::Visitor<'de> for ProofConfigurationVisitor<T>
where
    T: DeserializeCryptographicSuiteMultiplexing<'de>,
{
    type Value = ProofConfiguration<T>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "Data-Integrity proof")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keep = Vec::new();
        let mut cryptosuite = None;
        let mut data_integrity_proof = false;

        while let Some(key) = map.next_key::<TypeField>()? {
            match key {
                TypeField::Type => {
                    let name = map.next_value::<String>()?;

                    if name == "DataIntegrityProof" {
                        match cryptosuite.take() {
                            Some(c) => {
                                return ProofConfiguration::<T>::deserialize_with_type(
                                    Type::DataIntegrityProof(c),
                                    ReplayMap::new(keep, map),
                                );
                            }
                            None => {
                                data_integrity_proof = true;
                            }
                        }
                    } else {
                        return ProofConfiguration::<T>::deserialize_with_type(
                            Type::Other(name),
                            ReplayMap::new(keep, map),
                        );
                    }
                }
                TypeField::Cryptosuite => {
                    let name = map.next_value::<CryptosuiteString>()?;
                    if data_integrity_proof {
                        return ProofConfiguration::<T>::deserialize_with_type(
                            Type::DataIntegrityProof(name),
                            ReplayMap::new(keep, map),
                        );
                    } else {
                        cryptosuite = Some(name)
                    }
                }
                TypeField::Other(key) => {
                    keep.push((key, map.next_value()?));
                }
            }
        }

        Err(serde::de::Error::custom("missing type"))
    }
}
