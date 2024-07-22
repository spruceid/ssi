//! Proof deserialization primitives.
//!
//! Deserializing a Data-Integrity proof while preserving type information can
//! be tricky, in particular when the considered cryptographic suite type
//! abstracts multiple actual cryptographic suite implementations.
//! In this case, it may be necessary to know the proof `type`
//! (and `cryptosuite`) field *before* deserializing the other fields of the
//! proof.
use crate::{
    suite::bounds::{OptionsOf, SignatureOf, VerificationMethodOf},
    CryptosuiteString, DeserializeCryptographicSuite, Proof, Type,
};
use serde::{
    de::{DeserializeSeed, MapAccess},
    Deserialize,
};
use ssi_core::de::WithType;
use std::{collections::BTreeMap, marker::PhantomData};

mod field;
pub use field::*;

mod ref_or_value;
pub use ref_or_value::*;

mod replay_map;
pub use replay_map::*;

mod configuration;

fn datetime_to_utc_datetimestamp(
    d: Option<xsd_types::DateTime>,
) -> Option<xsd_types::DateTimeStamp> {
    d.map(|d| {
        xsd_types::DateTimeStamp::new(
            d.date_time,
            d.offset
                .unwrap_or(chrono::FixedOffset::east_opt(0).unwrap()),
        )
    })
}

impl<'de, T: DeserializeCryptographicSuite<'de>> Proof<T> {
    fn deserialize_with_type<S>(type_: Type, mut deserializer: S) -> Result<Self, S::Error>
    where
        S: serde::de::MapAccess<'de>,
    {
        let suite: T = type_
            .try_into()
            .map_err(|_| serde::de::Error::custom("unexpected cryptosuite"))?;

        let mut context = None;
        let mut created: Option<xsd_types::DateTime> = None;
        let mut verification_method = None;
        let mut proof_purpose = None;
        let mut expires: Option<xsd_types::DateTime> = None;
        let mut domains = None;
        let mut challenge = None;
        let mut nonce = None;

        let mut other = Vec::new();

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
                Field::Other(key) => other.push(Some((key, deserializer.next_value()?))),
            }
        }

        let options = WithType::<T, OptionsOf<T>>::new(&suite)
            .deserialize(serde::__private::de::FlatMapDeserializer(
                &mut other,
                PhantomData,
            ))?
            .0;

        let signature = WithType::<T, SignatureOf<T>>::new(&suite)
            .deserialize(serde::__private::de::FlatMapDeserializer(
                &mut other,
                PhantomData,
            ))?
            .0;

        Ok(Self {
            context,
            type_: suite,
            created: datetime_to_utc_datetimestamp(created),
            verification_method: verification_method
                .map(|v| v.map(VerificationMethodOf::unwrap).into())
                .ok_or_else(|| serde::de::Error::custom("missing `verificationMethod` property"))?,
            proof_purpose: proof_purpose
                .ok_or_else(|| serde::de::Error::custom("missing `proofPurpose` property"))?,
            expires: datetime_to_utc_datetimestamp(expires),
            domains: domains.unwrap_or_default(),
            challenge,
            nonce,
            options,
            signature,
            extra_properties: BTreeMap::deserialize(serde::__private::de::FlatMapDeserializer(
                &mut other,
                PhantomData,
            ))?,
        })
    }
}

impl<'de, T: DeserializeCryptographicSuite<'de>> serde::Deserialize<'de> for Proof<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(ProofVisitor(PhantomData))
    }
}

struct ProofVisitor<T>(PhantomData<T>);

impl<'de, T: DeserializeCryptographicSuite<'de>> serde::de::Visitor<'de> for ProofVisitor<T> {
    type Value = Proof<T>;

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
                                return Proof::<T>::deserialize_with_type(
                                    Type::DataIntegrityProof(c),
                                    ReplayMap::new(keep, map),
                                );
                            }
                            None => {
                                data_integrity_proof = true;
                            }
                        }
                    } else {
                        return Proof::<T>::deserialize_with_type(
                            Type::Other(name),
                            ReplayMap::new(keep, map),
                        );
                    }
                }
                TypeField::Cryptosuite => {
                    let name = map.next_value::<CryptosuiteString>()?;
                    if data_integrity_proof {
                        return Proof::<T>::deserialize_with_type(
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
