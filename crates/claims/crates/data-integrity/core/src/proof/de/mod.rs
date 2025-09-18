//! Proof deserialization primitives.
//!
//! Deserializing a Data-Integrity proof while preserving type information can
//! be tricky, in particular when the considered cryptographic suite type
//! abstracts multiple actual cryptographic suite implementations.
//! In this case, it may be necessary to know the proof `type`
//! (and `cryptosuite`) field *before* deserializing the other fields of the
//! proof.
use crate::{
    suite::bounds::{DeserializeCryptographicSuiteMultiplexing, VerificationMethodOf},
    CryptosuiteString, Proof, Type,
};
use serde::de::{Error, MapAccess};
use ssi_core::{de::WithType, Lexical, OneOrMany};
use std::marker::PhantomData;

mod field;
pub use field::{Field, TypeField};

mod ref_or_value;
pub use ref_or_value::*;

mod replay_map;
pub use replay_map::*;

mod configuration;

/// Converts an XSD dateTime into a XSD dateTimeStamp while preserving the
/// lexical representation.
///
/// If no offset is given in the dateTime, the UTC offset (`Z`) is added.
fn datetime_to_utc_datetimestamp(
    value: Option<Lexical<xsd_types::DateTime>>,
) -> Option<Lexical<xsd_types::DateTimeStamp>> {
    value.map(|lexical_dt| {
        let (dt, mut representation) = lexical_dt.into_parts();

        let dts = xsd_types::DateTimeStamp::new(
            dt.date_time,
            dt.offset.unwrap_or_else(|| {
                if let Some(r) = &mut representation {
                    // Keep most of the lexical representation, just add the
                    // offset.
                    r.push('Z');
                }

                chrono::FixedOffset::east_opt(0).unwrap()
            }),
        );

        Lexical::from_parts(dts, representation)
    })
}

impl<'de, T> Proof<T>
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
        let mut created: Option<Lexical<xsd_types::DateTime>> = None;
        let mut verification_method = None;
        let mut proof_purpose = None;
        let mut expires: Option<Lexical<xsd_types::DateTime>> = None;
        let mut domains: Option<OneOrMany<String>> = None;
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
            .deserialize_extra_properties_finalized_proof(other)
            .map_err(S::Error::custom)?;

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
            domains: domains.map(|d| d.into_vec()).unwrap_or_default(),
            challenge,
            nonce,
            options: interim_extra_properties.options,
            signature: interim_extra_properties.signature,
            extra_properties: interim_extra_properties.extra_properties,
        })
    }
}

impl<'de, T: DeserializeCryptographicSuiteMultiplexing<'de>> serde::Deserialize<'de> for Proof<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(ProofVisitor(PhantomData))
    }
}

struct ProofVisitor<T>(PhantomData<T>);

impl<'de, T: DeserializeCryptographicSuiteMultiplexing<'de>> serde::de::Visitor<'de>
    for ProofVisitor<T>
{
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
