use ssi_core::{covariance_rule, Referencable};
use ssi_data_integrity_suites::{
    JwsSignature, JwsSignatureRef, MultibaseSignature, MultibaseSignatureRef,
};
use ssi_jws::{CompactJWSStr, CompactJWSString};
use ssi_verification_methods::InvalidSignature;

#[derive(
    Debug,
    Default,
    Clone,
    serde::Serialize,
    serde::Deserialize,
    linked_data::Serialize,
    linked_data::Deserialize,
)]
#[ld(prefix("sec" = "https://w3id.org/security#"))]
#[serde(rename_all = "camelCase")]
pub struct AnySignature {
    #[ld("sec:proofValue")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_value: Option<String>,

    #[ld("sec:signatureValue")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_value: Option<String>,

    #[ld("sec:jws")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jws: Option<CompactJWSString>,

    #[cfg(feature = "eip712")]
    #[ld("https://w3c-ccg.github.io/ethereum-eip712-signature-2021-spec/#eip712-domain")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eip712: Option<ssi_data_integrity_suites::eip712::Eip712Metadata>,
}

impl Referencable for AnySignature {
    type Reference<'a> = AnySignatureRef<'a> where Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_> {
        AnySignatureRef {
            proof_value: self.proof_value.as_deref(),
            signature_value: self.signature_value.as_deref(),
            jws: self.jws.as_deref(),
            #[cfg(feature = "eip712")]
            eip712: self.eip712.as_ref(),
        }
    }

    covariance_rule!();
}

#[derive(Debug, Default, Clone, Copy)]
pub struct AnySignatureRef<'a> {
    pub proof_value: Option<&'a str>,

    pub signature_value: Option<&'a str>,

    pub jws: Option<&'a CompactJWSStr>,

    #[cfg(feature = "eip712")]
    pub eip712: Option<&'a ssi_data_integrity_suites::eip712::Eip712Metadata>,
}

impl From<MultibaseSignature> for AnySignature {
    fn from(value: MultibaseSignature) -> Self {
        AnySignature {
            proof_value: Some(value.proof_value),
            ..Default::default()
        }
    }
}

impl<'a> TryFrom<AnySignatureRef<'a>> for MultibaseSignatureRef<'a> {
    type Error = InvalidSignature;

    fn try_from(value: AnySignatureRef<'a>) -> Result<Self, Self::Error> {
        match value.proof_value {
            Some(v) => Ok(Self { proof_value: v }),
            None => Err(InvalidSignature::MissingValue),
        }
    }
}

impl From<JwsSignature> for AnySignature {
    fn from(value: JwsSignature) -> Self {
        AnySignature {
            jws: Some(value.jws),
            ..Default::default()
        }
    }
}

impl<'a> TryFrom<AnySignatureRef<'a>> for JwsSignatureRef<'a> {
    type Error = InvalidSignature;

    fn try_from(value: AnySignatureRef<'a>) -> Result<Self, Self::Error> {
        match value.jws {
            Some(v) => Ok(Self { jws: v }),
            None => Err(InvalidSignature::MissingValue),
        }
    }
}

#[cfg(all(feature = "ethereum", feature = "secp256k1"))]
impl From<ssi_data_integrity_suites::ethereum_personal_signature_2021::Signature> for AnySignature {
    fn from(value: ssi_data_integrity_suites::ethereum_personal_signature_2021::Signature) -> Self {
        Self {
            proof_value: Some(value.proof_value),
            ..Default::default()
        }
    }
}

#[cfg(all(feature = "ethereum", feature = "secp256k1"))]
impl TryFrom<AnySignature>
    for ssi_data_integrity_suites::ethereum_personal_signature_2021::Signature
{
    type Error = InvalidSignature;

    fn try_from(value: AnySignature) -> Result<Self, Self::Error> {
        Ok(Self {
            proof_value: value.proof_value.ok_or(InvalidSignature::MissingValue)?,
        })
    }
}

#[cfg(all(feature = "ethereum", feature = "secp256k1"))]
impl<'a> From<ssi_data_integrity_suites::ethereum_personal_signature_2021::SignatureRef<'a>>
    for AnySignatureRef<'a>
{
    fn from(
        value: ssi_data_integrity_suites::ethereum_personal_signature_2021::SignatureRef<'a>,
    ) -> Self {
        Self {
            proof_value: Some(value.proof_value),
            ..Default::default()
        }
    }
}

#[cfg(all(feature = "ethereum", feature = "secp256k1"))]
impl<'a> TryFrom<AnySignatureRef<'a>>
    for ssi_data_integrity_suites::ethereum_personal_signature_2021::SignatureRef<'a>
{
    type Error = InvalidSignature;

    fn try_from(value: AnySignatureRef<'a>) -> Result<Self, Self::Error> {
        Ok(Self {
            proof_value: value.proof_value.ok_or(InvalidSignature::MissingValue)?,
        })
    }
}

#[cfg(feature = "solana")]
impl From<ssi_data_integrity_suites::solana_signature_2021::Signature> for AnySignature {
    fn from(value: ssi_data_integrity_suites::solana_signature_2021::Signature) -> Self {
        AnySignature {
            proof_value: Some(value.proof_value),
            ..Default::default()
        }
    }
}

#[cfg(feature = "solana")]
impl TryFrom<AnySignature> for ssi_data_integrity_suites::solana_signature_2021::Signature {
    type Error = InvalidSignature;

    fn try_from(value: AnySignature) -> Result<Self, Self::Error> {
        match value.proof_value {
            Some(v) => Ok(Self { proof_value: v }),
            None => Err(InvalidSignature::MissingValue),
        }
    }
}

#[cfg(feature = "solana")]
impl<'a> From<ssi_data_integrity_suites::solana_signature_2021::SignatureRef<'a>>
    for AnySignatureRef<'a>
{
    fn from(value: ssi_data_integrity_suites::solana_signature_2021::SignatureRef<'a>) -> Self {
        AnySignatureRef {
            proof_value: Some(value.proof_value),
            ..Default::default()
        }
    }
}

#[cfg(feature = "solana")]
impl<'a> TryFrom<AnySignatureRef<'a>>
    for ssi_data_integrity_suites::solana_signature_2021::SignatureRef<'a>
{
    type Error = InvalidSignature;

    fn try_from(value: AnySignatureRef<'a>) -> Result<Self, Self::Error> {
        match value.proof_value {
            Some(v) => Ok(Self { proof_value: v }),
            None => Err(InvalidSignature::MissingValue),
        }
    }
}

#[cfg(feature = "tezos")]
impl From<ssi_data_integrity_suites::tezos::Signature> for AnySignature {
    fn from(value: ssi_data_integrity_suites::tezos::Signature) -> Self {
        Self {
            proof_value: Some(value.proof_value),
            ..Default::default()
        }
    }
}

#[cfg(feature = "tezos")]
impl<'a> From<ssi_data_integrity_suites::tezos::SignatureRef<'a>> for AnySignatureRef<'a> {
    fn from(value: ssi_data_integrity_suites::tezos::SignatureRef<'a>) -> Self {
        Self {
            proof_value: Some(value.proof_value),
            ..Default::default()
        }
    }
}

#[cfg(feature = "tezos")]
impl<'a> TryFrom<AnySignatureRef<'a>> for ssi_data_integrity_suites::tezos::SignatureRef<'a> {
    type Error = InvalidSignature;

    fn try_from(value: AnySignatureRef<'a>) -> Result<Self, Self::Error> {
        Ok(Self {
            proof_value: value.proof_value.ok_or(InvalidSignature::MissingValue)?,
        })
    }
}

#[cfg(all(feature = "w3c", feature = "rsa"))]
impl From<ssi_data_integrity_suites::rsa_signature_2018::Signature> for AnySignature {
    fn from(value: ssi_data_integrity_suites::rsa_signature_2018::Signature) -> Self {
        AnySignature {
            signature_value: Some(value.signature_value),
            ..Default::default()
        }
    }
}

#[cfg(all(feature = "w3c", feature = "rsa"))]
impl<'a> TryFrom<AnySignatureRef<'a>>
    for ssi_data_integrity_suites::rsa_signature_2018::SignatureRef<'a>
{
    type Error = InvalidSignature;

    fn try_from(value: AnySignatureRef<'a>) -> Result<Self, Self::Error> {
        match value.signature_value {
            Some(v) => Ok(Self { signature_value: v }),
            None => Err(InvalidSignature::MissingValue),
        }
    }
}

#[cfg(feature = "eip712")]
impl From<ssi_data_integrity_suites::eip712::Eip712Signature> for AnySignature {
    fn from(value: ssi_data_integrity_suites::eip712::Eip712Signature) -> Self {
        Self {
            proof_value: Some(value.proof_value),
            ..Default::default()
        }
    }
}

#[cfg(feature = "eip712")]
impl TryFrom<AnySignature> for ssi_data_integrity_suites::eip712::Eip712Signature {
    type Error = InvalidSignature;

    fn try_from(value: AnySignature) -> Result<Self, Self::Error> {
        Ok(Self {
            proof_value: value.proof_value.ok_or(InvalidSignature::MissingValue)?,
        })
    }
}

#[cfg(feature = "eip712")]
impl<'a> From<ssi_data_integrity_suites::eip712::Eip712SignatureRef<'a>> for AnySignatureRef<'a> {
    fn from(value: ssi_data_integrity_suites::eip712::Eip712SignatureRef<'a>) -> Self {
        Self {
            proof_value: Some(value.proof_value),
            ..Default::default()
        }
    }
}

#[cfg(feature = "eip712")]
impl<'a> TryFrom<AnySignatureRef<'a>>
    for ssi_data_integrity_suites::eip712::Eip712SignatureRef<'a>
{
    type Error = InvalidSignature;

    fn try_from(value: AnySignatureRef<'a>) -> Result<Self, Self::Error> {
        Ok(Self {
            proof_value: value.proof_value.ok_or(InvalidSignature::MissingValue)?,
        })
    }
}
