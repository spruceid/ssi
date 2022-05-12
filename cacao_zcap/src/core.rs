use std::{
    collections::HashMap,
    fmt::{Display, Formatter},
    str::FromStr,
};

use cacaos::{SignatureScheme, CACAO};
use iri_string::types::UriString;
use libipld::{
    cbor::{DagCbor, DagCborCodec},
    codec::Codec,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ssi::{one_or_many::OneOrMany, vc::URI, zcap::Delegation};
use thiserror::Error;
use uuid::adapter::Urn;

/// [Type](https://www.w3.org/TR/json-ld11/#specifying-the-type) term
/// for [CacaoZcap2022](https://demo.didkit.dev/2022/cacao-zcap/#CacaoZcap2022)
pub const DELEGATION_TYPE_2022: &str = "CacaoZcap2022";

/// [Type](https://www.w3.org/TR/json-ld11/#specifying-the-type) term
/// for [CacaoZcapProof2022]
pub const PROOF_TYPE_2022: &str = "CacaoZcapProof2022";

/// JSON-LD [Context](https://www.w3.org/TR/json-ld11/#the-context) URL
/// for [CACAO-ZCAP suite](https://demo.didkit.dev/2022/cacao-zcap/),
/// version 1
pub const CONTEXT_URL_V1: &str = "https://demo.didkit.dev/2022/cacao-zcap/contexts/v1.json";

/// Type alias for a CacaoZcap2022 delegation.
pub type CacaoZcap2022Delegation = Delegation<(), CacaoZcapExtraProps>;

/// An item in a [proof capabilityChain array](CacaoZcapProofExtraProps::capability_chain)
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[serde(untagged)]
pub enum CapabilityChainItem {
    Id(UriString),
    Object(Delegation<(), CacaoZcapExtraProps>),
}

/// Error [converting ZCAP to CACAO](zcap_to_cacao)
#[derive(Error, Debug)]
pub enum CapToResourceError {
    /// Unable to serialize delegation
    #[error("Unable to serialize delegation")]
    SerializeDelegation(#[source] serde_json::Error),

    /// Unable to format capability chain item as URI
    #[error("Unable to format capability chain item as URI")]
    UriParse(#[source] iri_string::validate::Error),
}

/// Error [converting a CACAO resource URI to a delegation object](CapabilityChainItem::from_resource_uri)
#[derive(Error, Debug)]
pub enum CapFromResourceError {
    /// Expected JSON base64 data URI
    #[error("Expected JSON base64 data URI")]
    ExpectedBase64JsonDataUri,

    /// Unable to parse JSON
    #[error("Unable to parse JSON")]
    JsonParse(#[source] serde_json::Error),

    /// Unable to decode base64
    #[error("Unable to decode base64")]
    Base64Decode(#[source] base64::DecodeError),
}

impl CapabilityChainItem {
    pub fn id(&self) -> &str {
        match self {
            Self::Id(string) => string.as_str(),
            Self::Object(delegation) => {
                let URI::String(s) = &delegation.id;
                s
            }
        }
    }

    pub fn as_resource_uri(&self) -> Result<UriString, CapToResourceError> {
        match self {
            Self::Id(id) => Ok(id.clone()),
            Self::Object(delegation) => {
                let json = serde_jcs::to_string(delegation)
                    .map_err(CapToResourceError::SerializeDelegation)?;
                let b64 = base64::encode(&json);
                let uri_string = "data:application/json;base64,".to_string() + &b64;
                UriString::from_str(&uri_string).map_err(CapToResourceError::UriParse)
            }
        }
    }

    /// Convert a [CACAO resource](Payload::resources) URI to a [delegation](Delegation) object
    pub fn from_resource_uri(uri: &UriString) -> Result<Self, CapFromResourceError> {
        let uri_string = uri.to_string();
        let b64_json = uri_string
            .strip_prefix("data:application/json;base64,")
            .ok_or(CapFromResourceError::ExpectedBase64JsonDataUri)?;
        let json = base64::decode(b64_json).map_err(CapFromResourceError::Base64Decode)?;
        let delegation: Delegation<(), CacaoZcapExtraProps> =
            serde_json::from_slice(&json).map_err(CapFromResourceError::JsonParse)?;
        Ok(Self::Object(delegation))
    }
}

/// [Extra properties](Delegation::property_set) for a zCap delegation
/// object
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct CacaoZcapExtraProps {
    /// Type of Delegation
    pub r#type: String,

    /// Invocation target
    ///
    /// <https://w3id.org/security#invocationTarget>
    pub invocation_target: String,

    /// CACAO/Zcap expiration time
    ///
    /// <https://w3id.org/security#expires>
    /// mapped to CACAO "exp" value
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,

    /// CACAO/Zcap validFrom (nbf)
    ///
    /// <https://www.w3.org/2018/credentials#validFrom>
    ///
    /// mapped to CACAO "nbf" value
    ///
    /// EIP-4361 not-before: "when the signed authentication message will become valid."
    // TODO: use https://schema.org/validFrom instead?
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<String>,

    /// CACAO payload type.
    ///
    /// CACAO header "t" value
    pub cacao_payload_type: String,

    /// zCap allowed actions
    ///
    /// <https://w3id.org/security#allowedAction>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_action: Option<OneOrMany<String>>,

    /// CACAO-ZCAP substatement
    ///
    /// Part of a [CACAO] payload "statement" value
    ///
    /// In [EIP-4361], statement is defined as a "human-readable ASCII assertion that the user will sign".
    ///
    /// CACAO-ZCAP requires the CACAO statement to match a format containing an optional a list of
    /// [allowed actions](CacaoZcapExtraProps::allowed_action) and an optional
    /// [substatement string](CacaoZcapExtraProps::cacao_zcap_substatement).
    ///
    /// [CACAO-ZCAP]: https://demo.didkit.dev/2022/cacao-zcap/
    /// [CACAO]: https://github.com/ChainAgnostic/CAIPs/blob/8fdb5bfd1bdf15c9daf8aacfbcc423533764dfe9/CAIPs/caip-draft_cacao.md#container-format
    /// [EIP-4361]: https://eips.ethereum.org/EIPS/eip-4361#message-field-descriptions
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cacao_zcap_substatement: Option<String>,

    /// CACAO request ID.
    ///
    /// CACAO payload "requestId" value
    /// SIWE "system-specific identifier that may be used to uniquely refer to the sign-in request"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cacao_request_id: Option<String>,
}

/// [Extra properties](Proof::property_set) for a proof object
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct CacaoZcapProofExtraProps {
    /// Capability chain
    ///
    /// <https://w3id.org/security#capabilityChain>
    pub capability_chain: Vec<CapabilityChainItem>,

    /// CACAO signature type.
    ///
    /// CACAO signature "t" value
    pub cacao_signature_type: String,
}

/// Error [converting Proof to CacaoZcapProofExtraProps](CacaoZcapProofExtraProps::from_property_set_opt)
#[derive(Error, Debug)]
pub enum CacaoZcapProofConvertError {
    /// Unable to convert HashMap to Value
    #[error("Unable to convert HashMap to Value")]
    HashMapToValue(#[source] serde_json::Error),

    /// Unable to convert Value to CacaoZcapProofExtraProps
    #[error("Unable to convert Value to CacaoZcapProofExtraProps")]
    ValueToExtraProps(#[source] serde_json::Error),

    /// Unable to convert Value to HashMap
    #[error("Unable to convert Value to HashMap")]
    ValueToHashMap(#[source] serde_json::Error),

    /// Unable to convert CacaoZcapProofExtraProps to Value
    #[error("Unable to convert CacaoZcapProofExtraProps to Value")]
    ExtraPropsToValue(#[source] serde_json::Error),
}

impl CacaoZcapProofExtraProps {
    pub fn from_property_set_opt(
        pso: Option<HashMap<String, Value>>,
    ) -> Result<Self, CacaoZcapProofConvertError> {
        let value =
            serde_json::to_value(pso).map_err(CacaoZcapProofConvertError::HashMapToValue)?;
        let extraprops: CacaoZcapProofExtraProps =
            serde_json::from_value(value).map_err(CacaoZcapProofConvertError::ValueToExtraProps)?;
        Ok(extraprops)
    }

    pub fn into_property_set_opt(
        self,
    ) -> Result<Option<HashMap<String, Value>>, CacaoZcapProofConvertError> {
        let props =
            serde_json::to_value(self).map_err(CacaoZcapProofConvertError::ExtraPropsToValue)?;
        let property_set: HashMap<String, Value> =
            serde_json::from_value(props).map_err(CacaoZcapProofConvertError::ValueToHashMap)?;
        Ok(Some(property_set))
    }
}

/// A [CACAO statement](Payload::statement) for CACAO-ZCAP
#[derive(Clone, Debug)]
pub struct CacaoZcapStatement {
    /// zCap [allowedAction](CacaoZcapExtraProps::allowed_action) values
    pub actions: Option<OneOrMany<String>>,

    /// CACAO-ZCAP [substatement](CacaoZcapExtraProps::cacao_zcap_substatement)
    pub substatement: Option<String>,
}

impl CacaoZcapStatement {
    /// Construct cacao-zcap statement
    pub fn from_actions_and_substatement_opt(
        substmt: Option<&str>,
        actions: Option<&OneOrMany<String>>,
    ) -> Self {
        Self {
            actions: actions.cloned(),
            substatement: substmt.map(|s| s.to_string()),
        }
    }

    /// Serialize to a CACAO statement string, or None if there is no actions or substatement
    pub fn to_string_opt(&self) -> Option<String> {
        if self.actions.is_some() || self.substatement.is_some() {
            Some(format!("{}", self))
        } else {
            None
        }
    }
}

impl Display for CacaoZcapStatement {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "Authorize action")?;
        if let Some(actions) = self.actions.as_ref() {
            write!(f, " (")?;
            let mut actions_iter = actions.into_iter();
            if let Some(action) = actions_iter.next() {
                write!(f, "{}", action)?;
            }
            for action in actions_iter {
                write!(f, ", {}", action)?;
            }
            write!(f, ")")?;
        }
        if let Some(substatement) = self.substatement.as_ref() {
            write!(f, ": {}", substatement)?;
        }
        Ok(())
    }
}

/// Derive a UUID from a CACAO's CID
///
/// RFC 4122 v4 UUID, using last 16 bytes of the hash of the DAG-CBOR serialization of the CACAO as the pseudo-random bytes.
pub fn cacao_cid_uuid<S: SignatureScheme>(cacao: &CACAO<S>) -> Urn
where
    S::Signature: DagCbor,
{
    let cacao_dagcbor_bytes = DagCborCodec.encode(cacao).unwrap();
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(&cacao_dagcbor_bytes);
    let hash: [u8; 32] = *hasher.finalize().as_ref();
    // Use the hash as pseudo-random bytes for a RFC 4122 UUID.
    let mut uuid_bytes: uuid::Bytes = [0; 16];
    // UUID has 16 bytes, minus the 6 bits that are overwritten to set the version and variant per
    // RFC 4122. Use the last 16 bytes of the hash.
    uuid_bytes.copy_from_slice(&hash[16..32]);
    // Using the "RFC 4122" variant and version 4.
    // https://datatracker.ietf.org/doc/html/rfc4122.html#section-4.1.3
    let uuid = uuid::Builder::from_bytes(uuid_bytes)
        .set_variant(uuid::Variant::RFC4122)
        .set_version(uuid::Version::Random)
        .build();
    uuid.to_urn()
}

/// Root URN for authorization capability
///
/// as proposed in <https://github.com/w3c-ccg/zcap-spec/issues/39>
pub struct ZcapRootURN {
    /// Invocation target URL for root object
    pub target: UriString,
}

/// Error [parsing ZcapRootURN](ZcapRootURN::from_str)
#[derive(Error, Debug)]
pub enum ZcapRootURNParseError {
    /// Unable to parse [root URI](ZcapRootURN)
    #[error("Unable to decode invocation target")]
    TargetDecode(#[source] ::core::str::Utf8Error),

    /// Unable to parse [target URL](ZcapRootURN::target)
    #[error("Unable to parse target URL")]
    TargetParse(#[source] iri_string::validate::Error),

    /// Unexpected scheme for zcap root URI. Expected URN (urn:).
    #[error("Unexpected zcap root URN (urn:zcap:root:...) but found: '{uri}'")]
    ExpectedZcapRootUrn {
        /// String found that did not match the expected pattern
        uri: String,
    },
}

impl FromStr for ZcapRootURN {
    type Err = ZcapRootURNParseError;
    fn from_str(uri: &str) -> Result<Self, Self::Err> {
        let target = if let Some(suffix) = uri.strip_prefix("urn:zcap:root:") {
            percent_encoding::percent_decode_str(suffix)
                .decode_utf8()
                .map_err(ZcapRootURNParseError::TargetDecode)?
        } else {
            return Err(ZcapRootURNParseError::ExpectedZcapRootUrn {
                uri: uri.to_string(),
            });
        };
        let target_uri =
            UriString::from_str(&target).map_err(ZcapRootURNParseError::TargetParse)?;
        Ok(Self { target: target_uri })
    }
}

impl Display for ZcapRootURN {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
        // Emulate encodeURIComponent
        const CHARS: &AsciiSet = &CONTROLS
            .add(b' ')
            .add(b'"')
            .add(b'<')
            .add(b'>')
            .add(b'`')
            .add(b':')
            .add(b'/');
        let target_encoded = utf8_percent_encode(self.target.as_str(), CHARS);
        write!(f, "urn:zcap:root:{}", target_encoded)
    }
}
