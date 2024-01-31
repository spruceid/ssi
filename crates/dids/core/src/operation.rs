/// Something that can be used to derive (generate) a DID.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Source<'a> {
    /// A public key.
    Key(&'a JWK),
    /// A public key and additional pattern.
    KeyAndPattern(&'a JWK, &'a str),
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
/// [DID Parameters](https://www.w3.org/TR/did-core/#did-parameters).
///
/// As specified in DID Core and/or in [DID Specification
/// Registries](https://www.w3.org/TR/did-spec-registries/#parameters).
pub struct DIDParameters {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>, // ASCII
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(alias = "relative-ref")]
    /// [`relativeRef`](https://www.w3.org/TR/did-spec-registries/#relativeRef-param) parameter.
    pub relative_ref: Option<String>, // ASCII, percent-encoding
    /// [`versionId`](https://www.w3.org/TR/did-spec-registries/#versionId-param) parameter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_id: Option<String>, // ASCII
    /// [`versionTime`](https://www.w3.org/TR/did-spec-registries/#versionTime-param) parameter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_time: Option<DateTime<Utc>>, // ASCII
    /// [`hl`](https://www.w3.org/TR/did-spec-registries/#hl-param) parameter.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "hl")]
    pub hashlink: Option<String>, // ASCII
    /// Additional parameters.
    #[serde(flatten)]
    pub property_set: Option<Map<String, Value>>,
}

/// DID Create Operation
///
/// <https://identity.foundation/did-registration/#create>
pub struct DIDCreate {
    pub update_key: Option<JWK>,
    pub recovery_key: Option<JWK>,
    pub verification_key: Option<JWK>,
    pub options: Map<String, Value>,
}

/// DID Update Operation
///
/// <https://identity.foundation/did-registration/#update>
pub struct DIDUpdate {
    pub did: String,
    pub update_key: Option<JWK>,
    pub new_update_key: Option<JWK>,
    pub operation: DIDDocumentOperation,
    pub options: Map<String, Value>,
}

/// DID Recover Operation
///
/// <https://www.w3.org/TR/did-core/#did-recovery>
pub struct DIDRecover {
    pub did: String,
    pub recovery_key: Option<JWK>,
    pub new_update_key: Option<JWK>,
    pub new_recovery_key: Option<JWK>,
    pub new_verification_key: Option<JWK>,
    pub options: Map<String, Value>,
}

/// DID Deactivate Operation
///
/// <https://identity.foundation/did-registration/#deactivate>
pub struct DIDDeactivate {
    pub did: String,
    pub key: Option<JWK>,
    pub options: Map<String, Value>,
}

/// DID Document Operation
///
/// This should represent [didDocument][dd] and [didDocumentOperation][ddo] specified by DID
/// Registration.
///
/// [dd]: https://identity.foundation/did-registration/#diddocumentoperation
/// [ddo]: https://identity.foundation/did-registration/#diddocument
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "didDocumentOperation", content = "didDocument")]
#[serde(rename_all = "camelCase")]
#[allow(clippy::large_enum_variant)]
pub enum DIDDocumentOperation {
    /// Set the contents of the DID document
    ///
    /// setDidDocument operation defined by DIF DID Registration
    SetDidDocument(Document),

    /// Add properties to the DID document
    ///
    /// addToDidDocument operation defined by DIF DID Registration
    AddToDidDocument(HashMap<String, Value>),

    /// Remove properties from the DID document
    ///
    /// removeFromDidDocument operation defined by DIF Registration
    RemoveFromDidDocument(Vec<String>),

    /// Add or update a verification method in the DID document
    SetVerificationMethod {
        vmm: VerificationMethodMap,
        purposes: Vec<VerificationRelationship>,
    },

    /// Add or update a service map in the DID document
    SetService(Service),

    /// Remove a verification method in the DID document
    RemoveVerificationMethod(DIDURL),

    /// Add or update a service map in the DID document
    RemoveService(DIDURL),
}