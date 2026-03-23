use indexmap::IndexMap;
use ssi_caips::caip10::BlockchainAccountId;
use ssi_caips::caip2::ChainId;
use ssi_dids_core::{
    document::{
        self,
        representation::{self, MediaType},
        DIDVerificationMethod,
    },
    resolution::{self, DIDMethodResolver, Error, Output},
    DIDBuf, DIDMethod, DIDURLBuf, Document,
};
use std::collections::HashMap;
use std::str::FromStr;

use crate::abi::{
    decode_address, decode_uint256, encode_call, format_address_eip55, format_timestamp_iso8601,
    CHANGED_SELECTOR, IDENTITY_OWNER_SELECTOR,
};
use crate::events::{collect_events, Erc1056Event};
use crate::json_ld_context::JsonLdContext;
use crate::network::{DecodedMethodSpecificId, NetworkChain};
use crate::provider::{BlockRef, EthProvider, NetworkConfig};
use crate::vm::{
    decode_delegate_type, KeyPurpose, PendingService, PendingVm, PendingVmPayload,
    VerificationMethod, VerificationMethodType,
};

// --- DIDEthr ---

/// did:ethr DID Method
///
/// [Specification](https://github.com/decentralized-identity/ethr-did-resolver/)
///
/// Generic over `P`: when `P = ()` (the default), only offline resolution is
/// available. When `P` implements [`EthProvider`], on-chain resolution is used
/// for networks that have a configured provider.
pub struct DIDEthr<P = ()> {
    networks: HashMap<String, NetworkConfig<P>>,
}

impl<P> Default for DIDEthr<P> {
    fn default() -> Self {
        Self {
            networks: HashMap::new(),
        }
    }
}

impl<P> DIDEthr<P> {
    /// Create a new `DIDEthr` resolver with no networks configured.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a named network configuration.
    pub fn add_network(&mut self, name: &str, config: NetworkConfig<P>) {
        self.networks.insert(name.to_owned(), config);
    }
}

impl DIDEthr {
    pub fn generate(jwk: &ssi_jwk::JWK) -> Result<DIDBuf, ssi_jwk::Error> {
        let hash = ssi_jwk::eip155::hash_public_key(jwk)?;
        Ok(DIDBuf::from_string(format!("did:ethr:{}", hash)).unwrap())
    }
}

impl<P: Send + Sync> DIDMethod for DIDEthr<P> {
    const DID_METHOD_NAME: &'static str = "ethr";
}

impl<P: EthProvider> DIDMethodResolver for DIDEthr<P> {
    async fn resolve_method_representation<'a>(
        &'a self,
        method_specific_id: &'a str,
        options: resolution::Options,
    ) -> Result<Output<Vec<u8>>, Error> {
        let decoded_id = DecodedMethodSpecificId::from_str(method_specific_id)
            .map_err(|_| Error::InvalidMethodSpecificId(method_specific_id.to_owned()))?;

        // Check if we have a provider for this network
        if let Some(config) = self.networks.get(decoded_id.network_name()) {
            let addr_hex = decoded_id.account_address_hex()
                .ok_or_else(|| Error::InvalidMethodSpecificId(method_specific_id.to_owned()))?;
            if let Some(addr) = crate::network::parse_address_bytes(&addr_hex) {
                // Parse historical resolution target block from ?versionId=N
                let target_block: Option<u64> = options
                    .parameters
                    .version_id
                    .as_deref()
                    .and_then(|v| v.parse::<u64>().ok());

                // Call changed(addr) to see if there are on-chain modifications
                let calldata = encode_call(CHANGED_SELECTOR, &addr);
                let result = config
                    .provider
                    .call(config.registry, calldata, BlockRef::Latest)
                    .await
                    .map_err(|e| Error::Internal(e.to_string()))?;
                let changed_block = decode_uint256(&result)
                    .map_err(|e| Error::Internal(e.to_string()))?;

                if changed_block > 0 {
                    // Collect all events via linked-list walk
                    let all_events = collect_events(
                        &config.provider,
                        config.registry,
                        &addr,
                        changed_block,
                    )
                    .await
                    .map_err(Error::Internal)?;

                    // Partition events for historical resolution
                    let (events, events_after) = if let Some(tb) = target_block {
                        all_events.into_iter().partition(|(b, _)| *b <= tb)
                    } else {
                        (all_events, Vec::new())
                    };

                    // For historical resolution at a block before any changes,
                    // return the genesis (default) document
                    if target_block.is_some() && events.is_empty() {
                        return resolve_offline(method_specific_id, &decoded_id, options);
                    }

                    // Build document metadata (versionId + updated)
                    let meta_block = if let Some(tb) = target_block {
                        // Latest event block at or before target
                        events.iter().map(|(b, _)| *b).max().unwrap_or(tb)
                    } else {
                        changed_block
                    };
                    let block_ts = config
                        .provider
                        .block_timestamp(meta_block)
                        .await
                        .map_err(|e| Error::Internal(e.to_string()))?;
                    let mut doc_metadata = document::Metadata {
                        version_id: Some(meta_block.to_string()),
                        updated: Some(format_timestamp_iso8601(block_ts)),
                        ..Default::default()
                    };

                    // Populate nextVersionId/nextUpdate from first event after target
                    if target_block.is_some() {
                        if let Some((next_block, _)) = events_after.first() {
                            let next_ts = config
                                .provider
                                .block_timestamp(*next_block)
                                .await
                                .map_err(|e| Error::Internal(e.to_string()))?;
                            doc_metadata.next_version_id = Some(next_block.to_string());
                            doc_metadata.next_update = Some(format_timestamp_iso8601(next_ts));
                        }
                    }

                    // Check identityOwner(addr) — at target block for historical, Latest otherwise
                    let owner_block = match target_block {
                        Some(tb) => BlockRef::Number(tb),
                        None => BlockRef::Latest,
                    };
                    let owner_calldata = encode_call(IDENTITY_OWNER_SELECTOR, &addr);
                    let owner_result = config
                        .provider
                        .call(config.registry, owner_calldata, owner_block)
                        .await
                        .map_err(|e| Error::Internal(e.to_string()))?;
                    let owner = decode_address(&owner_result);

                    // Check for deactivation (owner = null address)
                    const NULL_ADDRESS: [u8; 20] = [0u8; 20];
                    if owner == NULL_ADDRESS {
                        let did = DIDBuf::from_string(format!("did:ethr:{method_specific_id}")).unwrap();
                        let doc = Document::new(did);
                        let json_ld_context = JsonLdContext::default();
                        doc_metadata.deactivated = Some(true);
                        return serialize_document(doc, json_ld_context, options, doc_metadata);
                    }

                    // Build base document from owner
                    let mut json_ld_context = JsonLdContext::default();
                    let (mut doc, _account_address) = if owner == addr {
                        // Owner unchanged — build from the DID's own identity
                        let doc = match decoded_id.address_or_public_key.len() {
                            42 => resolve_address(
                                &mut json_ld_context,
                                method_specific_id,
                                &decoded_id.network_chain,
                                &decoded_id.address_or_public_key,
                            ),
                            68 => resolve_public_key(
                                &mut json_ld_context,
                                method_specific_id,
                                &decoded_id.network_chain,
                                &decoded_id.address_or_public_key,
                            ),
                            _ => Err(Error::InvalidMethodSpecificId(
                                method_specific_id.to_owned(),
                            )),
                        }?;
                        (doc, decoded_id.address_or_public_key.clone())
                    } else {
                        // Owner changed — build with the new owner's address
                        let owner_address = format_address_eip55(&owner);
                        let doc = resolve_address(
                            &mut json_ld_context,
                            method_specific_id,
                            &decoded_id.network_chain,
                            &owner_address,
                        )?;
                        (doc, owner_address)
                    };

                    // Apply delegate/attribute events
                    // For historical resolution, use the actual target block's
                    // timestamp as "now" (not meta_block's, which may be earlier)
                    let now = if let Some(tb) = target_block {
                        if meta_block == tb {
                            block_ts
                        } else {
                            config
                                .provider
                                .block_timestamp(tb)
                                .await
                                .map_err(|e| Error::Internal(e.to_string()))?
                        }
                    } else {
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs()
                    };

                    let did = DIDBuf::from_string(format!("did:ethr:{method_specific_id}"))
                        .unwrap();
                    apply_events(
                        &mut doc,
                        &events,
                        &did,
                        &decoded_id.network_chain,
                        &mut json_ld_context,
                        now,
                    );

                    return serialize_document(doc, json_ld_context, options, doc_metadata);
                }
            }
        }

        // No provider or changed=0 — offline resolution
        resolve_offline(method_specific_id, &decoded_id, options)
    }
}

/// DIDMethodResolver impl for DIDEthr<()> — offline-only resolution
impl DIDMethodResolver for DIDEthr<()> {
    async fn resolve_method_representation<'a>(
        &'a self,
        method_specific_id: &'a str,
        options: resolution::Options,
    ) -> Result<Output<Vec<u8>>, Error> {
        let decoded_id = DecodedMethodSpecificId::from_str(method_specific_id)
            .map_err(|_| Error::InvalidMethodSpecificId(method_specific_id.to_owned()))?;
        resolve_offline(method_specific_id, &decoded_id, options)
    }
}

/// Encode raw key bytes as multibase(base58btc) with a multicodec varint prefix.
/// Matches the encoding expected by Ed25519VerificationKey2020 and
/// X25519KeyAgreementKey2020 verification method types per W3C spec.
fn encode_multibase_multicodec(codec: u64, key_bytes: &[u8]) -> String {
    let encoded = ssi_multicodec::MultiEncodedBuf::encode_bytes(codec, key_bytes);
    multibase::encode(multibase::Base::Base58Btc, encoded.as_bytes())
}

/// Process ERC-1056 events and add delegate verification methods to the document.
///
/// Uses a map-accumulation model: each delegate/attribute event is keyed by its
/// content (delegate_type+delegate or name+value). When a valid event arrives the
/// entry is inserted; when a revoked/expired event arrives the entry is removed.
/// This correctly handles the case where a previously-valid key is later revoked.
///
/// `now` is the current timestamp (seconds since epoch) used for expiry checks.
/// The delegate counter increments for every recognised DelegateChanged /
/// AttributeChanged-pub event regardless of validity, ensuring stable `#delegate-N`
/// IDs. Likewise for service_counter / `#service-N`.
pub(crate) fn apply_events(
    doc: &mut Document,
    events: &[(u64, Erc1056Event)],
    did: &DIDBuf,
    network_chain: &NetworkChain,
    json_ld_context: &mut JsonLdContext,
    now: u64,
) {
    let mut delegate_counter = 0u64;
    let mut service_counter = 0u64;

    // Content-keyed maps for deduplication and revocation support.
    // Key = delegate_type[32] ++ delegate[20] for delegates,
    //       name[32] ++ value[..] for attribute keys / services.
    let mut vms: IndexMap<Vec<u8>, PendingVm> = IndexMap::new();
    let mut svcs: IndexMap<Vec<u8>, PendingService> = IndexMap::new();

    for (_block, event) in events {
        match event {
            Erc1056Event::DelegateChanged {
                delegate_type,
                delegate,
                valid_to,
                ..
            } => {
                let dt = decode_delegate_type(delegate_type);

                let purpose = if dt == b"veriKey" {
                    KeyPurpose::VeriKey
                } else if dt == b"sigAuth" {
                    KeyPurpose::SigAuth
                } else {
                    continue;
                };

                delegate_counter += 1;

                // Content key: delegate_type[32] ++ delegate[20]
                let mut key = Vec::with_capacity(52);
                key.extend_from_slice(delegate_type);
                key.extend_from_slice(delegate);

                if *valid_to >= now {
                    let delegate_addr = format_address_eip55(delegate);
                    let blockchain_account_id = BlockchainAccountId {
                        account_address: delegate_addr,
                        chain_id: ChainId {
                            namespace: "eip155".to_string(),
                            reference: network_chain.id().to_string(),
                        },
                    };

                    vms.insert(key, PendingVm {
                        counter: delegate_counter,
                        payload: PendingVmPayload::Delegate { blockchain_account_id },
                        purpose,
                    });
                } else {
                    vms.shift_remove(&key);
                }
            }
            Erc1056Event::AttributeChanged {
                name,
                value,
                valid_to,
                ..
            } => {
                let attr_name = decode_delegate_type(name); // trims trailing zeros
                let attr_str = match std::str::from_utf8(attr_name) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let parts: Vec<&str> = attr_str.split('/').collect();

                if parts.len() >= 3 && parts[0] == "did" && parts[1] == "pub" {
                    // did/pub/<algo>/<purpose>/<encoding>
                    delegate_counter += 1;

                    let algo = parts.get(2).copied().unwrap_or("");
                    let purpose_str = parts.get(3).copied().unwrap_or("");

                    // Content key: name[32] ++ value[..]
                    let mut key = Vec::with_capacity(32 + value.len());
                    key.extend_from_slice(name);
                    key.extend_from_slice(value);

                    if *valid_to >= now {
                        // Determine VM type and build the property value.
                        // Encoding hint from the attribute name is ignored; we
                        // always use the canonical property for each VM type.
                        let pending = match algo {
                            "Secp256k1" => {
                                match ssi_jwk::secp256k1_parse(value) {
                                    Ok(jwk) => Some(PendingVmPayload::AttributeKey {
                                        vm_type: VerificationMethodType::EcdsaSecp256k1VerificationKey2019,
                                        prop_name: "publicKeyJwk",
                                        prop_value: serde_json::to_value(&jwk).unwrap(),
                                    }),
                                    Err(_) => None,
                                }
                            }
                            "Ed25519" => {
                                let multibase = encode_multibase_multicodec(
                                    ssi_multicodec::ED25519_PUB, value,
                                );
                                Some(PendingVmPayload::AttributeKey {
                                    vm_type: VerificationMethodType::Ed25519VerificationKey2020,
                                    prop_name: "publicKeyMultibase",
                                    prop_value: serde_json::Value::String(multibase),
                                })
                            }
                            "X25519" => {
                                let multibase = encode_multibase_multicodec(
                                    ssi_multicodec::X25519_PUB, value,
                                );
                                Some(PendingVmPayload::AttributeKey {
                                    vm_type: VerificationMethodType::X25519KeyAgreementKey2020,
                                    prop_name: "publicKeyMultibase",
                                    prop_value: serde_json::Value::String(multibase),
                                })
                            }
                            _ => None,
                        };

                        if let Some(payload) = pending {
                            let purpose = match purpose_str {
                                "sigAuth" => KeyPurpose::SigAuth,
                                "enc" => KeyPurpose::Enc,
                                _ => KeyPurpose::VeriKey,
                            };
                            vms.insert(key, PendingVm {
                                counter: delegate_counter,
                                payload,
                                purpose,
                            });
                        }
                    } else {
                        vms.shift_remove(&key);
                    }
                } else if parts.len() >= 3 && parts[0] == "did" && parts[1] == "svc" {
                    // did/svc/<ServiceType>
                    service_counter += 1;

                    // Content key: name[32] ++ value[..]
                    let mut key = Vec::with_capacity(32 + value.len());
                    key.extend_from_slice(name);
                    key.extend_from_slice(value);

                    if *valid_to >= now {
                        let service_type = parts[2..].join("/");
                        let endpoint_str = String::from_utf8_lossy(value);
                        let endpoint = if let Ok(json_val) = serde_json::from_str::<serde_json::Value>(&endpoint_str) {
                            if json_val.is_object() || json_val.is_array() {
                                document::service::Endpoint::Map(json_val)
                            } else {
                                parse_uri_endpoint(&endpoint_str)
                            }
                        } else {
                            parse_uri_endpoint(&endpoint_str)
                        };

                        svcs.insert(key, PendingService {
                            counter: service_counter,
                            service_type,
                            endpoint,
                        });
                    } else {
                        svcs.shift_remove(&key);
                    }
                }
            }
            // OwnerChanged handled by identityOwner() call
            _ => {}
        }
    }

    // Materialise VMs from the map, sorted by counter for stable ordering.
    let mut vm_entries: Vec<_> = vms.into_values().collect();
    vm_entries.sort_by_key(|v| v.counter);

    for vm_entry in vm_entries {
        match vm_entry.payload {
            PendingVmPayload::Delegate { blockchain_account_id } => {
                let vm_id = format!("{did}#delegate-{}", vm_entry.counter);
                let eip712_id = format!("{did}#delegate-{}-Eip712Method2021", vm_entry.counter);

                let vm_id_url = DIDURLBuf::from_string(vm_id).unwrap();
                let eip712_id_url = DIDURLBuf::from_string(eip712_id).unwrap();

                let vm = VerificationMethod::EcdsaSecp256k1RecoveryMethod2020 {
                    id: vm_id_url.clone(),
                    controller: did.clone(),
                    blockchain_account_id: blockchain_account_id.clone(),
                };

                let eip712_vm = VerificationMethod::Eip712Method2021 {
                    id: eip712_id_url.clone(),
                    controller: did.clone(),
                    blockchain_account_id,
                };

                json_ld_context.add_verification_method_type(vm.type_());
                json_ld_context.add_verification_method_type(eip712_vm.type_());

                doc.verification_method.push(vm.into());
                doc.verification_method.push(eip712_vm.into());

                doc.verification_relationships
                    .assertion_method
                    .push(vm_id_url.clone().into());
                doc.verification_relationships
                    .assertion_method
                    .push(eip712_id_url.clone().into());

                if vm_entry.purpose == KeyPurpose::SigAuth {
                    doc.verification_relationships
                        .authentication
                        .push(vm_id_url.into());
                    doc.verification_relationships
                        .authentication
                        .push(eip712_id_url.into());
                }
            }
            PendingVmPayload::AttributeKey { vm_type, prop_name, prop_value } => {
                let vm_id = format!("{did}#delegate-{}", vm_entry.counter);
                let vm_id_url = DIDURLBuf::from_string(vm_id).unwrap();

                let vm = DIDVerificationMethod {
                    id: vm_id_url.clone(),
                    type_: vm_type.name().to_owned(),
                    controller: did.clone(),
                    properties: [(prop_name.into(), prop_value)]
                        .into_iter()
                        .collect(),
                };

                json_ld_context.add_verification_method_type(vm_type);
                json_ld_context.add_property(prop_name);

                doc.verification_method.push(vm);

                // Route to the correct verification relationship based on
                // the explicit purpose from the attribute name.
                match vm_entry.purpose {
                    KeyPurpose::Enc => {
                        doc.verification_relationships
                            .key_agreement
                            .push(vm_id_url.into());
                    }
                    KeyPurpose::SigAuth => {
                        doc.verification_relationships
                            .assertion_method
                            .push(vm_id_url.clone().into());
                        doc.verification_relationships
                            .authentication
                            .push(vm_id_url.into());
                    }
                    KeyPurpose::VeriKey => {
                        doc.verification_relationships
                            .assertion_method
                            .push(vm_id_url.into());
                    }
                }
            }
        }
    }

    // Materialise services from the map, sorted by counter.
    let mut svc_entries: Vec<_> = svcs.into_values().collect();
    svc_entries.sort_by_key(|s| s.counter);

    for svc_entry in svc_entries {
        let service_id = format!("{did}#service-{}", svc_entry.counter);
        let service = document::Service {
            id: iref::UriBuf::new(service_id.into_bytes()).unwrap(),
            type_: ssi_core::one_or_many::OneOrMany::One(svc_entry.service_type),
            service_endpoint: Some(ssi_core::one_or_many::OneOrMany::One(svc_entry.endpoint)),
            property_set: std::collections::BTreeMap::new(),
        };
        doc.service.push(service);
    }
}

/// Helper to parse a string as a URI endpoint, falling back to a string-valued Map.
pub(crate) fn parse_uri_endpoint(s: &str) -> document::service::Endpoint {
    match iref::UriBuf::new(s.as_bytes().to_vec()) {
        Ok(uri) => document::service::Endpoint::Uri(uri),
        Err(e) => document::service::Endpoint::Map(
            serde_json::Value::String(String::from_utf8_lossy(&e.0).into_owned()),
        ),
    }
}

/// Resolve a DID using the offline (genesis document) path
pub(crate) fn resolve_offline(
    method_specific_id: &str,
    decoded_id: &DecodedMethodSpecificId,
    options: resolution::Options,
) -> Result<Output<Vec<u8>>, Error> {
    let mut json_ld_context = JsonLdContext::default();

    let doc = match decoded_id.address_or_public_key.len() {
        42 => resolve_address(
            &mut json_ld_context,
            method_specific_id,
            &decoded_id.network_chain,
            &decoded_id.address_or_public_key,
        ),
        68 => resolve_public_key(
            &mut json_ld_context,
            method_specific_id,
            &decoded_id.network_chain,
            &decoded_id.address_or_public_key,
        ),
        _ => Err(Error::InvalidMethodSpecificId(
            method_specific_id.to_owned(),
        )),
    }?;

    serialize_document(doc, json_ld_context, options, document::Metadata::default())
}

pub(crate) fn serialize_document(
    doc: Document,
    json_ld_context: JsonLdContext,
    options: resolution::Options,
    doc_metadata: document::Metadata,
) -> Result<Output<Vec<u8>>, Error> {
    let content_type = options.accept.unwrap_or(MediaType::JsonLd);
    let represented = doc.into_representation(representation::Options::from_media_type(
        content_type,
        move || representation::json_ld::Options {
            context: representation::json_ld::Context::array(
                representation::json_ld::DIDContext::V1,
                json_ld_context.into_entries(),
            ),
        },
    ));

    Ok(resolution::Output::new(
        represented.to_bytes(),
        doc_metadata,
        resolution::Metadata::from_content_type(Some(content_type.to_string())),
    ))
}

pub(crate) fn resolve_address(
    json_ld_context: &mut JsonLdContext,
    method_specific_id: &str,
    network_chain: &NetworkChain,
    account_address: &str,
) -> Result<Document, Error> {
    let blockchain_account_id = BlockchainAccountId {
        account_address: account_address.to_owned(),
        chain_id: ChainId {
            namespace: "eip155".to_string(),
            reference: network_chain.id().to_string(),
        },
    };

    let did = DIDBuf::from_string(format!("did:ethr:{method_specific_id}")).unwrap();

    let vm = VerificationMethod::EcdsaSecp256k1RecoveryMethod2020 {
        id: DIDURLBuf::from_string(format!("{did}#controller")).unwrap(),
        controller: did.to_owned(),
        blockchain_account_id: blockchain_account_id.clone(),
    };

    let eip712_vm = VerificationMethod::Eip712Method2021 {
        id: DIDURLBuf::from_string(format!("{did}#Eip712Method2021")).unwrap(),
        controller: did.to_owned(),
        blockchain_account_id,
    };

    json_ld_context.add_verification_method_type(vm.type_());
    json_ld_context.add_verification_method_type(eip712_vm.type_());

    let vm_id = vm.id().to_owned();
    let eip712_vm_id = eip712_vm.id().to_owned();

    let mut doc = Document::new(did);
    doc.verification_relationships.assertion_method =
        vec![vm_id.clone().into(), eip712_vm_id.clone().into()];
    doc.verification_relationships.authentication =
        vec![vm_id.into(), eip712_vm_id.into()];
    doc.verification_method = vec![vm.into(), eip712_vm.into()];

    Ok(doc)
}

/// Resolve an Ethr DID that uses a public key hex string instead of an account address
pub(crate) fn resolve_public_key(
    json_ld_context: &mut JsonLdContext,
    method_specific_id: &str,
    network_chain: &NetworkChain,
    public_key_hex: &str,
) -> Result<Document, Error> {
    if !public_key_hex.starts_with("0x") {
        return Err(Error::InvalidMethodSpecificId(
            method_specific_id.to_owned(),
        ));
    }

    let pk_bytes = hex::decode(&public_key_hex[2..])
        .map_err(|_| Error::InvalidMethodSpecificId(method_specific_id.to_owned()))?;

    let pk_jwk = ssi_jwk::secp256k1_parse(&pk_bytes)
        .map_err(|_| Error::InvalidMethodSpecificId(method_specific_id.to_owned()))?;

    let account_address = ssi_jwk::eip155::hash_public_key_eip55(&pk_jwk)
        .map_err(|_| Error::InvalidMethodSpecificId(method_specific_id.to_owned()))?;

    let blockchain_account_id = BlockchainAccountId {
        account_address,
        chain_id: ChainId {
            namespace: "eip155".to_string(),
            reference: network_chain.id().to_string(),
        },
    };

    let did = DIDBuf::from_string(format!("did:ethr:{method_specific_id}")).unwrap();

    let vm = VerificationMethod::EcdsaSecp256k1RecoveryMethod2020 {
        id: DIDURLBuf::from_string(format!("{did}#controller")).unwrap(),
        controller: did.to_owned(),
        blockchain_account_id: blockchain_account_id.clone(),
    };

    let key_vm = VerificationMethod::EcdsaSecp256k1VerificationKey2019 {
        id: DIDURLBuf::from_string(format!("{did}#controllerKey")).unwrap(),
        controller: did.to_owned(),
        public_key_jwk: pk_jwk,
    };

    let eip712_vm = VerificationMethod::Eip712Method2021 {
        id: DIDURLBuf::from_string(format!("{did}#Eip712Method2021")).unwrap(),
        controller: did.to_owned(),
        blockchain_account_id,
    };

    json_ld_context.add_verification_method_type(vm.type_());
    json_ld_context.add_verification_method_type(key_vm.type_());
    json_ld_context.add_verification_method_type(eip712_vm.type_());
    json_ld_context.add_property("publicKeyJwk");

    let mut doc = Document::new(did);
    doc.verification_relationships.assertion_method = vec![
        vm.id().to_owned().into(),
        key_vm.id().to_owned().into(),
        eip712_vm.id().to_owned().into(),
    ];
    doc.verification_relationships.authentication = vec![
        vm.id().to_owned().into(),
        key_vm.id().to_owned().into(),
        eip712_vm.id().to_owned().into(),
    ];
    doc.verification_method = vec![vm.into(), key_vm.into(), eip712_vm.into()];

    Ok(doc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::{abi_encode_address, CHANGED_SELECTOR, IDENTITY_OWNER_SELECTOR};
    use crate::events::{topic_owner_changed, topic_delegate_changed, topic_attribute_changed};
    use crate::provider::{BlockRef, EthProvider, Log, LogFilter, NetworkConfig};
    use ssi_dids_core::{did, DIDResolver};

    // --- Mock provider for on-chain resolution tests ---

    #[derive(Debug)]
    struct MockProviderError(String);
    impl std::fmt::Display for MockProviderError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "MockProviderError: {}", self.0)
        }
    }
    impl std::error::Error for MockProviderError {}

    /// Mock provider that returns configurable responses for changed(), identityOwner(), and get_logs()
    struct MockProvider {
        /// Block number to return for changed(addr) calls
        changed_block: u64,
        /// Address to return for identityOwner(addr) calls (None = return the queried address)
        identity_owner: Option<[u8; 20]>,
        /// Per-block identity owners for historical resolution (block -> owner)
        /// When identityOwner is called at BlockRef::Number(n), returns the owner for
        /// the highest block <= n, falling back to identity_owner
        identity_owner_at_block: HashMap<u64, [u8; 20]>,
        /// Logs to return for get_logs calls, keyed by block number
        logs: HashMap<u64, Vec<Log>>,
        /// Block timestamps to return for block_timestamp calls
        block_timestamps: HashMap<u64, u64>,
    }

    impl MockProvider {
        fn new_unchanged() -> Self {
            Self {
                changed_block: 0,
                identity_owner: None,
                identity_owner_at_block: HashMap::new(),
                logs: HashMap::new(),
                block_timestamps: HashMap::new(),
            }
        }

        fn new_same_owner() -> Self {
            Self {
                changed_block: 1, // has changes
                identity_owner: None, // but owner is the same
                identity_owner_at_block: HashMap::new(),
                logs: HashMap::new(),
                block_timestamps: HashMap::new(),
            }
        }
    }

    impl EthProvider for MockProvider {
        type Error = MockProviderError;

        async fn call(
            &self,
            _to: [u8; 20],
            data: Vec<u8>,
            block: BlockRef,
        ) -> Result<Vec<u8>, Self::Error> {
            if data.len() < 4 {
                return Err(MockProviderError("calldata too short".into()));
            }
            let selector: [u8; 4] = data[..4].try_into().unwrap();
            match selector {
                CHANGED_SELECTOR => {
                    // Return changed_block as uint256
                    let mut result = vec![0u8; 32];
                    result[24..32].copy_from_slice(&self.changed_block.to_be_bytes());
                    Ok(result)
                }
                IDENTITY_OWNER_SELECTOR => {
                    let mut result = vec![0u8; 32];
                    // For block-specific queries, check identity_owner_at_block first
                    if let BlockRef::Number(n) = block {
                        if !self.identity_owner_at_block.is_empty() {
                            // Find the owner at or before block n
                            let owner = self.identity_owner_at_block
                                .iter()
                                .filter(|(&b, _)| b <= n)
                                .max_by_key(|(&b, _)| b)
                                .map(|(_, o)| *o);
                            if let Some(o) = owner {
                                result[12..32].copy_from_slice(&o);
                                return Ok(result);
                            }
                        }
                    }
                    // Fallback to identity_owner or echo back the queried address
                    if let Some(owner) = self.identity_owner {
                        result[12..32].copy_from_slice(&owner);
                    } else if data.len() >= 36 {
                        result[12..32].copy_from_slice(&data[16..36]);
                    }
                    Ok(result)
                }
                _ => Err(MockProviderError(format!(
                    "unknown selector: {:?}",
                    selector
                ))),
            }
        }

        async fn get_logs(&self, filter: LogFilter) -> Result<Vec<Log>, Self::Error> {
            // Return logs for the requested block range, filtering by topic0 and topic1
            let mut result = Vec::new();
            for block in filter.from_block..=filter.to_block {
                if let Some(block_logs) = self.logs.get(&block) {
                    for log in block_logs {
                        // Filter by topic0 if specified
                        if !filter.topic0.is_empty() && !log.topics.is_empty() {
                            if !filter.topic0.contains(&log.topics[0]) {
                                continue;
                            }
                        }
                        // Filter by topic1 if specified
                        if let Some(t1) = filter.topic1 {
                            if log.topics.len() < 2 || log.topics[1] != t1 {
                                continue;
                            }
                        }
                        result.push(Log {
                            address: log.address,
                            topics: log.topics.clone(),
                            data: log.data.clone(),
                            block_number: log.block_number,
                            log_index: log.log_index,
                        });
                    }
                }
            }
            Ok(result)
        }

        async fn block_timestamp(&self, block: u64) -> Result<u64, Self::Error> {
            Ok(self.block_timestamps.get(&block).copied().unwrap_or(0))
        }
    }

    const TEST_REGISTRY: [u8; 20] = [
        0xdc, 0xa7, 0xef, 0x03, 0xe9, 0x8e, 0x0d, 0xc2,
        0xb8, 0x55, 0xbe, 0x64, 0x7c, 0x39, 0xab, 0xe9,
        0x84, 0xfc, 0xf2, 0x1b,
    ];

    /// Build a DIDOwnerChanged log entry for testing
    fn make_owner_changed_log(
        block: u64,
        identity: &[u8; 20],
        new_owner: &[u8; 20],
        previous_change: u64,
    ) -> Log {
        let identity_topic = abi_encode_address(identity);
        let mut data = vec![0u8; 64];
        // data[0:32] = owner (address, zero-padded to 32 bytes)
        data[12..32].copy_from_slice(new_owner);
        // data[32:64] = previousChange (uint256)
        data[56..64].copy_from_slice(&previous_change.to_be_bytes());

        Log {
            address: TEST_REGISTRY,
            topics: vec![topic_owner_changed(), identity_topic],
            data,
            block_number: block,
            log_index: 0,
        }
    }

    /// Build a DIDDelegateChanged log entry for testing
    fn make_delegate_changed_log(
        block: u64,
        identity: &[u8; 20],
        delegate_type: &[u8; 32],
        delegate: &[u8; 20],
        valid_to: u64,
        previous_change: u64,
    ) -> Log {
        let identity_topic = abi_encode_address(identity);
        let mut data = vec![0u8; 128];
        // data[0:32] = delegateType
        data[0..32].copy_from_slice(delegate_type);
        // data[32:64] = delegate (address, zero-padded)
        data[44..64].copy_from_slice(delegate);
        // data[64:96] = validTo
        data[88..96].copy_from_slice(&valid_to.to_be_bytes());
        // data[96:128] = previousChange
        data[120..128].copy_from_slice(&previous_change.to_be_bytes());

        Log {
            address: TEST_REGISTRY,
            topics: vec![topic_delegate_changed(), identity_topic],
            data,
            block_number: block,
            log_index: 0,
        }
    }

    /// Build a DIDAttributeChanged log entry for testing
    fn make_attribute_changed_log(
        block: u64,
        identity: &[u8; 20],
        name: &[u8; 32],
        value: &[u8],
        valid_to: u64,
        previous_change: u64,
    ) -> Log {
        let identity_topic = abi_encode_address(identity);
        // data layout: name(32) + offset(32) + validTo(32) + previousChange(32) + valueLen(32) + value(padded)
        let padded_value_len = ((value.len() + 31) / 32) * 32;
        let total_len = 160 + padded_value_len;
        let mut data = vec![0u8; total_len];
        // data[0:32] = name
        data[0..32].copy_from_slice(name);
        // data[32:64] = offset to value (always 0xa0 = 160)
        data[56..64].copy_from_slice(&160u64.to_be_bytes());
        // data[64:96] = validTo
        data[88..96].copy_from_slice(&valid_to.to_be_bytes());
        // data[96:128] = previousChange
        data[120..128].copy_from_slice(&previous_change.to_be_bytes());
        // data[128:160] = value length
        data[152..160].copy_from_slice(&(value.len() as u64).to_be_bytes());
        // data[160..] = value bytes
        data[160..160 + value.len()].copy_from_slice(value);

        Log {
            address: TEST_REGISTRY,
            topics: vec![topic_attribute_changed(), identity_topic],
            data,
            block_number: block,
            log_index: 0,
        }
    }

    /// Helper: encode a delegate type string as bytes32 (right-padded with zeros)
    fn encode_delegate_type(s: &str) -> [u8; 32] {
        let mut b = [0u8; 32];
        let bytes = s.as_bytes();
        b[..bytes.len().min(32)].copy_from_slice(&bytes[..bytes.len().min(32)]);
        b
    }

    /// Helper: encode an attribute name string as bytes32 (right-padded with zeros)
    fn encode_attr_name(s: &str) -> [u8; 32] {
        let mut b = [0u8; 32];
        let bytes = s.as_bytes();
        b[..bytes.len().min(32)].copy_from_slice(&bytes[..bytes.len().min(32)]);
        b
    }

    /// A valid compressed secp256k1 public key (33 bytes) for use in tests.
    const TEST_SECP256K1_COMPRESSED: [u8; 33] = [
        0x03, 0xfd, 0xd5, 0x7a, 0xde, 0xc3, 0xd4, 0x38, 0xea, 0x23, 0x7f,
        0xe4, 0x6b, 0x33, 0xee, 0x1e, 0x01, 0x6e, 0xda, 0x6b, 0x58, 0x5c,
        0x3e, 0x27, 0xea, 0x66, 0x68, 0x6c, 0x2e, 0xa5, 0x35, 0x84, 0x79,
    ];

    /// A second valid compressed secp256k1 public key (different from the first).
    const TEST_SECP256K1_COMPRESSED_2: [u8; 33] = [
        0x02, 0xb9, 0x7c, 0x30, 0xde, 0x76, 0x7f, 0x08, 0x4c, 0xe3, 0x08,
        0x09, 0x68, 0xd8, 0x53, 0xd0, 0x3c, 0x3a, 0x28, 0x86, 0x53, 0xf8,
        0x12, 0x64, 0xa0, 0x90, 0xcd, 0x20, 0x3a, 0x12, 0xe5, 0x60, 0x40,
    ];

    #[tokio::test]
    async fn resolve_with_mock_provider_changed_zero() {
        // A mock provider where changed(addr) returns 0 should produce
        // the same document as offline resolution.
        let mut resolver = DIDEthr::new();
        resolver.add_network(
            "mainnet",
            NetworkConfig {
                chain_id: 1,
                registry: [0xdc, 0xa7, 0xef, 0x03, 0xe9, 0x8e, 0x0d, 0xc2,
                           0xb8, 0x55, 0xbe, 0x64, 0x7c, 0x39, 0xab, 0xe9,
                           0x84, 0xfc, 0xf2, 0x1b],
                provider: MockProvider::new_unchanged(),
            },
        );

        let doc_onchain = resolver
            .resolve(did!(
                "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a"
            ))
            .await
            .unwrap()
            .document;

        let doc_offline = DIDEthr::<()>::default()
            .resolve(did!(
                "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a"
            ))
            .await
            .unwrap()
            .document;

        assert_eq!(
            serde_json::to_value(&doc_onchain).unwrap(),
            serde_json::to_value(&doc_offline).unwrap(),
            "mock provider with changed=0 should produce same doc as offline"
        );
    }

    #[tokio::test]
    async fn resolve_with_mock_provider_owner_changed_address_did() {
        // When identityOwner(addr) returns a different address, the #controller
        // and Eip712Method2021 VMs should use the new owner's address in
        // blockchainAccountId.
        let new_owner: [u8; 20] = [0x11; 20];
        let mut resolver = DIDEthr::new();
        resolver.add_network(
            "mainnet",
            NetworkConfig {
                chain_id: 1,
                registry: [0xdc, 0xa7, 0xef, 0x03, 0xe9, 0x8e, 0x0d, 0xc2,
                           0xb8, 0x55, 0xbe, 0x64, 0x7c, 0x39, 0xab, 0xe9,
                           0x84, 0xfc, 0xf2, 0x1b],
                provider: MockProvider {
                    changed_block: 1,
                    identity_owner: Some(new_owner),
                    logs: HashMap::new(),
                    block_timestamps: HashMap::new(),
                    identity_owner_at_block: HashMap::new(),
                },
            },
        );

        let doc = resolver
            .resolve(did!(
                "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a"
            ))
            .await
            .unwrap()
            .document;

        let doc_value = serde_json::to_value(&doc).unwrap();

        // The DID id should still use the original address
        assert_eq!(
            doc_value["id"],
            "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a"
        );

        // #controller VM should use the new owner's address
        let vms = doc_value["verificationMethod"].as_array().unwrap();
        let controller_vm = vms.iter().find(|vm| {
            vm["id"].as_str().unwrap().ends_with("#controller")
        }).expect("should have #controller VM");
        assert_eq!(
            controller_vm["blockchainAccountId"],
            "eip155:1:0x1111111111111111111111111111111111111111"
        );

        // Eip712Method2021 should also use the new owner's address
        let eip712_vm = vms.iter().find(|vm| {
            vm["id"].as_str().unwrap().ends_with("#Eip712Method2021")
        }).expect("should have #Eip712Method2021 VM");
        assert_eq!(
            eip712_vm["blockchainAccountId"],
            "eip155:1:0x1111111111111111111111111111111111111111"
        );

        // Should only have 2 VMs (no controllerKey for address-based DID)
        assert_eq!(vms.len(), 2);
    }

    #[tokio::test]
    async fn resolve_with_mock_provider_owner_changed_pubkey_did() {
        // When a public-key DID has a changed owner, #controllerKey must be
        // omitted (the pubkey no longer represents the current owner).
        // Only #controller and Eip712Method2021 remain.
        let new_owner: [u8; 20] = [0x22; 20];
        let mut resolver = DIDEthr::new();
        resolver.add_network(
            "mainnet",
            NetworkConfig {
                chain_id: 1,
                registry: [0xdc, 0xa7, 0xef, 0x03, 0xe9, 0x8e, 0x0d, 0xc2,
                           0xb8, 0x55, 0xbe, 0x64, 0x7c, 0x39, 0xab, 0xe9,
                           0x84, 0xfc, 0xf2, 0x1b],
                provider: MockProvider {
                    changed_block: 1,
                    identity_owner: Some(new_owner),
                    logs: HashMap::new(),
                    block_timestamps: HashMap::new(),
                    identity_owner_at_block: HashMap::new(),
                },
            },
        );

        let did_str = "did:ethr:0x03fdd57adec3d438ea237fe46b33ee1e016eda6b585c3e27ea66686c2ea5358479";
        let doc = resolver
            .resolve(did!(
                "did:ethr:0x03fdd57adec3d438ea237fe46b33ee1e016eda6b585c3e27ea66686c2ea5358479"
            ))
            .await
            .unwrap()
            .document;

        let doc_value = serde_json::to_value(&doc).unwrap();

        // DID id still uses the original public key
        assert_eq!(doc_value["id"], did_str);

        let vms = doc_value["verificationMethod"].as_array().unwrap();

        // Should have exactly 2 VMs: #controller and #Eip712Method2021
        assert_eq!(vms.len(), 2, "should have 2 VMs, not 3 (no #controllerKey)");

        // No #controllerKey
        assert!(
            vms.iter().all(|vm| !vm["id"].as_str().unwrap().ends_with("#controllerKey")),
            "#controllerKey should be omitted when owner has changed"
        );

        // #controller uses new owner's blockchainAccountId
        let controller_vm = vms.iter().find(|vm| {
            vm["id"].as_str().unwrap().ends_with("#controller")
        }).expect("should have #controller VM");
        assert_eq!(
            controller_vm["blockchainAccountId"],
            "eip155:1:0x2222222222222222222222222222222222222222"
        );

        // Eip712Method2021 uses new owner's blockchainAccountId
        let eip712_vm = vms.iter().find(|vm| {
            vm["id"].as_str().unwrap().ends_with("#Eip712Method2021")
        }).expect("should have #Eip712Method2021 VM");
        assert_eq!(
            eip712_vm["blockchainAccountId"],
            "eip155:1:0x2222222222222222222222222222222222222222"
        );
    }

    #[tokio::test]
    async fn resolve_with_mock_provider_identity_owner_same() {
        // A mock provider where identityOwner(addr) returns the same address
        // should produce the same document as offline resolution.
        let mut resolver = DIDEthr::new();
        resolver.add_network(
            "mainnet",
            NetworkConfig {
                chain_id: 1,
                registry: [0xdc, 0xa7, 0xef, 0x03, 0xe9, 0x8e, 0x0d, 0xc2,
                           0xb8, 0x55, 0xbe, 0x64, 0x7c, 0x39, 0xab, 0xe9,
                           0x84, 0xfc, 0xf2, 0x1b],
                provider: MockProvider::new_same_owner(),
            },
        );

        let doc_onchain = resolver
            .resolve(did!(
                "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a"
            ))
            .await
            .unwrap()
            .document;

        let doc_offline = DIDEthr::<()>::default()
            .resolve(did!(
                "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a"
            ))
            .await
            .unwrap()
            .document;

        assert_eq!(
            serde_json::to_value(&doc_onchain).unwrap(),
            serde_json::to_value(&doc_offline).unwrap(),
            "mock provider with identityOwner=same should produce same doc as offline"
        );
    }

    #[tokio::test]
    async fn resolve_with_mock_provider_owner_same_pubkey_did_retains_controller_key() {
        // When a public-key DID's owner hasn't changed, #controllerKey
        // must be retained in the document.
        let mut resolver = DIDEthr::new();
        resolver.add_network(
            "mainnet",
            NetworkConfig {
                chain_id: 1,
                registry: [0xdc, 0xa7, 0xef, 0x03, 0xe9, 0x8e, 0x0d, 0xc2,
                           0xb8, 0x55, 0xbe, 0x64, 0x7c, 0x39, 0xab, 0xe9,
                           0x84, 0xfc, 0xf2, 0x1b],
                provider: MockProvider::new_same_owner(),
            },
        );

        let doc = resolver
            .resolve(did!(
                "did:ethr:0x03fdd57adec3d438ea237fe46b33ee1e016eda6b585c3e27ea66686c2ea5358479"
            ))
            .await
            .unwrap()
            .document;

        let doc_value = serde_json::to_value(&doc).unwrap();
        let vms = doc_value["verificationMethod"].as_array().unwrap();

        // Should have 3 VMs: #controller, #controllerKey, Eip712Method2021
        // (Note: Eip712Method2021 is only on the controller, not the key,
        // so the exact set depends on the offline resolve_public_key behavior)
        assert!(
            vms.iter().any(|vm| vm["id"].as_str().unwrap().ends_with("#controllerKey")),
            "#controllerKey should be retained when owner is unchanged"
        );

        // #controllerKey should have publicKeyJwk
        let key_vm = vms.iter().find(|vm| {
            vm["id"].as_str().unwrap().ends_with("#controllerKey")
        }).unwrap();
        assert!(key_vm.get("publicKeyJwk").is_some(), "#controllerKey should have publicKeyJwk");
    }

    #[tokio::test]
    async fn resolve_verikey_delegate_adds_vm() {
        // A DIDDelegateChanged event with delegate_type="veriKey" and valid_to=MAX
        // should add EcdsaSecp256k1RecoveryMethod2020 + Eip712Method2021 VMs
        // with #delegate-1 and #delegate-1-Eip712Method2021 IDs.
        // The delegate VM is referenced in assertionMethod but NOT authentication.
        let identity: [u8; 20] = [0xb9, 0xc5, 0x71, 0x40, 0x89, 0x47, 0x8a, 0x32, 0x7f, 0x09,
                                   0x19, 0x79, 0x87, 0xf1, 0x6f, 0x9e, 0x5d, 0x93, 0x6e, 0x8a];
        let delegate: [u8; 20] = [0xAA; 20];
        let delegate_type = encode_delegate_type("veriKey");

        let log = make_delegate_changed_log(100, &identity, &delegate_type, &delegate, u64::MAX, 0);

        let mut resolver = DIDEthr::new();
        resolver.add_network(
            "mainnet",
            NetworkConfig {
                chain_id: 1,
                registry: TEST_REGISTRY,
                provider: MockProvider {
                    changed_block: 100,
                    identity_owner: None, // same as identity
                    logs: HashMap::from([(100, vec![log])]),
                    block_timestamps: HashMap::new(),
                    identity_owner_at_block: HashMap::new(),
                },
            },
        );

        let doc = resolver
            .resolve(did!("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a"))
            .await
            .unwrap()
            .document;

        let doc_value = serde_json::to_value(&doc).unwrap();
        eprintln!("{}", serde_json::to_string_pretty(&doc_value).unwrap());

        let vms = doc_value["verificationMethod"].as_array().unwrap();

        // Should have 4 VMs: #controller, #Eip712Method2021, #delegate-1, #delegate-1-Eip712Method2021
        assert_eq!(vms.len(), 4, "expected 4 VMs, got {}", vms.len());

        // Check #delegate-1 VM
        let delegate_vm = vms.iter().find(|vm| {
            vm["id"].as_str().unwrap().ends_with("#delegate-1")
        }).expect("should have #delegate-1 VM");
        assert_eq!(delegate_vm["type"], "EcdsaSecp256k1RecoveryMethod2020");
        let delegate_addr = format_address_eip55(&delegate);
        let expected_account_id = format!("eip155:1:{}", delegate_addr);
        assert_eq!(delegate_vm["blockchainAccountId"], expected_account_id);

        // Check #delegate-1-Eip712Method2021 VM
        let delegate_eip712 = vms.iter().find(|vm| {
            vm["id"].as_str().unwrap().ends_with("#delegate-1-Eip712Method2021")
        }).expect("should have #delegate-1-Eip712Method2021 VM");
        assert_eq!(delegate_eip712["type"], "Eip712Method2021");
        assert_eq!(delegate_eip712["blockchainAccountId"], expected_account_id);

        // #delegate-1 should be in assertionMethod but NOT authentication
        let assertion = doc_value["assertionMethod"].as_array().unwrap();
        let auth = doc_value["authentication"].as_array().unwrap();

        let did_prefix = "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a";
        assert!(assertion.iter().any(|v| v == &format!("{did_prefix}#delegate-1")));
        assert!(assertion.iter().any(|v| v == &format!("{did_prefix}#delegate-1-Eip712Method2021")));
        assert!(!auth.iter().any(|v| v == &format!("{did_prefix}#delegate-1")));
        assert!(!auth.iter().any(|v| v == &format!("{did_prefix}#delegate-1-Eip712Method2021")));
    }

    #[tokio::test]
    async fn resolve_sigauth_delegate_also_in_authentication() {
        // A DIDDelegateChanged with delegate_type="sigAuth" should add VMs
        // referenced in BOTH assertionMethod AND authentication.
        let identity: [u8; 20] = [0xb9, 0xc5, 0x71, 0x40, 0x89, 0x47, 0x8a, 0x32, 0x7f, 0x09,
                                   0x19, 0x79, 0x87, 0xf1, 0x6f, 0x9e, 0x5d, 0x93, 0x6e, 0x8a];
        let delegate: [u8; 20] = [0xBB; 20];
        let delegate_type = encode_delegate_type("sigAuth");

        let log = make_delegate_changed_log(100, &identity, &delegate_type, &delegate, u64::MAX, 0);

        let mut resolver = DIDEthr::new();
        resolver.add_network(
            "mainnet",
            NetworkConfig {
                chain_id: 1,
                registry: TEST_REGISTRY,
                provider: MockProvider {
                    changed_block: 100,
                    identity_owner: None,
                    logs: HashMap::from([(100, vec![log])]),
                    block_timestamps: HashMap::new(),
                    identity_owner_at_block: HashMap::new(),
                },
            },
        );

        let doc = resolver
            .resolve(did!("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a"))
            .await
            .unwrap()
            .document;

        let doc_value = serde_json::to_value(&doc).unwrap();
        let did_prefix = "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a";

        let vms = doc_value["verificationMethod"].as_array().unwrap();
        assert_eq!(vms.len(), 4);

        // #delegate-1 should be in BOTH assertionMethod AND authentication
        let assertion = doc_value["assertionMethod"].as_array().unwrap();
        let auth = doc_value["authentication"].as_array().unwrap();

        assert!(assertion.iter().any(|v| v == &format!("{did_prefix}#delegate-1")));
        assert!(assertion.iter().any(|v| v == &format!("{did_prefix}#delegate-1-Eip712Method2021")));
        assert!(auth.iter().any(|v| v == &format!("{did_prefix}#delegate-1")));
        assert!(auth.iter().any(|v| v == &format!("{did_prefix}#delegate-1-Eip712Method2021")));
    }

    #[tokio::test]
    async fn resolve_expired_delegate_not_included() {
        // A delegate with valid_to < now is NOT included in the document.
        let identity: [u8; 20] = [0xb9, 0xc5, 0x71, 0x40, 0x89, 0x47, 0x8a, 0x32, 0x7f, 0x09,
                                   0x19, 0x79, 0x87, 0xf1, 0x6f, 0x9e, 0x5d, 0x93, 0x6e, 0x8a];
        let delegate: [u8; 20] = [0xCC; 20];
        let delegate_type = encode_delegate_type("veriKey");

        // valid_to = 1000 (well in the past)
        let log = make_delegate_changed_log(100, &identity, &delegate_type, &delegate, 1000, 0);

        let mut resolver = DIDEthr::new();
        resolver.add_network(
            "mainnet",
            NetworkConfig {
                chain_id: 1,
                registry: TEST_REGISTRY,
                provider: MockProvider {
                    changed_block: 100,
                    identity_owner: None,
                    logs: HashMap::from([(100, vec![log])]),
                    block_timestamps: HashMap::new(),
                    identity_owner_at_block: HashMap::new(),
                },
            },
        );

        let doc = resolver
            .resolve(did!("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a"))
            .await
            .unwrap()
            .document;

        let doc_value = serde_json::to_value(&doc).unwrap();
        let vms = doc_value["verificationMethod"].as_array().unwrap();

        // Should only have the 2 base VMs (no delegate VMs)
        assert_eq!(vms.len(), 2, "expired delegate should not be in document");
        assert!(vms.iter().all(|vm| !vm["id"].as_str().unwrap().contains("delegate")));
    }

    #[tokio::test]
    async fn resolve_revoked_delegate_skipped_but_counter_increments() {
        // A revoked delegate (valid_to=0) is not included, but the counter
        // still increments. So a subsequent valid delegate gets #delegate-2.
        let identity: [u8; 20] = [0xb9, 0xc5, 0x71, 0x40, 0x89, 0x47, 0x8a, 0x32, 0x7f, 0x09,
                                   0x19, 0x79, 0x87, 0xf1, 0x6f, 0x9e, 0x5d, 0x93, 0x6e, 0x8a];
        let delegate_a: [u8; 20] = [0xDD; 20];
        let delegate_b: [u8; 20] = [0xEE; 20];
        let delegate_type = encode_delegate_type("veriKey");

        // First delegate: revoked (valid_to=0)
        let log_a = make_delegate_changed_log(100, &identity, &delegate_type, &delegate_a, 0, 0);
        // Second delegate: valid
        let log_b = make_delegate_changed_log(200, &identity, &delegate_type, &delegate_b, u64::MAX, 100);

        let mut resolver = DIDEthr::new();
        resolver.add_network(
            "mainnet",
            NetworkConfig {
                chain_id: 1,
                registry: TEST_REGISTRY,
                provider: MockProvider {
                    changed_block: 200,
                    identity_owner: None,
                    logs: HashMap::from([
                        (100, vec![log_a]),
                        (200, vec![log_b]),
                    ]),
                    block_timestamps: HashMap::new(),
                    identity_owner_at_block: HashMap::new(),
                },
            },
        );

        let doc = resolver
            .resolve(did!("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a"))
            .await
            .unwrap()
            .document;

        let doc_value = serde_json::to_value(&doc).unwrap();
        let vms = doc_value["verificationMethod"].as_array().unwrap();

        // Should have 4 VMs: 2 base + 2 delegate (only delegate_b)
        assert_eq!(vms.len(), 4);

        // No #delegate-1 (revoked)
        assert!(vms.iter().all(|vm| !vm["id"].as_str().unwrap().ends_with("#delegate-1")));

        // Has #delegate-2 (counter still incremented past revoked)
        let delegate_vm = vms.iter().find(|vm| {
            vm["id"].as_str().unwrap().ends_with("#delegate-2")
        }).expect("should have #delegate-2 VM");

        let delegate_addr = format_address_eip55(&delegate_b);
        assert_eq!(delegate_vm["blockchainAccountId"], format!("eip155:1:{delegate_addr}"));
    }

    #[tokio::test]
    async fn resolve_multiple_valid_delegates_sequential_ids() {
        // Multiple valid delegates produce sequential #delegate-1, #delegate-2, etc.
        let identity: [u8; 20] = [0xb9, 0xc5, 0x71, 0x40, 0x89, 0x47, 0x8a, 0x32, 0x7f, 0x09,
                                   0x19, 0x79, 0x87, 0xf1, 0x6f, 0x9e, 0x5d, 0x93, 0x6e, 0x8a];
        let delegate_a: [u8; 20] = [0x11; 20];
        let delegate_b: [u8; 20] = [0x22; 20];
        let veri_key = encode_delegate_type("veriKey");
        let sig_auth = encode_delegate_type("sigAuth");

        let log_a = make_delegate_changed_log(100, &identity, &veri_key, &delegate_a, u64::MAX, 0);
        let log_b = make_delegate_changed_log(200, &identity, &sig_auth, &delegate_b, u64::MAX, 100);

        let mut resolver = DIDEthr::new();
        resolver.add_network(
            "mainnet",
            NetworkConfig {
                chain_id: 1,
                registry: TEST_REGISTRY,
                provider: MockProvider {
                    changed_block: 200,
                    identity_owner: None,
                    logs: HashMap::from([
                        (100, vec![log_a]),
                        (200, vec![log_b]),
                    ]),
                    block_timestamps: HashMap::new(),
                    identity_owner_at_block: HashMap::new(),
                },
            },
        );

        let doc = resolver
            .resolve(did!("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a"))
            .await
            .unwrap()
            .document;

        let doc_value = serde_json::to_value(&doc).unwrap();
        let vms = doc_value["verificationMethod"].as_array().unwrap();

        // 2 base + 2 for delegate_a + 2 for delegate_b = 6
        assert_eq!(vms.len(), 6);

        // #delegate-1 is veriKey (assertionMethod only, NOT authentication)
        assert!(vms.iter().any(|vm| vm["id"].as_str().unwrap().ends_with("#delegate-1")));
        assert!(vms.iter().any(|vm| vm["id"].as_str().unwrap().ends_with("#delegate-1-Eip712Method2021")));

        // #delegate-2 is sigAuth (both assertionMethod AND authentication)
        assert!(vms.iter().any(|vm| vm["id"].as_str().unwrap().ends_with("#delegate-2")));
        assert!(vms.iter().any(|vm| vm["id"].as_str().unwrap().ends_with("#delegate-2-Eip712Method2021")));

        let did_prefix = "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a";
        let auth = doc_value["authentication"].as_array().unwrap();

        // delegate-1 should NOT be in auth (veriKey)
        assert!(!auth.iter().any(|v| v == &format!("{did_prefix}#delegate-1")));

        // delegate-2 SHOULD be in auth (sigAuth)
        assert!(auth.iter().any(|v| v == &format!("{did_prefix}#delegate-2")));
        assert!(auth.iter().any(|v| v == &format!("{did_prefix}#delegate-2-Eip712Method2021")));
    }

    #[tokio::test]
    async fn resolve_delegate_and_attribute_key_share_counter() {
        // Delegate events and attribute pub key events share the same delegate
        // counter. A delegate at block 100 gets #delegate-1, an attribute key
        // at block 200 gets #delegate-2.
        let identity: [u8; 20] = [0xb9, 0xc5, 0x71, 0x40, 0x89, 0x47, 0x8a, 0x32, 0x7f, 0x09,
                                   0x19, 0x79, 0x87, 0xf1, 0x6f, 0x9e, 0x5d, 0x93, 0x6e, 0x8a];
        let delegate: [u8; 20] = [0xAA; 20];
        let delegate_type = encode_delegate_type("veriKey");
        let attr_name = encode_attr_name("did/pub/Secp256k1/veriKey/hex");

        let log_delegate = make_delegate_changed_log(100, &identity, &delegate_type, &delegate, u64::MAX, 0);
        let log_attr = make_attribute_changed_log(200, &identity, &attr_name, &TEST_SECP256K1_COMPRESSED, u64::MAX, 100);

        let mut resolver = DIDEthr::new();
        resolver.add_network("mainnet", NetworkConfig {
            chain_id: 1,
            registry: TEST_REGISTRY,
            provider: MockProvider {
                changed_block: 200,
                identity_owner: None,
                logs: HashMap::from([(100, vec![log_delegate]), (200, vec![log_attr])]),
                block_timestamps: HashMap::new(),
                identity_owner_at_block: HashMap::new(),
            },
        });

        let doc = resolver
            .resolve(did!("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a"))
            .await.unwrap().document;

        let doc_value = serde_json::to_value(&doc).unwrap();
        let vms = doc_value["verificationMethod"].as_array().unwrap();

        // 2 base + 2 delegate (RecoveryMethod + Eip712) + 1 attribute key = 5
        assert_eq!(vms.len(), 5);

        // #delegate-1 is the delegate event (EcdsaSecp256k1RecoveryMethod2020)
        let d1 = vms.iter().find(|vm| vm["id"].as_str().unwrap().ends_with("#delegate-1")).unwrap();
        assert_eq!(d1["type"], "EcdsaSecp256k1RecoveryMethod2020");

        // #delegate-2 is the attribute key (EcdsaSecp256k1VerificationKey2019 with publicKeyJwk)
        let d2 = vms.iter().find(|vm| vm["id"].as_str().unwrap().ends_with("#delegate-2")).unwrap();
        assert_eq!(d2["type"], "EcdsaSecp256k1VerificationKey2019");
        assert!(d2["publicKeyJwk"].is_object(), "attribute key should have publicKeyJwk");
        assert_eq!(d2["publicKeyJwk"]["kty"], "EC");
        assert_eq!(d2["publicKeyJwk"]["crv"], "secp256k1");
    }

    #[tokio::test]
    async fn resolve_multiple_services_sequential_ids() {
        // Multiple did/svc attributes produce #service-1, #service-2, etc.
        let identity: [u8; 20] = [0xb9, 0xc5, 0x71, 0x40, 0x89, 0x47, 0x8a, 0x32, 0x7f, 0x09,
                                   0x19, 0x79, 0x87, 0xf1, 0x6f, 0x9e, 0x5d, 0x93, 0x6e, 0x8a];
        let attr_hub = encode_attr_name("did/svc/HubService");
        let attr_msg = encode_attr_name("did/svc/MessagingService");

        let log_a = make_attribute_changed_log(100, &identity, &attr_hub, b"https://hub.example.com", u64::MAX, 0);
        let log_b = make_attribute_changed_log(200, &identity, &attr_msg, b"https://msg.example.com", u64::MAX, 100);

        let mut resolver = DIDEthr::new();
        resolver.add_network("mainnet", NetworkConfig {
            chain_id: 1,
            registry: TEST_REGISTRY,
            provider: MockProvider {
                changed_block: 200,
                identity_owner: None,
                logs: HashMap::from([(100, vec![log_a]), (200, vec![log_b])]),
                block_timestamps: HashMap::new(),
                identity_owner_at_block: HashMap::new(),
            },
        });

        let doc = resolver
            .resolve(did!("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a"))
            .await.unwrap().document;

        let doc_value = serde_json::to_value(&doc).unwrap();
        let services = doc_value["service"].as_array().unwrap();
        assert_eq!(services.len(), 2);

        let did_prefix = "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a";
        assert_eq!(services[0]["id"], format!("{did_prefix}#service-1"));
        assert_eq!(services[0]["type"], "HubService");
        assert_eq!(services[1]["id"], format!("{did_prefix}#service-2"));
        assert_eq!(services[1]["type"], "MessagingService");
    }

    #[tokio::test]
    async fn resolve_expired_attribute_excluded_counter_increments() {
        // An expired attribute (valid_to < now) is excluded but the delegate
        // counter still increments, so the next valid entry gets #delegate-2.
        let identity: [u8; 20] = [0xb9, 0xc5, 0x71, 0x40, 0x89, 0x47, 0x8a, 0x32, 0x7f, 0x09,
                                   0x19, 0x79, 0x87, 0xf1, 0x6f, 0x9e, 0x5d, 0x93, 0x6e, 0x8a];
        let attr_name = encode_attr_name("did/pub/Secp256k1/veriKey/hex");

        // First key: expired (valid_to = 1000, well in the past)
        let log_a = make_attribute_changed_log(100, &identity, &attr_name, &TEST_SECP256K1_COMPRESSED, 1000, 0);
        // Second key: valid (different key bytes so they have different content keys)
        let log_b = make_attribute_changed_log(200, &identity, &attr_name, &TEST_SECP256K1_COMPRESSED_2, u64::MAX, 100);

        let mut resolver = DIDEthr::new();
        resolver.add_network("mainnet", NetworkConfig {
            chain_id: 1,
            registry: TEST_REGISTRY,
            provider: MockProvider {
                changed_block: 200,
                identity_owner: None,
                logs: HashMap::from([(100, vec![log_a]), (200, vec![log_b])]),
                block_timestamps: HashMap::new(),
                identity_owner_at_block: HashMap::new(),
            },
        });

        let doc = resolver
            .resolve(did!("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a"))
            .await.unwrap().document;

        let doc_value = serde_json::to_value(&doc).unwrap();
        let vms = doc_value["verificationMethod"].as_array().unwrap();

        // 2 base + 1 valid attribute key = 3 (expired one excluded)
        assert_eq!(vms.len(), 3);

        // No #delegate-1 (expired)
        assert!(vms.iter().all(|vm| !vm["id"].as_str().unwrap().ends_with("#delegate-1")));

        // Has #delegate-2 (counter incremented past expired)
        let vm = vms.iter().find(|vm| {
            vm["id"].as_str().unwrap().ends_with("#delegate-2")
        }).expect("should have #delegate-2 VM");
        assert!(vm["publicKeyJwk"].is_object(), "should have publicKeyJwk as object");
    }

    #[tokio::test]
    async fn resolve_service_endpoint_json() {
        // did/svc/MessagingService with JSON object value → structured serviceEndpoint
        let identity: [u8; 20] = [0xb9, 0xc5, 0x71, 0x40, 0x89, 0x47, 0x8a, 0x32, 0x7f, 0x09,
                                   0x19, 0x79, 0x87, 0xf1, 0x6f, 0x9e, 0x5d, 0x93, 0x6e, 0x8a];
        let attr_name = encode_attr_name("did/svc/MessagingService");
        let endpoint = br#"{"uri":"https://msg.example.com","accept":["didcomm/v2"]}"#;

        let log = make_attribute_changed_log(100, &identity, &attr_name, endpoint, u64::MAX, 0);

        let mut resolver = DIDEthr::new();
        resolver.add_network("mainnet", NetworkConfig {
            chain_id: 1,
            registry: TEST_REGISTRY,
            provider: MockProvider {
                changed_block: 100,
                identity_owner: None,
                logs: HashMap::from([(100, vec![log])]),
                block_timestamps: HashMap::new(),
                identity_owner_at_block: HashMap::new(),
            },
        });

        let doc = resolver
            .resolve(did!("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a"))
            .await.unwrap().document;

        let doc_value = serde_json::to_value(&doc).unwrap();
        let services = doc_value["service"].as_array().unwrap();
        assert_eq!(services.len(), 1);

        let svc = &services[0];
        assert_eq!(svc["type"], "MessagingService");
        // JSON endpoint should be a parsed object, not a string
        assert!(svc["serviceEndpoint"].is_object());
        assert_eq!(svc["serviceEndpoint"]["uri"], "https://msg.example.com");
        assert_eq!(svc["serviceEndpoint"]["accept"], serde_json::json!(["didcomm/v2"]));
    }

    #[tokio::test]
    async fn resolve_service_endpoint_url() {
        // did/svc/HubService with URL string → service entry
        let identity: [u8; 20] = [0xb9, 0xc5, 0x71, 0x40, 0x89, 0x47, 0x8a, 0x32, 0x7f, 0x09,
                                   0x19, 0x79, 0x87, 0xf1, 0x6f, 0x9e, 0x5d, 0x93, 0x6e, 0x8a];
        let attr_name = encode_attr_name("did/svc/HubService");
        let endpoint = b"https://hubs.uport.me";

        let log = make_attribute_changed_log(100, &identity, &attr_name, endpoint, u64::MAX, 0);

        let mut resolver = DIDEthr::new();
        resolver.add_network("mainnet", NetworkConfig {
            chain_id: 1,
            registry: TEST_REGISTRY,
            provider: MockProvider {
                changed_block: 100,
                identity_owner: None,
                logs: HashMap::from([(100, vec![log])]),
                block_timestamps: HashMap::new(),
                identity_owner_at_block: HashMap::new(),
            },
        });

        let doc = resolver
            .resolve(did!("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a"))
            .await.unwrap().document;

        let doc_value = serde_json::to_value(&doc).unwrap();
        eprintln!("{}", serde_json::to_string_pretty(&doc_value).unwrap());
        let services = doc_value["service"].as_array().unwrap();
        assert_eq!(services.len(), 1);

        let svc = &services[0];
        assert_eq!(svc["id"], "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a#service-1");
        assert_eq!(svc["type"], "HubService");
        assert_eq!(svc["serviceEndpoint"], "https://hubs.uport.me");
    }

    #[tokio::test]
    async fn resolve_secp256k1_sigauth_hex_attribute_in_authentication() {
        // did/pub/Secp256k1/sigAuth/hex attribute adds VM referenced in
        // verificationMethod + assertionMethod + authentication.
        // Uses a real compressed secp256k1 key so secp256k1_parse succeeds.
        let identity: [u8; 20] = [0xb9, 0xc5, 0x71, 0x40, 0x89, 0x47, 0x8a, 0x32, 0x7f, 0x09,
                                   0x19, 0x79, 0x87, 0xf1, 0x6f, 0x9e, 0x5d, 0x93, 0x6e, 0x8a];
        let attr_name = encode_attr_name("did/pub/Secp256k1/sigAuth/hex");

        let log = make_attribute_changed_log(100, &identity, &attr_name, &TEST_SECP256K1_COMPRESSED, u64::MAX, 0);

        let mut resolver = DIDEthr::new();
        resolver.add_network("mainnet", NetworkConfig {
            chain_id: 1,
            registry: TEST_REGISTRY,
            provider: MockProvider {
                changed_block: 100,
                identity_owner: None,
                logs: HashMap::from([(100, vec![log])]),
                block_timestamps: HashMap::new(),
                identity_owner_at_block: HashMap::new(),
            },
        });

        let doc = resolver
            .resolve(did!("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a"))
            .await.unwrap().document;

        let doc_value = serde_json::to_value(&doc).unwrap();
        let did_prefix = "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a";

        let vms = doc_value["verificationMethod"].as_array().unwrap();
        // 2 base + 1 attribute key = 3
        assert_eq!(vms.len(), 3);

        let attr_vm = vms.iter().find(|vm| {
            vm["id"].as_str().unwrap().ends_with("#delegate-1")
        }).expect("should have #delegate-1 VM");
        assert_eq!(attr_vm["type"], "EcdsaSecp256k1VerificationKey2019");
        assert!(attr_vm["publicKeyJwk"].is_object(), "should have publicKeyJwk");

        let assertion = doc_value["assertionMethod"].as_array().unwrap();
        let auth = doc_value["authentication"].as_array().unwrap();

        // sigAuth should be in BOTH assertionMethod AND authentication
        assert!(assertion.iter().any(|v| v == &format!("{did_prefix}#delegate-1")));
        assert!(auth.iter().any(|v| v == &format!("{did_prefix}#delegate-1")));
    }

    #[tokio::test]
    async fn resolve_delegates_with_owner_change_integration() {
        // When the owner has changed AND there are delegates, both the
        // owner-derived controller VM and the delegate VMs appear.
        let identity: [u8; 20] = [0xb9, 0xc5, 0x71, 0x40, 0x89, 0x47, 0x8a, 0x32, 0x7f, 0x09,
                                   0x19, 0x79, 0x87, 0xf1, 0x6f, 0x9e, 0x5d, 0x93, 0x6e, 0x8a];
        let new_owner: [u8; 20] = [0xFF; 20];
        let delegate: [u8; 20] = [0xAA; 20];
        let delegate_type = encode_delegate_type("veriKey");

        let log_owner = make_owner_changed_log(100, &identity, &new_owner, 0);
        let log_delegate = make_delegate_changed_log(200, &identity, &delegate_type, &delegate, u64::MAX, 100);

        let mut resolver = DIDEthr::new();
        resolver.add_network(
            "mainnet",
            NetworkConfig {
                chain_id: 1,
                registry: TEST_REGISTRY,
                provider: MockProvider {
                    changed_block: 200,
                    identity_owner: Some(new_owner),
                    logs: HashMap::from([
                        (100, vec![log_owner]),
                        (200, vec![log_delegate]),
                    ]),
                    block_timestamps: HashMap::new(),
                    identity_owner_at_block: HashMap::new(),
                },
            },
        );

        let doc = resolver
            .resolve(did!("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a"))
            .await
            .unwrap()
            .document;

        let doc_value = serde_json::to_value(&doc).unwrap();
        let vms = doc_value["verificationMethod"].as_array().unwrap();

        // 2 base (with new owner) + 2 delegate = 4
        assert_eq!(vms.len(), 4);

        // #controller uses the new owner's address
        let controller_vm = vms.iter().find(|vm| {
            vm["id"].as_str().unwrap().ends_with("#controller")
        }).unwrap();
        let owner_addr = format_address_eip55(&new_owner);
        assert_eq!(
            controller_vm["blockchainAccountId"],
            format!("eip155:1:{owner_addr}")
        );

        // #delegate-1 uses the delegate's address
        let delegate_vm = vms.iter().find(|vm| {
            vm["id"].as_str().unwrap().ends_with("#delegate-1")
        }).unwrap();
        let delegate_addr = format_address_eip55(&delegate);
        assert_eq!(
            delegate_vm["blockchainAccountId"],
            format!("eip155:1:{delegate_addr}")
        );
    }

    #[tokio::test]
    async fn resolve_with_mock_provider_multiple_owner_changes() {
        // Simulate multiple ownership transfers: identityOwner() returns the
        // final owner. The document should use that address regardless of
        // how many transfers occurred.
        let final_owner: [u8; 20] = [
            0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD,
            0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01,
        ];
        let mut resolver = DIDEthr::new();
        resolver.add_network(
            "mainnet",
            NetworkConfig {
                chain_id: 1,
                registry: [0xdc, 0xa7, 0xef, 0x03, 0xe9, 0x8e, 0x0d, 0xc2,
                           0xb8, 0x55, 0xbe, 0x64, 0x7c, 0x39, 0xab, 0xe9,
                           0x84, 0xfc, 0xf2, 0x1b],
                provider: MockProvider {
                    changed_block: 5, // multiple blocks of changes
                    identity_owner: Some(final_owner),
                    logs: HashMap::new(),
                    block_timestamps: HashMap::new(),
                    identity_owner_at_block: HashMap::new(),
                },
            },
        );

        let doc = resolver
            .resolve(did!(
                "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a"
            ))
            .await
            .unwrap()
            .document;

        let doc_value = serde_json::to_value(&doc).unwrap();
        let vms = doc_value["verificationMethod"].as_array().unwrap();

        // Compute expected checksummed address
        let expected_addr = format_address_eip55(&final_owner);
        let expected_account_id = format!("eip155:1:{expected_addr}");

        let controller_vm = vms.iter().find(|vm| {
            vm["id"].as_str().unwrap().ends_with("#controller")
        }).expect("should have #controller VM");
        assert_eq!(
            controller_vm["blockchainAccountId"].as_str().unwrap(),
            expected_account_id,
        );

        let eip712_vm = vms.iter().find(|vm| {
            vm["id"].as_str().unwrap().ends_with("#Eip712Method2021")
        }).expect("should have #Eip712Method2021 VM");
        assert_eq!(
            eip712_vm["blockchainAccountId"].as_str().unwrap(),
            expected_account_id,
        );
    }

    #[tokio::test]
    async fn resolve_deactivated_null_owner_bare_doc() {
        // When identityOwner() returns the null address (0x000...0),
        // the DID is deactivated: bare doc with only `id`, empty VMs,
        // and document_metadata.deactivated = true.
        let identity: [u8; 20] = [0xb9, 0xc5, 0x71, 0x40, 0x89, 0x47, 0x8a, 0x32, 0x7f, 0x09,
                                   0x19, 0x79, 0x87, 0xf1, 0x6f, 0x9e, 0x5d, 0x93, 0x6e, 0x8a];
        let null_owner: [u8; 20] = [0u8; 20];

        let log = make_owner_changed_log(100, &identity, &null_owner, 0);

        let mut resolver = DIDEthr::new();
        resolver.add_network("mainnet", NetworkConfig {
            chain_id: 1,
            registry: TEST_REGISTRY,
            provider: MockProvider {
                changed_block: 100,
                identity_owner: Some(null_owner),
                logs: HashMap::from([(100, vec![log])]),
                block_timestamps: HashMap::from([(100, 1705312200)]),
                identity_owner_at_block: HashMap::new(),
            },
        });

        let output = resolver
            .resolve(did!("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a"))
            .await
            .unwrap();

        // Document metadata must have deactivated = true
        assert_eq!(output.document_metadata.deactivated, Some(true));
        // Deactivation is an on-chain change, so versionId/updated must be set
        assert_eq!(output.document_metadata.version_id.as_deref(), Some("100"));
        assert_eq!(output.document_metadata.updated.as_deref(), Some("2024-01-15T09:50:00Z"));

        let doc_value = serde_json::to_value(&output.document).unwrap();

        // ID preserved
        assert_eq!(doc_value["id"], "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a");

        // Empty verificationMethod, authentication, assertionMethod
        let vms = doc_value.get("verificationMethod");
        assert!(vms.is_none() || vms.unwrap().as_array().map_or(true, |a| a.is_empty()));
        let auth = doc_value.get("authentication");
        assert!(auth.is_none() || auth.unwrap().as_array().map_or(true, |a| a.is_empty()));
        let assertion = doc_value.get("assertionMethod");
        assert!(assertion.is_none() || assertion.unwrap().as_array().map_or(true, |a| a.is_empty()));
    }

    #[tokio::test]
    async fn resolve_deactivated_ignores_events() {
        // Even with delegate/attribute events, deactivation discards them all.
        let identity: [u8; 20] = [0xb9, 0xc5, 0x71, 0x40, 0x89, 0x47, 0x8a, 0x32, 0x7f, 0x09,
                                   0x19, 0x79, 0x87, 0xf1, 0x6f, 0x9e, 0x5d, 0x93, 0x6e, 0x8a];
        let null_owner: [u8; 20] = [0u8; 20];
        let delegate: [u8; 20] = [0xAA; 20];
        let delegate_type = encode_delegate_type("veriKey");
        let attr_name = encode_attr_name("did/svc/HubService");

        let log_owner = make_owner_changed_log(100, &identity, &null_owner, 0);
        let log_delegate = make_delegate_changed_log(200, &identity, &delegate_type, &delegate, u64::MAX, 100);
        let log_attr = make_attribute_changed_log(300, &identity, &attr_name, b"https://hub.example.com", u64::MAX, 200);

        let mut resolver = DIDEthr::new();
        resolver.add_network("mainnet", NetworkConfig {
            chain_id: 1,
            registry: TEST_REGISTRY,
            provider: MockProvider {
                changed_block: 300,
                identity_owner: Some(null_owner),
                logs: HashMap::from([
                    (100, vec![log_owner]),
                    (200, vec![log_delegate]),
                    (300, vec![log_attr]),
                ]),
                block_timestamps: HashMap::new(),
                identity_owner_at_block: HashMap::new(),
            },
        });

        let output = resolver
            .resolve(did!("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a"))
            .await
            .unwrap();

        assert_eq!(output.document_metadata.deactivated, Some(true));

        let doc_value = serde_json::to_value(&output.document).unwrap();

        // No VMs, no services — all events discarded
        let vms = doc_value.get("verificationMethod");
        assert!(vms.is_none() || vms.unwrap().as_array().map_or(true, |a| a.is_empty()));
        let services = doc_value.get("service");
        assert!(services.is_none() || services.unwrap().as_array().map_or(true, |a| a.is_empty()));
    }

    #[tokio::test]
    async fn resolve_non_null_owner_not_deactivated() {
        // When the owner is non-null, deactivated should be None (not set).
        let mut resolver = DIDEthr::new();
        resolver.add_network("mainnet", NetworkConfig {
            chain_id: 1,
            registry: TEST_REGISTRY,
            provider: MockProvider::new_same_owner(),
        });

        let output = resolver
            .resolve(did!("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a"))
            .await
            .unwrap();

        // deactivated should be None (default)
        assert!(output.document_metadata.deactivated.is_none()
            || output.document_metadata.deactivated == Some(false));
    }

    #[tokio::test]
    async fn metadata_no_changes_no_version_id_or_updated() {
        // DID with no on-chain changes (changed=0) → no versionId/updated metadata
        let mut resolver = DIDEthr::new();
        resolver.add_network("mainnet", NetworkConfig {
            chain_id: 1,
            registry: TEST_REGISTRY,
            provider: MockProvider::new_unchanged(),
        });

        let output = resolver
            .resolve(did!("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a"))
            .await
            .unwrap();

        assert!(output.document_metadata.version_id.is_none());
        assert!(output.document_metadata.updated.is_none());
    }

    #[tokio::test]
    async fn metadata_with_changes_has_version_id_and_updated() {
        // DID with on-chain changes (changed_block=100) → versionId = "100",
        // updated = ISO 8601 timestamp of block 100
        let identity: [u8; 20] = [0xb9, 0xc5, 0x71, 0x40, 0x89, 0x47, 0x8a, 0x32, 0x7f, 0x09,
                                   0x19, 0x79, 0x87, 0xf1, 0x6f, 0x9e, 0x5d, 0x93, 0x6e, 0x8a];
        let delegate: [u8; 20] = [0xAA; 20];
        let delegate_type = encode_delegate_type("veriKey");
        let log = make_delegate_changed_log(100, &identity, &delegate_type, &delegate, u64::MAX, 0);

        // Block 100 has timestamp 1705312200 = 2024-01-15T09:50:00Z
        let mut resolver = DIDEthr::new();
        resolver.add_network("mainnet", NetworkConfig {
            chain_id: 1,
            registry: TEST_REGISTRY,
            provider: MockProvider {
                changed_block: 100,
                identity_owner: None,
                logs: HashMap::from([(100, vec![log])]),
                block_timestamps: HashMap::from([(100, 1705312200)]),
                identity_owner_at_block: HashMap::new(),
            },
        });

        let output = resolver
            .resolve(did!("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a"))
            .await
            .unwrap();

        assert_eq!(output.document_metadata.version_id.as_deref(), Some("100"));
        assert_eq!(output.document_metadata.updated.as_deref(), Some("2024-01-15T09:50:00Z"));
    }

    // --- Phase 8: Historical Resolution (?versionId=N) tests ---

    #[tokio::test]
    async fn historical_version_id_skips_events_after_target_block() {
        // Events at blocks 100 and 200. Resolving with versionId=100
        // should only include events from block 100.
        let identity: [u8; 20] = [0xb9, 0xc5, 0x71, 0x40, 0x89, 0x47, 0x8a, 0x32, 0x7f, 0x09,
                                   0x19, 0x79, 0x87, 0xf1, 0x6f, 0x9e, 0x5d, 0x93, 0x6e, 0x8a];
        let delegate_a: [u8; 20] = [0xAA; 20];
        let delegate_b: [u8; 20] = [0xBB; 20];
        let delegate_type = encode_delegate_type("veriKey");

        let log_100 = make_delegate_changed_log(100, &identity, &delegate_type, &delegate_a, u64::MAX, 0);
        let log_200 = make_delegate_changed_log(200, &identity, &delegate_type, &delegate_b, u64::MAX, 100);

        let mut resolver = DIDEthr::new();
        resolver.add_network("mainnet", NetworkConfig {
            chain_id: 1,
            registry: TEST_REGISTRY,
            provider: MockProvider {
                changed_block: 200,
                identity_owner: None,
                identity_owner_at_block: HashMap::new(),
                logs: HashMap::from([
                    (100, vec![log_100]),
                    (200, vec![log_200]),
                ]),
                block_timestamps: HashMap::from([
                    (100, 1705312200), // 2024-01-15T09:50:00Z
                    (200, 1705398600), // 2024-01-16T09:50:00Z
                ]),
            },
        });

        let options = resolution::Options {
            parameters: resolution::Parameters {
                version_id: Some("100".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };

        let output = resolver
            .resolve_with(
                did!("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a"),
                options,
            )
            .await
            .unwrap();

        let doc_value = serde_json::to_value(&output.document).unwrap();
        let vms = doc_value["verificationMethod"].as_array().unwrap();

        // Should have 4 VMs: 2 base + 2 delegate (only delegate_a from block 100)
        assert_eq!(vms.len(), 4, "only events at/before block 100 should be applied");

        // delegate_a (#delegate-1) present
        let d1 = vms.iter().find(|vm| vm["id"].as_str().unwrap().ends_with("#delegate-1"));
        assert!(d1.is_some(), "delegate from block 100 should be present");

        // delegate_b (#delegate-2) NOT present
        let d2 = vms.iter().find(|vm| vm["id"].as_str().unwrap().ends_with("#delegate-2"));
        assert!(d2.is_none(), "delegate from block 200 should NOT be present");

        // Metadata: versionId should be "100" (latest event at or before target)
        assert_eq!(output.document_metadata.version_id.as_deref(), Some("100"));
        assert_eq!(output.document_metadata.updated.as_deref(), Some("2024-01-15T09:50:00Z"));
    }

    #[tokio::test]
    async fn historical_valid_to_uses_target_block_timestamp() {
        // Delegate valid_to = 1705315800 (block 100 timestamp + 1 hour).
        // Block 100 timestamp = 1705312200. At block 100 the delegate is still valid.
        // At wall-clock time (far future) it would be expired.
        // ?versionId=100 should include the delegate.
        let identity: [u8; 20] = [0xb9, 0xc5, 0x71, 0x40, 0x89, 0x47, 0x8a, 0x32, 0x7f, 0x09,
                                   0x19, 0x79, 0x87, 0xf1, 0x6f, 0x9e, 0x5d, 0x93, 0x6e, 0x8a];
        let delegate_a: [u8; 20] = [0xAA; 20];
        let delegate_type = encode_delegate_type("veriKey");
        let valid_to = 1705315800u64; // 1 hour after block 100 timestamp

        let log_100 = make_delegate_changed_log(100, &identity, &delegate_type, &delegate_a, valid_to, 0);

        let mut resolver = DIDEthr::new();
        resolver.add_network("mainnet", NetworkConfig {
            chain_id: 1,
            registry: TEST_REGISTRY,
            provider: MockProvider {
                changed_block: 100,
                identity_owner: None,
                identity_owner_at_block: HashMap::new(),
                logs: HashMap::from([
                    (100, vec![log_100]),
                ]),
                block_timestamps: HashMap::from([
                    (100, 1705312200), // 2024-01-15T09:50:00Z
                ]),
            },
        });

        let options = resolution::Options {
            parameters: resolution::Parameters {
                version_id: Some("100".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };

        let output = resolver
            .resolve_with(
                did!("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a"),
                options,
            )
            .await
            .unwrap();

        let doc_value = serde_json::to_value(&output.document).unwrap();
        let vms = doc_value["verificationMethod"].as_array().unwrap();

        // 2 base + 2 delegate VMs (delegate is valid at block 100's timestamp)
        assert_eq!(vms.len(), 4, "delegate valid at block timestamp should be included");

        let d1 = vms.iter().find(|vm| vm["id"].as_str().unwrap().ends_with("#delegate-1"));
        assert!(d1.is_some(), "delegate still valid at block 100 timestamp should be present");
    }

    #[tokio::test]
    async fn historical_next_version_id_and_next_update() {
        // Events at blocks 100 and 200. Resolving at versionId=100 should set
        // nextVersionId=200 and nextUpdate to block 200's timestamp.
        let identity: [u8; 20] = [0xb9, 0xc5, 0x71, 0x40, 0x89, 0x47, 0x8a, 0x32, 0x7f, 0x09,
                                   0x19, 0x79, 0x87, 0xf1, 0x6f, 0x9e, 0x5d, 0x93, 0x6e, 0x8a];
        let delegate_a: [u8; 20] = [0xAA; 20];
        let delegate_b: [u8; 20] = [0xBB; 20];
        let delegate_type = encode_delegate_type("veriKey");

        let log_100 = make_delegate_changed_log(100, &identity, &delegate_type, &delegate_a, u64::MAX, 0);
        let log_200 = make_delegate_changed_log(200, &identity, &delegate_type, &delegate_b, u64::MAX, 100);

        let mut resolver = DIDEthr::new();
        resolver.add_network("mainnet", NetworkConfig {
            chain_id: 1,
            registry: TEST_REGISTRY,
            provider: MockProvider {
                changed_block: 200,
                identity_owner: None,
                identity_owner_at_block: HashMap::new(),
                logs: HashMap::from([
                    (100, vec![log_100]),
                    (200, vec![log_200]),
                ]),
                block_timestamps: HashMap::from([
                    (100, 1705312200), // 2024-01-15T09:50:00Z
                    (200, 1705398600), // 2024-01-16T09:50:00Z
                ]),
            },
        });

        let options = resolution::Options {
            parameters: resolution::Parameters {
                version_id: Some("100".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };

        let output = resolver
            .resolve_with(
                did!("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a"),
                options,
            )
            .await
            .unwrap();

        assert_eq!(output.document_metadata.version_id.as_deref(), Some("100"));
        assert_eq!(output.document_metadata.updated.as_deref(), Some("2024-01-15T09:50:00Z"));
        assert_eq!(output.document_metadata.next_version_id.as_deref(), Some("200"));
        assert_eq!(output.document_metadata.next_update.as_deref(), Some("2024-01-16T09:50:00Z"));
    }

    #[tokio::test]
    async fn historical_before_any_changes_returns_genesis() {
        // Events only at block 100. Resolving at versionId=50 (before any changes)
        // should return the default genesis document (no delegates/attributes).
        let identity: [u8; 20] = [0xb9, 0xc5, 0x71, 0x40, 0x89, 0x47, 0x8a, 0x32, 0x7f, 0x09,
                                   0x19, 0x79, 0x87, 0xf1, 0x6f, 0x9e, 0x5d, 0x93, 0x6e, 0x8a];
        let delegate_a: [u8; 20] = [0xAA; 20];
        let delegate_type = encode_delegate_type("veriKey");

        let log_100 = make_delegate_changed_log(100, &identity, &delegate_type, &delegate_a, u64::MAX, 0);

        let mut resolver = DIDEthr::new();
        resolver.add_network("mainnet", NetworkConfig {
            chain_id: 1,
            registry: TEST_REGISTRY,
            provider: MockProvider {
                changed_block: 100,
                identity_owner: None,
                identity_owner_at_block: HashMap::new(),
                logs: HashMap::from([
                    (100, vec![log_100]),
                ]),
                block_timestamps: HashMap::from([
                    (100, 1705312200),
                ]),
            },
        });

        let options = resolution::Options {
            parameters: resolution::Parameters {
                version_id: Some("50".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };

        let output = resolver
            .resolve_with(
                did!("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a"),
                options,
            )
            .await
            .unwrap();

        let doc_value = serde_json::to_value(&output.document).unwrap();
        let vms = doc_value["verificationMethod"].as_array().unwrap();

        // Genesis document: only 2 base VMs, no delegates
        assert_eq!(vms.len(), 2, "genesis doc should have only base VMs");

        // No metadata versionId/updated (offline genesis)
        assert!(output.document_metadata.version_id.is_none());
        assert!(output.document_metadata.updated.is_none());
    }

    #[tokio::test]
    async fn pubkey_did_with_provider_unchanged_includes_eip712method2021() {
        // Public-key DID with MockProvider (changed_block=0) should also
        // include Eip712Method2021, matching offline resolution.
        let mut resolver = DIDEthr::new();
        resolver.add_network(
            "mainnet",
            NetworkConfig {
                chain_id: 1,
                registry: TEST_REGISTRY,
                provider: MockProvider::new_unchanged(),
            },
        );

        let doc = resolver
            .resolve(did!(
                "did:ethr:0x03fdd57adec3d438ea237fe46b33ee1e016eda6b585c3e27ea66686c2ea5358479"
            ))
            .await
            .unwrap()
            .document;

        let doc_value = serde_json::to_value(&doc).unwrap();
        let vms = doc_value["verificationMethod"].as_array().unwrap();

        assert_eq!(vms.len(), 3, "public-key DID with unchanged provider should have 3 VMs");

        assert!(
            vms.iter().any(|vm| vm["type"].as_str() == Some("Eip712Method2021")),
            "should include Eip712Method2021"
        );

        // Should match offline resolution exactly
        let doc_offline = DIDEthr::<()>::default()
            .resolve(did!(
                "did:ethr:0x03fdd57adec3d438ea237fe46b33ee1e016eda6b585c3e27ea66686c2ea5358479"
            ))
            .await
            .unwrap()
            .document;

        assert_eq!(
            serde_json::to_value(&doc).unwrap(),
            serde_json::to_value(&doc_offline).unwrap(),
            "unchanged provider should match offline for public-key DID"
        );
    }

    // ── Revocation tests ──

    #[tokio::test]
    async fn resolve_previously_valid_delegate_then_revoked() {
        // A delegate is added valid at block 100, then revoked at block 200.
        // The revoked delegate must NOT appear in the final document.
        let identity: [u8; 20] = [0xb9, 0xc5, 0x71, 0x40, 0x89, 0x47, 0x8a, 0x32, 0x7f, 0x09,
                                   0x19, 0x79, 0x87, 0xf1, 0x6f, 0x9e, 0x5d, 0x93, 0x6e, 0x8a];
        let delegate: [u8; 20] = [0xAA; 20];
        let delegate_type = encode_delegate_type("veriKey");

        // Block 100: delegate added, valid_to = far future
        let log_add = make_delegate_changed_log(100, &identity, &delegate_type, &delegate, u64::MAX, 0);
        // Block 200: same delegate revoked (valid_to = 0)
        let log_revoke = make_delegate_changed_log(200, &identity, &delegate_type, &delegate, 0, 100);

        let mut resolver = DIDEthr::new();
        resolver.add_network("mainnet", NetworkConfig {
            chain_id: 1,
            registry: TEST_REGISTRY,
            provider: MockProvider {
                changed_block: 200,
                identity_owner: None,
                logs: HashMap::from([
                    (100, vec![log_add]),
                    (200, vec![log_revoke]),
                ]),
                block_timestamps: HashMap::new(),
                identity_owner_at_block: HashMap::new(),
            },
        });

        let doc = resolver
            .resolve(did!("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a"))
            .await.unwrap().document;

        let doc_value = serde_json::to_value(&doc).unwrap();
        let vms = doc_value["verificationMethod"].as_array().unwrap();

        // Only 2 base VMs — delegate was revoked
        assert_eq!(vms.len(), 2, "revoked delegate should not appear in document");
        assert!(vms.iter().all(|vm| !vm["id"].as_str().unwrap().contains("delegate")),
            "no delegate VMs should be present");
    }

    #[tokio::test]
    async fn resolve_previously_valid_service_then_revoked() {
        // A service is added valid at block 100, then revoked at block 200.
        let identity: [u8; 20] = [0xb9, 0xc5, 0x71, 0x40, 0x89, 0x47, 0x8a, 0x32, 0x7f, 0x09,
                                   0x19, 0x79, 0x87, 0xf1, 0x6f, 0x9e, 0x5d, 0x93, 0x6e, 0x8a];
        let attr_name = encode_attr_name("did/svc/HubService");
        let endpoint = b"https://hub.example.com";

        // Block 100: service added
        let log_add = make_attribute_changed_log(100, &identity, &attr_name, endpoint, u64::MAX, 0);
        // Block 200: same service revoked (valid_to = 0)
        let log_revoke = make_attribute_changed_log(200, &identity, &attr_name, endpoint, 0, 100);

        let mut resolver = DIDEthr::new();
        resolver.add_network("mainnet", NetworkConfig {
            chain_id: 1,
            registry: TEST_REGISTRY,
            provider: MockProvider {
                changed_block: 200,
                identity_owner: None,
                logs: HashMap::from([
                    (100, vec![log_add]),
                    (200, vec![log_revoke]),
                ]),
                block_timestamps: HashMap::new(),
                identity_owner_at_block: HashMap::new(),
            },
        });

        let doc = resolver
            .resolve(did!("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a"))
            .await.unwrap().document;

        let doc_value = serde_json::to_value(&doc).unwrap();
        let services = doc_value.get("service");

        // No services — the service was revoked
        assert!(
            services.is_none() || services.unwrap().as_array().map_or(true, |a| a.is_empty()),
            "revoked service should not appear in document"
        );
    }

    #[tokio::test]
    async fn resolve_revoked_then_readded_gets_new_id() {
        // A delegate is added, revoked, then re-added. The re-added delegate
        // should get a higher counter ID (#delegate-3, not #delegate-1).
        let identity: [u8; 20] = [0xb9, 0xc5, 0x71, 0x40, 0x89, 0x47, 0x8a, 0x32, 0x7f, 0x09,
                                   0x19, 0x79, 0x87, 0xf1, 0x6f, 0x9e, 0x5d, 0x93, 0x6e, 0x8a];
        let delegate: [u8; 20] = [0xAA; 20];
        let delegate_type = encode_delegate_type("veriKey");

        // Block 100: add (counter=1)
        let log1 = make_delegate_changed_log(100, &identity, &delegate_type, &delegate, u64::MAX, 0);
        // Block 200: revoke (counter=2)
        let log2 = make_delegate_changed_log(200, &identity, &delegate_type, &delegate, 0, 100);
        // Block 300: re-add (counter=3)
        let log3 = make_delegate_changed_log(300, &identity, &delegate_type, &delegate, u64::MAX, 200);

        let mut resolver = DIDEthr::new();
        resolver.add_network("mainnet", NetworkConfig {
            chain_id: 1,
            registry: TEST_REGISTRY,
            provider: MockProvider {
                changed_block: 300,
                identity_owner: None,
                logs: HashMap::from([
                    (100, vec![log1]),
                    (200, vec![log2]),
                    (300, vec![log3]),
                ]),
                block_timestamps: HashMap::new(),
                identity_owner_at_block: HashMap::new(),
            },
        });

        let doc = resolver
            .resolve(did!("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a"))
            .await.unwrap().document;

        let doc_value = serde_json::to_value(&doc).unwrap();
        let vms = doc_value["verificationMethod"].as_array().unwrap();

        // 2 base + 2 delegate (RecoveryMethod + Eip712) = 4
        assert_eq!(vms.len(), 4);

        // Should NOT have #delegate-1 or #delegate-2
        assert!(vms.iter().all(|vm| !vm["id"].as_str().unwrap().ends_with("#delegate-1")));
        assert!(vms.iter().all(|vm| !vm["id"].as_str().unwrap().ends_with("#delegate-2")));

        // Should have #delegate-3 (the re-added entry)
        let d3 = vms.iter().find(|vm| vm["id"].as_str().unwrap().ends_with("#delegate-3"))
            .expect("should have #delegate-3 VM");
        assert_eq!(d3["type"], "EcdsaSecp256k1RecoveryMethod2020");
    }

    #[tokio::test]
    async fn resolve_secp256k1_verikey_hex_attribute() {
        // did/pub/Secp256k1/veriKey/hex attribute adds EcdsaSecp256k1VerificationKey2019
        // with publicKeyJwk to verificationMethod + assertionMethod, using #delegate-N ID.
        // Encoding hint ("hex") is ignored; we always convert to JWK.
        let identity: [u8; 20] = [0xb9, 0xc5, 0x71, 0x40, 0x89, 0x47, 0x8a, 0x32, 0x7f, 0x09,
                                   0x19, 0x79, 0x87, 0xf1, 0x6f, 0x9e, 0x5d, 0x93, 0x6e, 0x8a];
        let attr_name = encode_attr_name("did/pub/Secp256k1/veriKey/hex");

        let log = make_attribute_changed_log(100, &identity, &attr_name, &TEST_SECP256K1_COMPRESSED, u64::MAX, 0);

        let mut resolver = DIDEthr::new();
        resolver.add_network("mainnet", NetworkConfig {
            chain_id: 1,
            registry: TEST_REGISTRY,
            provider: MockProvider {
                changed_block: 100,
                identity_owner: None,
                logs: HashMap::from([(100, vec![log])]),
                block_timestamps: HashMap::new(),
                identity_owner_at_block: HashMap::new(),
            },
        });

        let doc = resolver
            .resolve(did!("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a"))
            .await.unwrap().document;

        let doc_value = serde_json::to_value(&doc).unwrap();
        eprintln!("{}", serde_json::to_string_pretty(&doc_value).unwrap());
        let vms = doc_value["verificationMethod"].as_array().unwrap();

        // 2 base + 1 attribute key = 3
        assert_eq!(vms.len(), 3);

        let attr_vm = vms.iter().find(|vm| {
            vm["id"].as_str().unwrap().ends_with("#delegate-1")
        }).expect("should have #delegate-1 VM from attribute");
        assert_eq!(attr_vm["type"], "EcdsaSecp256k1VerificationKey2019");
        // Must have publicKeyJwk (a JSON object), NOT publicKeyHex
        assert!(attr_vm["publicKeyJwk"].is_object(), "should have publicKeyJwk as object");
        assert_eq!(attr_vm["publicKeyJwk"]["kty"], "EC");
        assert_eq!(attr_vm["publicKeyJwk"]["crv"], "secp256k1");
        assert!(attr_vm.get("publicKeyHex").is_none(), "should NOT have publicKeyHex");
        assert_eq!(attr_vm["controller"], "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a");

        // Should be in assertionMethod but NOT authentication
        let did_prefix = "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a";
        let assertion = doc_value["assertionMethod"].as_array().unwrap();
        let auth = doc_value["authentication"].as_array().unwrap();
        assert!(assertion.iter().any(|v| v == &format!("{did_prefix}#delegate-1")));
        assert!(!auth.iter().any(|v| v == &format!("{did_prefix}#delegate-1")));

        // Context should include publicKeyJwk binding
        let context = doc_value["@context"].as_array().unwrap();
        let ctx_obj = context.iter().find(|c| c.is_object()).unwrap();
        assert!(ctx_obj.get("publicKeyJwk").is_some(), "context should include publicKeyJwk");
    }

    #[tokio::test]
    async fn resolve_secp256k1_attr_key_uses_jwk() {
        // Secp256k1 attribute key (any encoding hint) must produce
        // EcdsaSecp256k1VerificationKey2019 with publicKeyJwk (a JSON object).
        let identity: [u8; 20] = [0xb9, 0xc5, 0x71, 0x40, 0x89, 0x47, 0x8a, 0x32, 0x7f, 0x09,
                                   0x19, 0x79, 0x87, 0xf1, 0x6f, 0x9e, 0x5d, 0x93, 0x6e, 0x8a];
        let attr_name = encode_attr_name("did/pub/Secp256k1/veriKey/base64");

        let log = make_attribute_changed_log(100, &identity, &attr_name, &TEST_SECP256K1_COMPRESSED, u64::MAX, 0);

        let mut resolver = DIDEthr::new();
        resolver.add_network("mainnet", NetworkConfig {
            chain_id: 1,
            registry: TEST_REGISTRY,
            provider: MockProvider {
                changed_block: 100,
                identity_owner: None,
                logs: HashMap::from([(100, vec![log])]),
                block_timestamps: HashMap::new(),
                identity_owner_at_block: HashMap::new(),
            },
        });

        let doc = resolver
            .resolve(did!("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a"))
            .await.unwrap().document;

        let doc_value = serde_json::to_value(&doc).unwrap();
        let vms = doc_value["verificationMethod"].as_array().unwrap();

        let attr_vm = vms.iter().find(|vm| {
            vm["id"].as_str().unwrap().ends_with("#delegate-1")
        }).expect("should have #delegate-1 VM");
        assert_eq!(attr_vm["type"], "EcdsaSecp256k1VerificationKey2019");
        assert!(attr_vm["publicKeyJwk"].is_object(), "should use publicKeyJwk");
        assert_eq!(attr_vm["publicKeyJwk"]["kty"], "EC");
        assert_eq!(attr_vm["publicKeyJwk"]["crv"], "secp256k1");
    }

    #[tokio::test]
    async fn resolve_ed25519_attr_key() {
        // Ed25519 attribute key → Ed25519VerificationKey2020 + publicKeyMultibase
        let identity: [u8; 20] = [0xb9, 0xc5, 0x71, 0x40, 0x89, 0x47, 0x8a, 0x32, 0x7f, 0x09,
                                   0x19, 0x79, 0x87, 0xf1, 0x6f, 0x9e, 0x5d, 0x93, 0x6e, 0x8a];
        let attr_name = encode_attr_name("did/pub/Ed25519/veriKey/base64");
        // 32-byte Ed25519 public key
        let ed_key: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        ];

        let log = make_attribute_changed_log(100, &identity, &attr_name, &ed_key, u64::MAX, 0);

        let mut resolver = DIDEthr::new();
        resolver.add_network("mainnet", NetworkConfig {
            chain_id: 1,
            registry: TEST_REGISTRY,
            provider: MockProvider {
                changed_block: 100,
                identity_owner: None,
                logs: HashMap::from([(100, vec![log])]),
                block_timestamps: HashMap::new(),
                identity_owner_at_block: HashMap::new(),
            },
        });

        let doc = resolver
            .resolve(did!("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a"))
            .await.unwrap().document;

        let doc_value = serde_json::to_value(&doc).unwrap();
        eprintln!("{}", serde_json::to_string_pretty(&doc_value).unwrap());
        let vms = doc_value["verificationMethod"].as_array().unwrap();

        // 2 base + 1 Ed25519 = 3
        assert_eq!(vms.len(), 3);

        let attr_vm = vms.iter().find(|vm| {
            vm["id"].as_str().unwrap().ends_with("#delegate-1")
        }).expect("should have #delegate-1 VM");
        assert_eq!(attr_vm["type"], "Ed25519VerificationKey2020");
        let expected_multibase = encode_multibase_multicodec(ssi_multicodec::ED25519_PUB, &ed_key);
        assert_eq!(attr_vm["publicKeyMultibase"], expected_multibase);
        assert!(attr_vm.get("publicKeyJwk").is_none(), "should NOT have publicKeyJwk");

        // Should be in assertionMethod (veriKey purpose)
        let did_prefix = "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a";
        let assertion = doc_value["assertionMethod"].as_array().unwrap();
        assert!(assertion.iter().any(|v| v == &format!("{did_prefix}#delegate-1")));

        // Context should include Ed25519VerificationKey2020 and publicKeyMultibase
        let context = doc_value["@context"].as_array().unwrap();
        let ctx_obj = context.iter().find(|c| c.is_object()).unwrap();
        assert!(ctx_obj.get("Ed25519VerificationKey2020").is_some(),
            "context should include Ed25519VerificationKey2020");
        assert!(ctx_obj.get("publicKeyMultibase").is_some(),
            "context should include publicKeyMultibase");
    }

    #[tokio::test]
    async fn resolve_x25519_attr_key() {
        // X25519 attribute key → X25519KeyAgreementKey2020 + publicKeyMultibase + keyAgreement
        let identity: [u8; 20] = [0xb9, 0xc5, 0x71, 0x40, 0x89, 0x47, 0x8a, 0x32, 0x7f, 0x09,
                                   0x19, 0x79, 0x87, 0xf1, 0x6f, 0x9e, 0x5d, 0x93, 0x6e, 0x8a];
        let attr_name = encode_attr_name("did/pub/X25519/enc/base64");
        // 32-byte X25519 public key
        let x_key: [u8; 32] = [
            0xAA, 0xBB, 0xCC, 0xDD, 0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
            0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
            0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
        ];

        let log = make_attribute_changed_log(100, &identity, &attr_name, &x_key, u64::MAX, 0);

        let mut resolver = DIDEthr::new();
        resolver.add_network("mainnet", NetworkConfig {
            chain_id: 1,
            registry: TEST_REGISTRY,
            provider: MockProvider {
                changed_block: 100,
                identity_owner: None,
                logs: HashMap::from([(100, vec![log])]),
                block_timestamps: HashMap::new(),
                identity_owner_at_block: HashMap::new(),
            },
        });

        let doc = resolver
            .resolve(did!("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a"))
            .await.unwrap().document;

        let doc_value = serde_json::to_value(&doc).unwrap();
        eprintln!("{}", serde_json::to_string_pretty(&doc_value).unwrap());
        let vms = doc_value["verificationMethod"].as_array().unwrap();

        // 2 base + 1 X25519 = 3
        assert_eq!(vms.len(), 3);

        let attr_vm = vms.iter().find(|vm| {
            vm["id"].as_str().unwrap().ends_with("#delegate-1")
        }).expect("should have #delegate-1 VM");
        assert_eq!(attr_vm["type"], "X25519KeyAgreementKey2020");
        let expected_multibase = encode_multibase_multicodec(ssi_multicodec::X25519_PUB, &x_key);
        assert_eq!(attr_vm["publicKeyMultibase"], expected_multibase);

        // X25519 enc purpose → keyAgreement (not assertionMethod or authentication)
        let did_prefix = "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a";
        let key_agreement = doc_value["keyAgreement"].as_array()
            .expect("should have keyAgreement array");
        assert!(key_agreement.iter().any(|v| v == &format!("{did_prefix}#delegate-1")),
            "X25519 should be in keyAgreement");

        let assertion = doc_value["assertionMethod"].as_array().unwrap();
        assert!(!assertion.iter().any(|v| v == &format!("{did_prefix}#delegate-1")),
            "X25519 should NOT be in assertionMethod");

        // Context
        let context = doc_value["@context"].as_array().unwrap();
        let ctx_obj = context.iter().find(|c| c.is_object()).unwrap();
        assert!(ctx_obj.get("X25519KeyAgreementKey2020").is_some(),
            "context should include X25519KeyAgreementKey2020");
        assert!(ctx_obj.get("publicKeyMultibase").is_some(),
            "context should include publicKeyMultibase");
    }

    #[tokio::test]
    async fn resolve_secp256k1_enc_attribute_goes_to_key_agreement() {
        // did/pub/Secp256k1/enc/hex must route to keyAgreement, NOT
        // authentication/assertionMethod. This was previously broken because
        // `enc` purpose was folded into `is_sig_auth`.
        let identity: [u8; 20] = [0xb9, 0xc5, 0x71, 0x40, 0x89, 0x47, 0x8a, 0x32, 0x7f, 0x09,
                                   0x19, 0x79, 0x87, 0xf1, 0x6f, 0x9e, 0x5d, 0x93, 0x6e, 0x8a];
        let attr_name = encode_attr_name("did/pub/Secp256k1/enc/hex");

        let log = make_attribute_changed_log(100, &identity, &attr_name, &TEST_SECP256K1_COMPRESSED, u64::MAX, 0);

        let mut resolver = DIDEthr::new();
        resolver.add_network("mainnet", NetworkConfig {
            chain_id: 1,
            registry: TEST_REGISTRY,
            provider: MockProvider {
                changed_block: 100,
                identity_owner: None,
                logs: HashMap::from([(100, vec![log])]),
                block_timestamps: HashMap::new(),
                identity_owner_at_block: HashMap::new(),
            },
        });

        let doc = resolver
            .resolve(did!("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a"))
            .await.unwrap().document;

        let doc_value = serde_json::to_value(&doc).unwrap();
        let did_prefix = "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a";

        // Should be in keyAgreement
        let key_agreement = doc_value["keyAgreement"].as_array()
            .expect("should have keyAgreement array");
        assert!(key_agreement.iter().any(|v| v == &format!("{did_prefix}#delegate-1")),
            "Secp256k1/enc should be in keyAgreement");

        // Should NOT be in assertionMethod or authentication
        let assertion = doc_value["assertionMethod"].as_array().unwrap();
        assert!(!assertion.iter().any(|v| v == &format!("{did_prefix}#delegate-1")),
            "Secp256k1/enc should NOT be in assertionMethod");
        let auth = doc_value["authentication"].as_array().unwrap();
        assert!(!auth.iter().any(|v| v == &format!("{did_prefix}#delegate-1")),
            "Secp256k1/enc should NOT be in authentication");
    }

    #[tokio::test]
    async fn historical_expiry_uses_target_block_timestamp_not_meta_block() {
        // Bug regression: when target_block > meta_block, `now` must be the
        // target block's timestamp, not meta_block's. A delegate whose
        // valid_to falls between the two timestamps must be expired.
        //
        // Setup:
        //   Block 100 (timestamp 1000): delegate added, valid_to = 1500
        //   Block 150 (timestamp 2000): no events, but this is the target
        //
        // meta_block = 100 (latest event at or before 150)
        // Before fix: now = 1000 → 1500 >= 1000 → delegate included (WRONG)
        // After fix:  now = 2000 → 1500 < 2000  → delegate excluded (CORRECT)
        let identity: [u8; 20] = [0xb9, 0xc5, 0x71, 0x40, 0x89, 0x47, 0x8a, 0x32, 0x7f, 0x09,
                                   0x19, 0x79, 0x87, 0xf1, 0x6f, 0x9e, 0x5d, 0x93, 0x6e, 0x8a];
        let delegate: [u8; 20] = [0xAA; 20];
        let delegate_type = encode_delegate_type("veriKey");

        // Delegate valid_to = 1500, between block 100 ts (1000) and block 150 ts (2000)
        let log = make_delegate_changed_log(100, &identity, &delegate_type, &delegate, 1500, 0);

        let mut resolver = DIDEthr::new();
        resolver.add_network("mainnet", NetworkConfig {
            chain_id: 1,
            registry: TEST_REGISTRY,
            provider: MockProvider {
                changed_block: 100,
                identity_owner: None,
                identity_owner_at_block: HashMap::new(),
                logs: HashMap::from([
                    (100, vec![log]),
                ]),
                block_timestamps: HashMap::from([
                    (100, 1000),  // meta_block timestamp
                    (150, 2000),  // target block timestamp
                ]),
            },
        });

        let options = resolution::Options {
            parameters: resolution::Parameters {
                version_id: Some("150".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };

        let output = resolver
            .resolve_with(
                did!("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a"),
                options,
            )
            .await
            .unwrap();

        let doc_value = serde_json::to_value(&output.document).unwrap();
        let vms = doc_value["verificationMethod"].as_array().unwrap();

        // Delegate valid_to (1500) < target block timestamp (2000) → expired
        assert_eq!(vms.len(), 2, "delegate expired at target block should NOT be included");
        assert!(
            vms.iter().all(|vm| !vm["id"].as_str().unwrap().contains("delegate")),
            "no delegate VMs should be present — delegate expired before target block"
        );

        // Metadata should still use meta_block (100) for versionId/updated
        assert_eq!(output.document_metadata.version_id.as_deref(), Some("100"));
    }
}
