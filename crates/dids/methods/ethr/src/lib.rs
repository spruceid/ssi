use iref::Iri;
use ssi_caips::caip10::BlockchainAccountId;
use ssi_caips::caip2::ChainId;
use ssi_crypto::hashes::keccak;
use ssi_dids_core::{
    document::{
        self,
        representation::{self, MediaType},
        DIDVerificationMethod,
    },
    resolution::{self, DIDMethodResolver, Error, Output},
    DIDBuf, DIDMethod, DIDURLBuf, Document, DIDURL,
};
use static_iref::iri;
use std::collections::HashMap;
use std::str::FromStr;

use base64::Engine as _;

mod json_ld_context;
use json_ld_context::JsonLdContext;
use ssi_jwk::JWK;

// --- Ethereum provider types ---

/// Block reference for eth_call
pub enum BlockRef {
    Latest,
    Number(u64),
}

/// Log filter for eth_getLogs
///
/// `topic0` filters by event signature hash(es) — multiple values are OR'd.
/// `topic1` filters by the first indexed parameter (e.g. identity address).
pub struct LogFilter {
    pub address: [u8; 20],
    pub topic0: Vec<[u8; 32]>,
    pub topic1: Option<[u8; 32]>,
    pub from_block: u64,
    pub to_block: u64,
}

/// Ethereum event log
pub struct Log {
    pub address: [u8; 20],
    pub topics: Vec<[u8; 32]>,
    pub data: Vec<u8>,
    pub block_number: u64,
}

/// Minimal async trait for Ethereum JSON-RPC interaction.
/// Users implement this with their preferred client (ethers-rs, alloy, etc.)
pub trait EthProvider: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    /// eth_call — execute a read-only contract call
    fn call(
        &self,
        to: [u8; 20],
        data: Vec<u8>,
        block: BlockRef,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, Self::Error>> + Send;

    /// eth_getLogs — query event logs
    fn get_logs(
        &self,
        filter: LogFilter,
    ) -> impl std::future::Future<Output = Result<Vec<Log>, Self::Error>> + Send;

    /// Get block timestamp (seconds since epoch)
    fn block_timestamp(
        &self,
        block: u64,
    ) -> impl std::future::Future<Output = Result<u64, Self::Error>> + Send;
}

/// Per-network Ethereum configuration
pub struct NetworkConfig<P> {
    pub chain_id: u64,
    pub registry: [u8; 20],
    pub provider: P,
}

// --- ERC-1056 ABI selectors ---

/// `changed(address)` — selector 0xf96d0f9f
const CHANGED_SELECTOR: [u8; 4] = [0xf9, 0x6d, 0x0f, 0x9f];

/// `identityOwner(address)` — selector 0x8733d4e8
const IDENTITY_OWNER_SELECTOR: [u8; 4] = [0x87, 0x33, 0xd4, 0xe8];

/// Encode a 20-byte address as a 32-byte ABI-padded word
fn abi_encode_address(addr: &[u8; 20]) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(addr);
    word
}

/// Build calldata: 4-byte selector + 32-byte padded address
fn encode_call(selector: [u8; 4], addr: &[u8; 20]) -> Vec<u8> {
    let mut data = Vec::with_capacity(36);
    data.extend_from_slice(&selector);
    data.extend_from_slice(&abi_encode_address(addr));
    data
}

/// Decode a 32-byte uint256 return value
fn decode_uint256(data: &[u8]) -> u64 {
    if data.len() < 32 {
        return 0;
    }
    // Read last 8 bytes as u64 (ERC-1056 changed() returns small block numbers)
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&data[24..32]);
    u64::from_be_bytes(bytes)
}

/// Decode a 32-byte ABI-encoded address return value
fn decode_address(data: &[u8]) -> [u8; 20] {
    if data.len() < 32 {
        return [0u8; 20];
    }
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&data[12..32]);
    addr
}

/// Convert raw 20 bytes to an EIP-55 checksummed hex address string
fn format_address_eip55(addr: &[u8; 20]) -> String {
    let lowercase = format!("0x{}", hex::encode(addr));
    keccak::eip55_checksum_addr(&lowercase).unwrap_or(lowercase)
}

// --- ERC-1056 event topic hashes ---

/// Compute keccak256 hash of an event signature string
fn keccak256(data: &[u8]) -> [u8; 32] {
    keccak::keccak256(data)
}

/// Lazily compute event topic hashes from their Solidity signatures
fn topic_owner_changed() -> [u8; 32] {
    keccak256(b"DIDOwnerChanged(address,address,uint256)")
}

fn topic_delegate_changed() -> [u8; 32] {
    keccak256(b"DIDDelegateChanged(address,bytes32,address,uint256,uint256)")
}

fn topic_attribute_changed() -> [u8; 32] {
    keccak256(b"DIDAttributeChanged(address,bytes32,bytes,uint256,uint256)")
}

// --- ERC-1056 event types ---

/// Parsed ERC-1056 events from the DIDRegistry contract
#[derive(Debug, Clone, PartialEq)]
pub enum Erc1056Event {
    OwnerChanged {
        identity: [u8; 20],
        owner: [u8; 20],
        previous_change: u64,
    },
    DelegateChanged {
        identity: [u8; 20],
        delegate_type: [u8; 32],
        delegate: [u8; 20],
        valid_to: u64,
        previous_change: u64,
    },
    AttributeChanged {
        identity: [u8; 20],
        name: [u8; 32],
        value: Vec<u8>,
        valid_to: u64,
        previous_change: u64,
    },
}

impl Erc1056Event {
    fn previous_change(&self) -> u64 {
        match self {
            Self::OwnerChanged { previous_change, .. } => *previous_change,
            Self::DelegateChanged { previous_change, .. } => *previous_change,
            Self::AttributeChanged { previous_change, .. } => *previous_change,
        }
    }
}

/// Parse an Ethereum log into an Erc1056Event.
///
/// Returns `None` if the log doesn't match any known ERC-1056 event or has
/// insufficient data.
fn parse_erc1056_event(log: &Log) -> Option<Erc1056Event> {
    if log.topics.is_empty() {
        return None;
    }
    let topic0 = log.topics[0];

    // Extract identity from topic[1] (indexed parameter, last 20 bytes of 32)
    if log.topics.len() < 2 {
        return None;
    }
    let mut identity = [0u8; 20];
    identity.copy_from_slice(&log.topics[1][12..32]);

    if topic0 == topic_owner_changed() {
        // data: owner(32) + previousChange(32) = 64 bytes
        if log.data.len() < 64 {
            return None;
        }
        let mut owner = [0u8; 20];
        owner.copy_from_slice(&log.data[12..32]);
        let previous_change = decode_uint256(&log.data[32..64]);
        Some(Erc1056Event::OwnerChanged {
            identity,
            owner,
            previous_change,
        })
    } else if topic0 == topic_delegate_changed() {
        // data: delegateType(32) + delegate(32) + validTo(32) + previousChange(32) = 128
        if log.data.len() < 128 {
            return None;
        }
        let mut delegate_type = [0u8; 32];
        delegate_type.copy_from_slice(&log.data[0..32]);
        let mut delegate = [0u8; 20];
        delegate.copy_from_slice(&log.data[44..64]);
        let valid_to = decode_uint256(&log.data[64..96]);
        let previous_change = decode_uint256(&log.data[96..128]);
        Some(Erc1056Event::DelegateChanged {
            identity,
            delegate_type,
            delegate,
            valid_to,
            previous_change,
        })
    } else if topic0 == topic_attribute_changed() {
        // data: name(32) + offset(32) + validTo(32) + previousChange(32) + valueLen(32) + value...
        if log.data.len() < 160 {
            return None;
        }
        let mut name = [0u8; 32];
        name.copy_from_slice(&log.data[0..32]);
        let valid_to = decode_uint256(&log.data[64..96]);
        let previous_change = decode_uint256(&log.data[96..128]);
        let value_len = decode_uint256(&log.data[128..160]) as usize;
        let value = if log.data.len() >= 160 + value_len {
            log.data[160..160 + value_len].to_vec()
        } else {
            Vec::new()
        };
        Some(Erc1056Event::AttributeChanged {
            identity,
            name,
            value,
            valid_to,
            previous_change,
        })
    } else {
        None
    }
}

/// Walk the ERC-1056 linked-list event log and return events in chronological order.
///
/// Starting from `changed_block`, fetches logs at each block and follows the
/// `previousChange` pointer backwards. The result is reversed to yield
/// chronological order.
async fn collect_events<P: EthProvider>(
    provider: &P,
    registry: [u8; 20],
    identity: &[u8; 20],
    changed_block: u64,
) -> Result<Vec<Erc1056Event>, String> {
    if changed_block == 0 {
        return Ok(Vec::new());
    }

    let identity_topic = abi_encode_address(identity);
    let topic0s = vec![
        topic_owner_changed(),
        topic_delegate_changed(),
        topic_attribute_changed(),
    ];

    let mut events = Vec::new();
    let mut current_block = changed_block;

    while current_block > 0 {
        let filter = LogFilter {
            address: registry,
            topic0: topic0s.clone(),
            topic1: Some(identity_topic),
            from_block: current_block,
            to_block: current_block,
        };

        let logs = provider
            .get_logs(filter)
            .await
            .map_err(|e| e.to_string())?;

        let mut next_block = 0u64;
        for log in &logs {
            if let Some(event) = parse_erc1056_event(log) {
                next_block = event.previous_change();
                events.push(event);
            }
        }

        current_block = next_block;
    }

    events.reverse(); // chronological order
    Ok(events)
}

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
    pub fn generate(jwk: &JWK) -> Result<DIDBuf, ssi_jwk::Error> {
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

        let network_name = decoded_id.network_name();

        // Check if we have a provider for this network
        if let Some(config) = self.networks.get(&network_name) {
            let addr_hex = decoded_id.account_address_hex();
            if let Some(addr) = parse_address_bytes(&addr_hex) {
                // Call changed(addr) to see if there are on-chain modifications
                let calldata = encode_call(CHANGED_SELECTOR, &addr);
                let result = config
                    .provider
                    .call(config.registry, calldata.clone(), BlockRef::Latest)
                    .await
                    .map_err(|e| Error::Internal(e.to_string()))?;
                let changed_block = decode_uint256(&result);

                if changed_block > 0 {
                    // Collect all events via linked-list walk
                    let events = collect_events(
                        &config.provider,
                        config.registry,
                        &addr,
                        changed_block,
                    )
                    .await
                    .map_err(Error::Internal)?;

                    // Check identityOwner(addr) for current owner
                    let owner_calldata = encode_call(IDENTITY_OWNER_SELECTOR, &addr);
                    let owner_result = config
                        .provider
                        .call(config.registry, owner_calldata, BlockRef::Latest)
                        .await
                        .map_err(|e| Error::Internal(e.to_string()))?;
                    let owner = decode_address(&owner_result);

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
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();

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

                    return serialize_document(doc, json_ld_context, options);
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

/// Decode the delegate_type bytes32 field by trimming trailing zeros
fn decode_delegate_type(delegate_type: &[u8; 32]) -> &[u8] {
    let end = delegate_type
        .iter()
        .rposition(|&b| b != 0)
        .map(|i| i + 1)
        .unwrap_or(0);
    &delegate_type[..end]
}

/// Process ERC-1056 events and add delegate verification methods to the document.
///
/// `now` is the current timestamp (seconds since epoch) used for expiry checks.
/// The delegate counter increments for every DelegateChanged event regardless of
/// validity, ensuring stable `#delegate-N` IDs.
fn apply_events(
    doc: &mut Document,
    events: &[Erc1056Event],
    did: &DIDBuf,
    network_chain: &NetworkChain,
    json_ld_context: &mut JsonLdContext,
    now: u64,
) {
    let mut delegate_counter = 0u64;
    let mut service_counter = 0u64;

    for event in events {
        match event {
            Erc1056Event::DelegateChanged {
                delegate_type,
                delegate,
                valid_to,
                ..
            } => {
                delegate_counter += 1;
                let dt = decode_delegate_type(delegate_type);

                let is_veri_key = dt == b"veriKey";
                let is_sig_auth = dt == b"sigAuth";

                if !is_veri_key && !is_sig_auth {
                    continue;
                }

                // Skip expired/revoked delegates
                if *valid_to < now {
                    continue;
                }

                let delegate_addr = format_address_eip55(delegate);
                let blockchain_account_id = BlockchainAccountId {
                    account_address: delegate_addr,
                    chain_id: ChainId {
                        namespace: "eip155".to_string(),
                        reference: network_chain.id().to_string(),
                    },
                };

                let vm_id = format!("{did}#delegate-{delegate_counter}");
                let eip712_id = format!("{did}#delegate-{delegate_counter}-Eip712Method2021");

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

                if is_sig_auth {
                    doc.verification_relationships
                        .authentication
                        .push(vm_id_url.into());
                    doc.verification_relationships
                        .authentication
                        .push(eip712_id_url.into());
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

                    if *valid_to < now {
                        continue;
                    }

                    let algo = parts.get(2).copied().unwrap_or("");
                    let purpose = parts.get(3).copied().unwrap_or("");
                    let encoding = parts.get(4).copied().unwrap_or("hex");

                    let vm_type = match algo {
                        "Secp256k1" => "EcdsaSecp256k1VerificationKey2019",
                        "Ed25519" => "Ed25519VerificationKey2018",
                        "X25519" => "X25519KeyAgreementKey2019",
                        _ => continue,
                    };

                    let prop_name = match encoding {
                        "hex" | "" => "publicKeyHex",
                        "base64" => "publicKeyBase64",
                        "base58" => "publicKeyBase58",
                        "pem" => "publicKeyPem",
                        _ => continue,
                    };

                    let prop_value = match encoding {
                        "hex" | "" => hex::encode(value),
                        "base64" => base64::engine::general_purpose::STANDARD.encode(value),
                        _ => String::from_utf8_lossy(value).into_owned(),
                    };

                    let vm_id = format!("{did}#delegate-{delegate_counter}");
                    let vm_id_url = DIDURLBuf::from_string(vm_id).unwrap();

                    let vm = DIDVerificationMethod {
                        id: vm_id_url.clone(),
                        type_: vm_type.to_owned(),
                        controller: did.clone(),
                        properties: [(
                            prop_name.into(),
                            serde_json::Value::String(prop_value),
                        )]
                        .into_iter()
                        .collect(),
                    };

                    // Add context entries
                    match algo {
                        "Secp256k1" => json_ld_context.add_verification_method_type(
                            VerificationMethodType::EcdsaSecp256k1VerificationKey2019,
                        ),
                        _ => {} // Ed25519/X25519 context handled in Phase 10+
                    }
                    json_ld_context.add_property(prop_name);

                    doc.verification_method.push(vm);

                    let is_veri_key = purpose == "veriKey";
                    let is_sig_auth = purpose == "sigAuth";
                    let is_enc = purpose == "enc";

                    if is_veri_key || is_sig_auth {
                        doc.verification_relationships
                            .assertion_method
                            .push(vm_id_url.clone().into());
                    }

                    if is_sig_auth {
                        doc.verification_relationships
                            .authentication
                            .push(vm_id_url.clone().into());
                    }

                    if is_enc {
                        doc.verification_relationships
                            .key_agreement
                            .push(vm_id_url.into());
                    }
                } else if parts.len() >= 3 && parts[0] == "did" && parts[1] == "svc" {
                    // did/svc/<ServiceType>
                    service_counter += 1;

                    if *valid_to < now {
                        continue;
                    }

                    let service_type = parts[2..].join("/");
                    let service_id = format!("{did}#service-{service_counter}");

                    let endpoint_str = String::from_utf8_lossy(value);
                    let endpoint = if let Ok(json_val) = serde_json::from_str::<serde_json::Value>(&endpoint_str) {
                        if json_val.is_object() || json_val.is_array() {
                            document::service::Endpoint::Map(json_val)
                        } else {
                            match iref::UriBuf::new(endpoint_str.as_bytes().to_vec()) {
                                Ok(uri) => document::service::Endpoint::Uri(uri),
                                Err(e) => document::service::Endpoint::Map(
                                    serde_json::Value::String(String::from_utf8_lossy(&e.0).into_owned()),
                                ),
                            }
                        }
                    } else {
                        match iref::UriBuf::new(endpoint_str.as_bytes().to_vec()) {
                            Ok(uri) => document::service::Endpoint::Uri(uri),
                            Err(e) => document::service::Endpoint::Map(
                                serde_json::Value::String(String::from_utf8_lossy(&e.0).into_owned()),
                            ),
                        }
                    };

                    let service = document::Service {
                        id: iref::UriBuf::new(service_id.into_bytes()).unwrap(),
                        type_: ssi_core::one_or_many::OneOrMany::One(service_type),
                        service_endpoint: Some(ssi_core::one_or_many::OneOrMany::One(endpoint)),
                        property_set: std::collections::BTreeMap::new(),
                    };

                    doc.service.push(service);
                }
            }
            // OwnerChanged handled by identityOwner() (Phase 2)
            _ => {}
        }
    }
}

/// Resolve a DID using the offline (genesis document) path
fn resolve_offline(
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

    serialize_document(doc, json_ld_context, options)
}

fn serialize_document(
    doc: Document,
    json_ld_context: JsonLdContext,
    options: resolution::Options,
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
        document::Metadata::default(),
        resolution::Metadata::from_content_type(Some(content_type.to_string())),
    ))
}

struct DecodedMethodSpecificId {
    network_name: String,
    network_chain: NetworkChain,
    address_or_public_key: String,
}

impl DecodedMethodSpecificId {
    /// Return the network name used for provider lookup
    fn network_name(&self) -> String {
        self.network_name.clone()
    }

    /// Extract the Ethereum address hex string (with 0x prefix).
    /// For public-key DIDs, derives the address from the public key.
    fn account_address_hex(&self) -> String {
        if self.address_or_public_key.len() == 42 {
            self.address_or_public_key.clone()
        } else {
            // Public key DID — derive the address
            let pk_hex = &self.address_or_public_key;
            if !pk_hex.starts_with("0x") {
                return String::new();
            }
            let pk_bytes = match hex::decode(&pk_hex[2..]) {
                Ok(b) => b,
                Err(_) => return String::new(),
            };
            let pk_jwk = match ssi_jwk::secp256k1_parse(&pk_bytes) {
                Ok(j) => j,
                Err(_) => return String::new(),
            };
            match ssi_jwk::eip155::hash_public_key_eip55(&pk_jwk) {
                Ok(addr) => addr,
                Err(_) => String::new(),
            }
        }
    }
}

impl FromStr for DecodedMethodSpecificId {
    type Err = InvalidNetwork;

    fn from_str(method_specific_id: &str) -> Result<Self, Self::Err> {
        // https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md#method-specific-identifier
        let (network_name, address_or_public_key) = match method_specific_id.split_once(':') {
            None => ("mainnet".to_string(), method_specific_id.to_string()),
            Some((network, address_or_public_key)) => {
                (network.to_string(), address_or_public_key.to_string())
            }
        };

        Ok(DecodedMethodSpecificId {
            network_chain: network_name.parse()?,
            network_name,
            address_or_public_key,
        })
    }
}

/// Parse a hex address string (with 0x prefix) into 20 bytes
fn parse_address_bytes(addr_hex: &str) -> Option<[u8; 20]> {
    if !addr_hex.starts_with("0x") || addr_hex.len() != 42 {
        return None;
    }
    let bytes = hex::decode(&addr_hex[2..]).ok()?;
    if bytes.len() != 20 {
        return None;
    }
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&bytes);
    Some(addr)
}

#[derive(Debug, thiserror::Error)]
#[error("invalid network `{0}`")]
struct InvalidNetwork(String);

enum NetworkChain {
    Mainnet,
    Morden,
    Ropsten,
    Rinkeby,
    Georli,
    Kovan,
    Other(u64),
}

impl NetworkChain {
    pub fn id(&self) -> u64 {
        match self {
            Self::Mainnet => 1,
            Self::Morden => 2,
            Self::Ropsten => 3,
            Self::Rinkeby => 4,
            Self::Georli => 5,
            Self::Kovan => 42,
            Self::Other(i) => *i,
        }
    }
}

impl FromStr for NetworkChain {
    type Err = InvalidNetwork;

    fn from_str(network_name: &str) -> Result<Self, Self::Err> {
        match network_name {
            "mainnet" => Ok(Self::Mainnet),
            "morden" => Ok(Self::Morden),
            "ropsten" => Ok(Self::Ropsten),
            "rinkeby" => Ok(Self::Rinkeby),
            "goerli" => Ok(Self::Georli),
            "kovan" => Ok(Self::Kovan),
            network_chain_id if network_chain_id.starts_with("0x") => {
                match u64::from_str_radix(&network_chain_id[2..], 16) {
                    Ok(chain_id) => Ok(Self::Other(chain_id)),
                    Err(_) => Err(InvalidNetwork(network_name.to_owned())),
                }
            }
            _ => Err(InvalidNetwork(network_name.to_owned())),
        }
    }
}

fn resolve_address(
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

    let mut doc = Document::new(did);
    doc.verification_relationships.assertion_method =
        vec![vm.id().to_owned().into(), eip712_vm.id().to_owned().into()];
    doc.verification_relationships.authentication =
        vec![vm.id().to_owned().into(), eip712_vm.id().to_owned().into()];
    doc.verification_method = vec![vm.into(), eip712_vm.into()];

    Ok(doc)
}

/// Resolve an Ethr DID that uses a public key hex string instead of an account address
fn resolve_public_key(
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
        blockchain_account_id,
    };

    let key_vm = VerificationMethod::EcdsaSecp256k1VerificationKey2019 {
        id: DIDURLBuf::from_string(format!("{did}#controllerKey")).unwrap(),
        controller: did.to_owned(),
        public_key_jwk: pk_jwk,
    };

    json_ld_context.add_verification_method_type(vm.type_());
    json_ld_context.add_verification_method_type(key_vm.type_());

    let mut doc = Document::new(did);
    doc.verification_relationships.assertion_method =
        vec![vm.id().to_owned().into(), key_vm.id().to_owned().into()];
    doc.verification_relationships.authentication =
        vec![vm.id().to_owned().into(), key_vm.id().to_owned().into()];
    doc.verification_method = vec![vm.into(), key_vm.into()];

    Ok(doc)
}

#[allow(clippy::large_enum_variant)]
pub enum VerificationMethod {
    EcdsaSecp256k1VerificationKey2019 {
        id: DIDURLBuf,
        controller: DIDBuf,
        public_key_jwk: JWK,
    },
    EcdsaSecp256k1RecoveryMethod2020 {
        id: DIDURLBuf,
        controller: DIDBuf,
        blockchain_account_id: BlockchainAccountId,
    },
    Eip712Method2021 {
        id: DIDURLBuf,
        controller: DIDBuf,
        blockchain_account_id: BlockchainAccountId,
    },
}

impl VerificationMethod {
    pub fn id(&self) -> &DIDURL {
        match self {
            Self::EcdsaSecp256k1VerificationKey2019 { id, .. } => id,
            Self::EcdsaSecp256k1RecoveryMethod2020 { id, .. } => id,
            Self::Eip712Method2021 { id, .. } => id,
        }
    }

    pub fn type_(&self) -> VerificationMethodType {
        match self {
            Self::EcdsaSecp256k1VerificationKey2019 { .. } => {
                VerificationMethodType::EcdsaSecp256k1VerificationKey2019
            }
            Self::EcdsaSecp256k1RecoveryMethod2020 { .. } => {
                VerificationMethodType::EcdsaSecp256k1RecoveryMethod2020
            }
            Self::Eip712Method2021 { .. } => VerificationMethodType::Eip712Method2021,
        }
    }
}

pub enum VerificationMethodType {
    EcdsaSecp256k1VerificationKey2019,
    EcdsaSecp256k1RecoveryMethod2020,
    Eip712Method2021,
}

impl VerificationMethodType {
    pub fn name(&self) -> &'static str {
        match self {
            Self::EcdsaSecp256k1VerificationKey2019 => "EcdsaSecp256k1VerificationKey2019",
            Self::EcdsaSecp256k1RecoveryMethod2020 => "EcdsaSecp256k1RecoveryMethod2020",
            Self::Eip712Method2021 => "Eip712Method2021",
        }
    }

    pub fn iri(&self) -> &'static Iri {
        match self {
            Self::EcdsaSecp256k1VerificationKey2019 => iri!("https://w3id.org/security#EcdsaSecp256k1VerificationKey2019"),
            Self::EcdsaSecp256k1RecoveryMethod2020 => iri!("https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#EcdsaSecp256k1RecoveryMethod2020"),
            Self::Eip712Method2021 => iri!("https://w3id.org/security#Eip712Method2021")
        }
    }
}

impl From<VerificationMethod> for DIDVerificationMethod {
    fn from(value: VerificationMethod) -> Self {
        match value {
            VerificationMethod::EcdsaSecp256k1VerificationKey2019 {
                id,
                controller,
                public_key_jwk,
            } => Self {
                id,
                type_: "EcdsaSecp256k1VerificationKey2019".to_owned(),
                controller,
                properties: [(
                    "publicKeyJwk".into(),
                    serde_json::to_value(&public_key_jwk).unwrap(),
                )]
                .into_iter()
                .collect(),
            },
            VerificationMethod::EcdsaSecp256k1RecoveryMethod2020 {
                id,
                controller,
                blockchain_account_id,
            } => Self {
                id,
                type_: "EcdsaSecp256k1RecoveryMethod2020".to_owned(),
                controller,
                properties: [(
                    "blockchainAccountId".into(),
                    blockchain_account_id.to_string().into(),
                )]
                .into_iter()
                .collect(),
            },
            VerificationMethod::Eip712Method2021 {
                id,
                controller,
                blockchain_account_id,
            } => Self {
                id,
                type_: "Eip712Method2021".to_owned(),
                controller,
                properties: [(
                    "blockchainAccountId".into(),
                    blockchain_account_id.to_string().into(),
                )]
                .into_iter()
                .collect(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iref::IriBuf;
    use serde_json::json;
    use ssi_claims::{
        data_integrity::{
            signing::AlterSignature, AnyInputSuiteOptions, AnySuite, CryptographicSuite,
            ProofOptions,
        },
        vc::{
            syntax::NonEmptyVec,
            v1::{JsonCredential, JsonPresentation},
        },
        VerificationParameters,
    };
    use ssi_dids_core::{did, DIDResolver};
    use ssi_jwk::JWK;
    use ssi_verification_methods_core::{ProofPurpose, ReferenceOrOwned, SingleSecretSigner};
    use static_iref::uri;

    #[test]
    fn jwk_to_did_ethr() {
        let jwk: JWK = serde_json::from_value(json!({
            "alg": "ES256K-R",
            "kty": "EC",
            "crv": "secp256k1",
            "x": "yclqMZ0MtyVkKm1eBh2AyaUtsqT0l5RJM3g4SzRT96A",
            "y": "yQzUwKnftWCJPGs-faGaHiYi1sxA6fGJVw2Px_LCNe8",
        }))
        .unwrap();
        let did = DIDEthr::generate(&jwk).unwrap();
        assert_eq!(did, "did:ethr:0x2fbf1be19d90a29aea9363f4ef0b6bf1c4ff0758");
    }

    #[tokio::test]
    async fn resolve_did_ethr_addr() {
        // https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md#create-register
        let resolver = DIDEthr::<()>::default();
        let doc = resolver
            .resolve(did!("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a"))
            .await
            .unwrap()
            .document;
        eprintln!("{}", serde_json::to_string_pretty(&doc).unwrap());
        assert_eq!(
            serde_json::to_value(doc).unwrap(),
            json!({
              "@context": [
                "https://www.w3.org/ns/did/v1",
                {
                  "blockchainAccountId": "https://w3id.org/security#blockchainAccountId",
                  "EcdsaSecp256k1RecoveryMethod2020": "https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#EcdsaSecp256k1RecoveryMethod2020",
                  "Eip712Method2021": "https://w3id.org/security#Eip712Method2021"
                }
              ],
              "id": "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a",
              "verificationMethod": [{
                "id": "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a#controller",
                "type": "EcdsaSecp256k1RecoveryMethod2020",
                "controller": "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a",
                "blockchainAccountId": "eip155:1:0xb9c5714089478a327f09197987f16f9e5d936e8a"
              }, {
                "id": "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a#Eip712Method2021",
                "type": "Eip712Method2021",
                "controller": "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a",
                "blockchainAccountId": "eip155:1:0xb9c5714089478a327f09197987f16f9e5d936e8a"
              }],
              "authentication": [
                "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a#controller",
                "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a#Eip712Method2021"
              ],
              "assertionMethod": [
                "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a#controller",
                "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a#Eip712Method2021"
              ]
            })
        );
    }

    #[tokio::test]
    async fn resolve_did_ethr_pk() {
        let resolver = DIDEthr::<()>::default();
        let doc = resolver
            .resolve(did!(
                "did:ethr:0x03fdd57adec3d438ea237fe46b33ee1e016eda6b585c3e27ea66686c2ea5358479"
            ))
            .await
            .unwrap()
            .document;
        eprintln!("{}", serde_json::to_string_pretty(&doc).unwrap());
        let doc_expected: serde_json::Value =
            serde_json::from_str(include_str!("../tests/did-pk.jsonld")).unwrap();
        assert_eq!(
            serde_json::to_value(doc).unwrap(),
            serde_json::to_value(doc_expected).unwrap()
        );
    }

    #[tokio::test]
    async fn credential_prove_verify_did_ethr() {
        eprintln!("with EcdsaSecp256k1RecoveryMethod2020...");
        credential_prove_verify_did_ethr2(false).await;
        eprintln!("with Eip712Method2021...");
        credential_prove_verify_did_ethr2(true).await;
    }

    async fn credential_prove_verify_did_ethr2(eip712: bool) {
        let didethr = DIDEthr::<()>::default().into_vm_resolver();
        let verifier = VerificationParameters::from_resolver(&didethr);
        let key: JWK = serde_json::from_value(json!({
            "alg": "ES256K-R",
            "kty": "EC",
            "crv": "secp256k1",
            "x": "yclqMZ0MtyVkKm1eBh2AyaUtsqT0l5RJM3g4SzRT96A",
            "y": "yQzUwKnftWCJPGs-faGaHiYi1sxA6fGJVw2Px_LCNe8",
            "d": "meTmccmR_6ZsOa2YuTTkKkJ4ZPYsKdAH1Wx_RRf2j_E"
        }))
        .unwrap();

        let did = DIDEthr::generate(&key).unwrap();
        eprintln!("did: {}", did);

        let cred = JsonCredential::new(
            None,
            did.clone().into_uri().into(),
            "2021-02-18T20:23:13Z".parse().unwrap(),
            NonEmptyVec::new(json_syntax::json!({
                "id": "did:example:foo"
            })),
        );

        let verification_method = if eip712 {
            ReferenceOrOwned::Reference(IriBuf::new(format!("{did}#Eip712Method2021")).unwrap())
        } else {
            ReferenceOrOwned::Reference(IriBuf::new(format!("{did}#controller")).unwrap())
        };

        let suite = AnySuite::pick(&key, Some(&verification_method)).unwrap();
        let issue_options = ProofOptions::new(
            "2021-02-18T20:23:13Z".parse().unwrap(),
            verification_method,
            ProofPurpose::Assertion,
            AnyInputSuiteOptions::default(),
        );

        eprintln!("vm {:?}", issue_options.verification_method);
        let signer = SingleSecretSigner::new(key).into_local();
        let vc = suite
            .sign(cred.clone(), &didethr, &signer, issue_options.clone())
            .await
            .unwrap();
        println!(
            "proof: {}",
            serde_json::to_string_pretty(&vc.proofs).unwrap()
        );
        if eip712 {
            assert_eq!(vc.proofs.first().unwrap().signature.as_ref(), "0xd3f4a049551fd25c7fb0789c7303be63265e8ade2630747de3807710382bbb7a25b0407e9f858a771782c35b4f487f4337341e9a4375a073730bda643895964e1b")
        } else {
            assert_eq!(vc.proofs.first().unwrap().signature.as_ref(), "eyJhbGciOiJFUzI1NkstUiIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..nwNfIHhCQlI-j58zgqwJgX2irGJNP8hqLis-xS16hMwzs3OuvjqzZIHlwvdzDMPopUA_Oq7M7Iql2LNe0B22oQE");
        }
        assert!(vc.verify(&verifier).await.unwrap().is_ok());

        // test that issuer property is used for verification
        let mut vc_bad_issuer = vc.clone();
        vc_bad_issuer.issuer = uri!("did:pkh:example:bad").to_owned().into();

        // It should fail.
        assert!(vc_bad_issuer.verify(&verifier).await.unwrap().is_err());

        // Check that proof JWK must match proof verificationMethod
        let wrong_key = JWK::generate_secp256k1();
        let wrong_signer = SingleSecretSigner::new(wrong_key.clone()).into_local();
        let vc_wrong_key = suite
            .sign(
                cred,
                &didethr,
                &wrong_signer,
                ProofOptions {
                    options: AnyInputSuiteOptions::default()
                        .with_public_key(wrong_key.to_public())
                        .unwrap(),
                    ..issue_options
                },
            )
            .await
            .unwrap();
        assert!(vc_wrong_key.verify(&verifier).await.unwrap().is_err());

        // Make it into a VP
        let presentation = JsonPresentation::new(
            Some(uri!("http://example.org/presentations/3731").to_owned()),
            None,
            vec![vc],
        );

        let vp_issue_options = ProofOptions::new(
            "2021-02-18T20:23:13Z".parse().unwrap(),
            IriBuf::new(format!("{did}#controller")).unwrap().into(),
            ProofPurpose::Authentication,
            AnyInputSuiteOptions::default(),
        );

        let vp = suite
            .sign(presentation, &didethr, &signer, vp_issue_options)
            .await
            .unwrap();

        println!("VP: {}", serde_json::to_string_pretty(&vp).unwrap());
        assert!(vp.verify(&verifier).await.unwrap().is_ok());

        // Mess with proof signature to make verify fail.
        let mut vp_fuzzed = vp.clone();
        vp_fuzzed.proofs.first_mut().unwrap().signature.alter();
        let vp_fuzzed_result = vp_fuzzed.verify(&verifier).await;
        assert!(vp_fuzzed_result.is_err() || vp_fuzzed_result.is_ok_and(|v| v.is_err()));

        // test that holder is verified
        let mut vp_bad_holder = vp;
        vp_bad_holder.holder = Some(uri!("did:pkh:example:bad").to_owned());

        // It should fail.
        assert!(vp_bad_holder.verify(&verifier).await.unwrap().is_err());
    }

    #[tokio::test]
    async fn credential_verify_eip712vm() {
        let didethr = DIDEthr::<()>::default().into_vm_resolver();
        let vc = ssi_claims::vc::v1::data_integrity::any_credential_from_json_str(include_str!(
            "../tests/vc.jsonld"
        ))
        .unwrap();
        // eprintln!("vc {:?}", vc);
        assert!(vc
            .verify(VerificationParameters::from_resolver(didethr))
            .await
            .unwrap()
            .is_ok())
    }

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
        /// Logs to return for get_logs calls, keyed by block number
        logs: HashMap<u64, Vec<Log>>,
    }

    impl MockProvider {
        fn new_unchanged() -> Self {
            Self {
                changed_block: 0,
                identity_owner: None,
                logs: HashMap::new(),
            }
        }

        fn new_same_owner() -> Self {
            Self {
                changed_block: 1, // has changes
                identity_owner: None, // but owner is the same
                logs: HashMap::new(),
            }
        }
    }

    impl EthProvider for MockProvider {
        type Error = MockProviderError;

        async fn call(
            &self,
            _to: [u8; 20],
            data: Vec<u8>,
            _block: BlockRef,
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
                    // Return identity_owner or echo back the queried address
                    let mut result = vec![0u8; 32];
                    if let Some(owner) = self.identity_owner {
                        result[12..32].copy_from_slice(&owner);
                    } else if data.len() >= 36 {
                        // Echo back the queried address (last 20 bytes of the 32-byte arg)
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
                        });
                    }
                }
            }
            Ok(result)
        }

        async fn block_timestamp(&self, _block: u64) -> Result<u64, Self::Error> {
            Ok(0)
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
        }
    }

    #[tokio::test]
    async fn collect_events_changed_zero_returns_empty() {
        let identity: [u8; 20] = [0xAA; 20];
        let provider = MockProvider::new_unchanged();

        let events = collect_events(&provider, TEST_REGISTRY, &identity, 0)
            .await
            .unwrap();

        assert!(events.is_empty(), "changed=0 should yield no events");
    }

    #[tokio::test]
    async fn collect_events_single_block_one_event() {
        let identity: [u8; 20] = [0xBB; 20];
        let new_owner: [u8; 20] = [0xCC; 20];

        let log = make_owner_changed_log(100, &identity, &new_owner, 0);

        let provider = MockProvider {
            changed_block: 100,
            identity_owner: Some(new_owner),
            logs: HashMap::from([(100, vec![log])]),
        };

        let events = collect_events(&provider, TEST_REGISTRY, &identity, 100)
            .await
            .unwrap();

        assert_eq!(events.len(), 1);
        match &events[0] {
            Erc1056Event::OwnerChanged { identity: id, owner, previous_change } => {
                assert_eq!(id, &[0xBB; 20]);
                assert_eq!(owner, &[0xCC; 20]);
                assert_eq!(*previous_change, 0);
            }
            _ => panic!("expected OwnerChanged event"),
        }
    }

    #[tokio::test]
    async fn collect_events_linked_list_walk_chronological_order() {
        // Block 200 has an owner change with previousChange=100
        // Block 100 has an owner change with previousChange=0
        // Expected: events returned in chronological order [block100, block200]
        let identity: [u8; 20] = [0xDD; 20];
        let owner_a: [u8; 20] = [0x11; 20];
        let owner_b: [u8; 20] = [0x22; 20];

        let log_at_100 = make_owner_changed_log(100, &identity, &owner_a, 0);
        let log_at_200 = make_owner_changed_log(200, &identity, &owner_b, 100);

        let provider = MockProvider {
            changed_block: 200,
            identity_owner: Some(owner_b),
            logs: HashMap::from([
                (100, vec![log_at_100]),
                (200, vec![log_at_200]),
            ]),
        };

        let events = collect_events(&provider, TEST_REGISTRY, &identity, 200)
            .await
            .unwrap();

        assert_eq!(events.len(), 2);

        // First event (chronologically) should be from block 100
        match &events[0] {
            Erc1056Event::OwnerChanged { owner, previous_change, .. } => {
                assert_eq!(owner, &owner_a);
                assert_eq!(*previous_change, 0);
            }
            _ => panic!("expected OwnerChanged event at index 0"),
        }

        // Second event should be from block 200
        match &events[1] {
            Erc1056Event::OwnerChanged { owner, previous_change, .. } => {
                assert_eq!(owner, &owner_b);
                assert_eq!(*previous_change, 100);
            }
            _ => panic!("expected OwnerChanged event at index 1"),
        }
    }

    #[tokio::test]
    async fn collect_events_multiple_event_types_across_blocks() {
        // Block 300: attribute change (previousChange=200)
        // Block 200: delegate change (previousChange=100)
        // Block 100: owner change (previousChange=0)
        let identity: [u8; 20] = [0xEE; 20];
        let new_owner: [u8; 20] = [0x11; 20];
        let delegate: [u8; 20] = [0x22; 20];

        let mut delegate_type = [0u8; 32];
        delegate_type[..7].copy_from_slice(b"veriKey");

        let mut attr_name = [0u8; 32];
        attr_name[..29].copy_from_slice(b"did/pub/Secp256k1/veriKey/hex");

        let log_100 = make_owner_changed_log(100, &identity, &new_owner, 0);
        let log_200 = make_delegate_changed_log(
            200, &identity, &delegate_type, &delegate, u64::MAX, 100,
        );
        let log_300 = make_attribute_changed_log(
            300, &identity, &attr_name, b"\x04abc", u64::MAX, 200,
        );

        let provider = MockProvider {
            changed_block: 300,
            identity_owner: Some(new_owner),
            logs: HashMap::from([
                (100, vec![log_100]),
                (200, vec![log_200]),
                (300, vec![log_300]),
            ]),
        };

        let events = collect_events(&provider, TEST_REGISTRY, &identity, 300)
            .await
            .unwrap();

        assert_eq!(events.len(), 3);

        // Chronological: block 100 first
        assert!(matches!(&events[0], Erc1056Event::OwnerChanged { .. }));
        assert!(matches!(&events[1], Erc1056Event::DelegateChanged { .. }));
        assert!(matches!(&events[2], Erc1056Event::AttributeChanged { .. }));

        // Verify delegate event details
        match &events[1] {
            Erc1056Event::DelegateChanged { delegate: d, valid_to, previous_change, .. } => {
                assert_eq!(d, &delegate);
                assert_eq!(*valid_to, u64::MAX);
                assert_eq!(*previous_change, 100);
            }
            _ => unreachable!(),
        }

        // Verify attribute event details
        match &events[2] {
            Erc1056Event::AttributeChanged { name, value, valid_to, previous_change, .. } => {
                assert_eq!(name, &attr_name);
                assert_eq!(value, b"\x04abc");
                assert_eq!(*valid_to, u64::MAX);
                assert_eq!(*previous_change, 200);
            }
            _ => unreachable!(),
        }
    }

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

    /// Helper: encode a delegate type string as bytes32 (right-padded with zeros)
    fn encode_delegate_type(s: &str) -> [u8; 32] {
        let mut b = [0u8; 32];
        let bytes = s.as_bytes();
        b[..bytes.len().min(32)].copy_from_slice(&bytes[..bytes.len().min(32)]);
        b
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

    /// Helper: encode an attribute name string as bytes32 (right-padded with zeros)
    fn encode_attr_name(s: &str) -> [u8; 32] {
        let mut b = [0u8; 32];
        let bytes = s.as_bytes();
        b[..bytes.len().min(32)].copy_from_slice(&bytes[..bytes.len().min(32)]);
        b
    }

    #[tokio::test]
    async fn resolve_secp256k1_verikey_hex_attribute() {
        // did/pub/Secp256k1/veriKey/hex attribute adds EcdsaSecp256k1VerificationKey2019
        // with publicKeyHex to verificationMethod + assertionMethod, using #delegate-N ID
        let identity: [u8; 20] = [0xb9, 0xc5, 0x71, 0x40, 0x89, 0x47, 0x8a, 0x32, 0x7f, 0x09,
                                   0x19, 0x79, 0x87, 0xf1, 0x6f, 0x9e, 0x5d, 0x93, 0x6e, 0x8a];
        let attr_name = encode_attr_name("did/pub/Secp256k1/veriKey/hex");
        let pub_key_value: Vec<u8> = vec![0x04, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67];

        let log = make_attribute_changed_log(100, &identity, &attr_name, &pub_key_value, u64::MAX, 0);

        let mut resolver = DIDEthr::new();
        resolver.add_network("mainnet", NetworkConfig {
            chain_id: 1,
            registry: TEST_REGISTRY,
            provider: MockProvider {
                changed_block: 100,
                identity_owner: None,
                logs: HashMap::from([(100, vec![log])]),
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
        assert_eq!(attr_vm["publicKeyHex"], hex::encode(&pub_key_value));
        assert_eq!(attr_vm["controller"], "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a");

        // Should be in assertionMethod but NOT authentication
        let did_prefix = "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a";
        let assertion = doc_value["assertionMethod"].as_array().unwrap();
        let auth = doc_value["authentication"].as_array().unwrap();
        assert!(assertion.iter().any(|v| v == &format!("{did_prefix}#delegate-1")));
        assert!(!auth.iter().any(|v| v == &format!("{did_prefix}#delegate-1")));
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
}
