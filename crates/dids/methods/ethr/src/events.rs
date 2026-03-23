use crate::abi::{abi_encode_address, decode_uint256, keccak256};
use crate::provider::{EthProvider, Log, LogFilter};

// --- ERC-1056 event topic hashes ---

pub(crate) fn topic_owner_changed() -> [u8; 32] {
    static HASH: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
    *HASH.get_or_init(|| keccak256(b"DIDOwnerChanged(address,address,uint256)"))
}

pub(crate) fn topic_delegate_changed() -> [u8; 32] {
    static HASH: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
    *HASH.get_or_init(|| keccak256(b"DIDDelegateChanged(address,bytes32,address,uint256,uint256)"))
}

pub(crate) fn topic_attribute_changed() -> [u8; 32] {
    static HASH: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
    *HASH.get_or_init(|| keccak256(b"DIDAttributeChanged(address,bytes32,bytes,uint256,uint256)"))
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
    pub(crate) fn previous_change(&self) -> u64 {
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
pub(crate) fn parse_erc1056_event(log: &Log) -> Option<Erc1056Event> {
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
        let previous_change = decode_uint256(&log.data[32..64]).ok()?;
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
        let valid_to = decode_uint256(&log.data[64..96]).ok()?;
        let previous_change = decode_uint256(&log.data[96..128]).ok()?;
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
        let valid_to = decode_uint256(&log.data[64..96]).ok()?;
        let previous_change = decode_uint256(&log.data[96..128]).ok()?;
        let value_len = decode_uint256(&log.data[128..160]).ok()? as usize;
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
pub(crate) async fn collect_events<P: EthProvider>(
    provider: &P,
    registry: [u8; 20],
    identity: &[u8; 20],
    changed_block: u64,
) -> Result<Vec<(u64, Erc1056Event)>, String> {
    if changed_block == 0 {
        return Ok(Vec::new());
    }

    let identity_topic = abi_encode_address(identity);
    let topic0s = vec![
        topic_owner_changed(),
        topic_delegate_changed(),
        topic_attribute_changed(),
    ];

    let mut events: Vec<(u64, u64, Erc1056Event)> = Vec::new();
    let mut current_block = changed_block;
    let mut visited = std::collections::HashSet::new();

    while current_block > 0 {
        if !visited.insert(current_block) {
            break; // cycle guard
        }

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
                events.push((log.block_number, log.log_index, event.clone()));
                let prev = event.previous_change();
                // Only follow pointers that strictly retreat; ignore same-block
                // self-references (prev == current_block) which cause cycles.
                if prev < current_block {
                    next_block = next_block.max(prev);
                }
            }
        }

        current_block = next_block;
    }

    // Sort into chronological order by (block_number, log_index).
    // This preserves intra-block ordering — critical when multiple events
    // in the same block have order-dependent semantics (e.g. add then revoke).
    events.sort_by_key(|(block, log_idx, _)| (*block, *log_idx));
    Ok(events.into_iter().map(|(block, _, event)| (block, event)).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use crate::provider::Log;

    const TEST_REGISTRY: [u8; 20] = [
        0xdc, 0xa7, 0xef, 0x03, 0xe9, 0x8e, 0x0d, 0xc2,
        0xb8, 0x55, 0xbe, 0x64, 0x7c, 0x39, 0xab, 0xe9,
        0x84, 0xfc, 0xf2, 0x1b,
    ];

    #[derive(Debug)]
    struct MockProviderError(String);
    impl std::fmt::Display for MockProviderError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "MockProviderError: {}", self.0)
        }
    }
    impl std::error::Error for MockProviderError {}

    struct MockProvider {
        logs: HashMap<u64, Vec<Log>>,
    }

    impl EthProvider for MockProvider {
        type Error = MockProviderError;

        async fn call(
            &self,
            _to: [u8; 20],
            _data: Vec<u8>,
            _block: crate::provider::BlockRef,
        ) -> Result<Vec<u8>, Self::Error> {
            Ok(vec![0u8; 32])
        }

        async fn get_logs(&self, filter: LogFilter) -> Result<Vec<Log>, Self::Error> {
            let mut result = Vec::new();
            for block in filter.from_block..=filter.to_block {
                if let Some(block_logs) = self.logs.get(&block) {
                    for log in block_logs {
                        if !filter.topic0.is_empty() && !log.topics.is_empty() {
                            if !filter.topic0.contains(&log.topics[0]) {
                                continue;
                            }
                        }
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

        async fn block_timestamp(&self, _block: u64) -> Result<u64, Self::Error> {
            Ok(0)
        }
    }

    fn make_owner_changed_log(
        block: u64,
        identity: &[u8; 20],
        new_owner: &[u8; 20],
        previous_change: u64,
    ) -> Log {
        let identity_topic = abi_encode_address(identity);
        let mut data = vec![0u8; 64];
        data[12..32].copy_from_slice(new_owner);
        data[56..64].copy_from_slice(&previous_change.to_be_bytes());
        Log {
            address: TEST_REGISTRY,
            topics: vec![topic_owner_changed(), identity_topic],
            data,
            block_number: block,
            log_index: 0,
        }
    }

    fn make_attribute_changed_log(
        block: u64,
        identity: &[u8; 20],
        name: &[u8; 32],
        value: &[u8],
        valid_to: u64,
        previous_change: u64,
    ) -> Log {
        let identity_topic = abi_encode_address(identity);
        let padded_value_len = ((value.len() + 31) / 32) * 32;
        let total_len = 160 + padded_value_len;
        let mut data = vec![0u8; total_len];
        data[0..32].copy_from_slice(name);
        data[56..64].copy_from_slice(&160u64.to_be_bytes());
        data[88..96].copy_from_slice(&valid_to.to_be_bytes());
        data[120..128].copy_from_slice(&previous_change.to_be_bytes());
        data[152..160].copy_from_slice(&(value.len() as u64).to_be_bytes());
        data[160..160 + value.len()].copy_from_slice(value);
        Log {
            address: TEST_REGISTRY,
            topics: vec![topic_attribute_changed(), identity_topic],
            data,
            block_number: block,
            log_index: 0,
        }
    }

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
        data[0..32].copy_from_slice(delegate_type);
        data[44..64].copy_from_slice(delegate);
        data[88..96].copy_from_slice(&valid_to.to_be_bytes());
        data[120..128].copy_from_slice(&previous_change.to_be_bytes());
        Log {
            address: TEST_REGISTRY,
            topics: vec![topic_delegate_changed(), identity_topic],
            data,
            block_number: block,
            log_index: 0,
        }
    }

    #[tokio::test]
    async fn collect_events_changed_zero_returns_empty() {
        let identity: [u8; 20] = [0xAA; 20];
        let provider = MockProvider { logs: HashMap::new() };

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
            logs: HashMap::from([(100, vec![log])]),
        };

        let events = collect_events(&provider, TEST_REGISTRY, &identity, 100)
            .await
            .unwrap();

        assert_eq!(events.len(), 1);
        match &events[0] {
            (_, Erc1056Event::OwnerChanged { identity: id, owner, previous_change }) => {
                assert_eq!(id, &[0xBB; 20]);
                assert_eq!(owner, &[0xCC; 20]);
                assert_eq!(*previous_change, 0);
            }
            _ => panic!("expected OwnerChanged event"),
        }
    }

    #[tokio::test]
    async fn collect_events_linked_list_walk_chronological_order() {
        let identity: [u8; 20] = [0xDD; 20];
        let owner_a: [u8; 20] = [0x11; 20];
        let owner_b: [u8; 20] = [0x22; 20];

        let log_at_100 = make_owner_changed_log(100, &identity, &owner_a, 0);
        let log_at_200 = make_owner_changed_log(200, &identity, &owner_b, 100);

        let provider = MockProvider {
            logs: HashMap::from([
                (100, vec![log_at_100]),
                (200, vec![log_at_200]),
            ]),
        };

        let events = collect_events(&provider, TEST_REGISTRY, &identity, 200)
            .await
            .unwrap();

        assert_eq!(events.len(), 2);

        match &events[0] {
            (_, Erc1056Event::OwnerChanged { owner, previous_change, .. }) => {
                assert_eq!(owner, &owner_a);
                assert_eq!(*previous_change, 0);
            }
            _ => panic!("expected OwnerChanged event at index 0"),
        }

        match &events[1] {
            (_, Erc1056Event::OwnerChanged { owner, previous_change, .. }) => {
                assert_eq!(owner, &owner_b);
                assert_eq!(*previous_change, 100);
            }
            _ => panic!("expected OwnerChanged event at index 1"),
        }
    }

    #[tokio::test]
    async fn collect_events_multiple_event_types_across_blocks() {
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

        assert!(matches!(&events[0], (_, Erc1056Event::OwnerChanged { .. })));
        assert!(matches!(&events[1], (_, Erc1056Event::DelegateChanged { .. })));
        assert!(matches!(&events[2], (_, Erc1056Event::AttributeChanged { .. })));

        match &events[1] {
            (_, Erc1056Event::DelegateChanged { delegate: d, valid_to, previous_change, .. }) => {
                assert_eq!(d, &delegate);
                assert_eq!(*valid_to, u64::MAX);
                assert_eq!(*previous_change, 100);
            }
            _ => unreachable!(),
        }

        match &events[2] {
            (_, Erc1056Event::AttributeChanged { name, value, valid_to, previous_change, .. }) => {
                assert_eq!(name, &attr_name);
                assert_eq!(value, b"\x04abc");
                assert_eq!(*valid_to, u64::MAX);
                assert_eq!(*previous_change, 200);
            }
            _ => unreachable!(),
        }
    }

    #[tokio::test]
    async fn collect_events_same_block_events_all_collected() {
        // Simulate the same-block cycle bug:
        // Block 100 has two events:
        //   - first event (log_index=0): previousChange=50 (normal retreat)
        //   - second event (log_index=1): previousChange=100 (self-reference due to changed[identity]
        //     already updated to current_block in the same block)
        // Both events should be collected; next block is 50; loop terminates.
        let identity: [u8; 20] = [0xFF; 20];
        let new_owner: [u8; 20] = [0x11; 20];

        let mut attr_name = [0u8; 32];
        attr_name[..29].copy_from_slice(b"did/pub/Secp256k1/veriKey/hex");

        // First event in block 100: previousChange=50 (normal)
        let mut log_100_first = make_owner_changed_log(100, &identity, &new_owner, 50);
        log_100_first.log_index = 0;
        // Second event in block 100: previousChange=100 (self-reference / cycle)
        let mut log_100_second = make_attribute_changed_log(
            100, &identity, &attr_name, b"\x04abc", u64::MAX, 100,
        );
        log_100_second.log_index = 1;
        // Event at block 50 (to ensure walk continues correctly)
        let owner_at_50: [u8; 20] = [0x22; 20];
        let log_50 = make_owner_changed_log(50, &identity, &owner_at_50, 0);

        let provider = MockProvider {
            logs: HashMap::from([
                (100, vec![log_100_first, log_100_second]),
                (50, vec![log_50]),
            ]),
        };

        let events = collect_events(&provider, TEST_REGISTRY, &identity, 100)
            .await
            .unwrap();

        // Both block-100 events plus the block-50 event should all be collected
        assert_eq!(events.len(), 3, "expected 3 events: one at block 50 and two at block 100");

        // Chronological by block: block 50 first, then block 100 events
        assert!(matches!(&events[0], (50, _)));
        // Intra-block order preserved: OwnerChanged (log_index=0) before AttributeChanged (log_index=1)
        assert!(matches!(&events[1], (100, Erc1056Event::OwnerChanged { .. })),
            "expected OwnerChanged at index 1 (log_index=0)");
        assert!(matches!(&events[2], (100, Erc1056Event::AttributeChanged { .. })),
            "expected AttributeChanged at index 2 (log_index=1)");
    }

    #[tokio::test]
    async fn collect_events_preserves_intra_block_order() {
        // Two events in the same block with distinct log_index values.
        // After collect_events, they must appear in log_index order (not reversed).
        let identity: [u8; 20] = [0xAA; 20];
        let delegate: [u8; 20] = [0xBB; 20];

        let mut delegate_type = [0u8; 32];
        delegate_type[..7].copy_from_slice(b"veriKey");

        let mut attr_name = [0u8; 32];
        attr_name[..29].copy_from_slice(b"did/pub/Secp256k1/veriKey/hex");

        // log_index=0: add delegate
        let mut log_add = make_delegate_changed_log(
            100, &identity, &delegate_type, &delegate, u64::MAX, 0,
        );
        log_add.log_index = 0;

        // log_index=1: revoke delegate (valid_to=0)
        let mut log_revoke = make_delegate_changed_log(
            100, &identity, &delegate_type, &delegate, 0, 100,
        );
        log_revoke.log_index = 1;

        let provider = MockProvider {
            logs: HashMap::from([(100, vec![log_add, log_revoke])]),
        };

        let events = collect_events(&provider, TEST_REGISTRY, &identity, 100)
            .await
            .unwrap();

        assert_eq!(events.len(), 2);

        // First event: add (valid_to = MAX)
        match &events[0] {
            (100, Erc1056Event::DelegateChanged { valid_to, .. }) => {
                assert_eq!(*valid_to, u64::MAX, "first event should be the add (valid_to=MAX)");
            }
            other => panic!("expected DelegateChanged add at index 0, got {other:?}"),
        }

        // Second event: revoke (valid_to = 0)
        match &events[1] {
            (100, Erc1056Event::DelegateChanged { valid_to, .. }) => {
                assert_eq!(*valid_to, 0, "second event should be the revoke (valid_to=0)");
            }
            other => panic!("expected DelegateChanged revoke at index 1, got {other:?}"),
        }
    }
}
