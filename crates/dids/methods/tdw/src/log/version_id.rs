pub struct VersionId {
    version_number: u64,
    // TODO multihash
    entry_hash: [u8; 32],
}

impl VersionId {
    pub fn new(version_number: u64, entry_hash: [u8; 32]) -> Self {
        Self {
            version_number,
            entry_hash,
        }
    }

    pub fn version_number(&self) -> u64 {
        self.version_number
    }

    pub fn entry_hash(&self) -> [u8; 32] {
        self.entry_hash
    }
}
