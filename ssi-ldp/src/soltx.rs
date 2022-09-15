pub struct LocalSolanaTransaction {
    bytes: Vec<u8>,
}

impl LocalSolanaTransaction {
    pub fn with_message(bytes: &[u8]) -> Self {
        // TODO
        Self {
            bytes: bytes.into(),
        }
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        // TODO
        self.bytes.clone()
    }
}
