impl PublicKey {
	pub fn from_spki(spki: spki::SubjectPublicKeyInfoOwned) -> Result<Self, InvalidPublicKey> {
        // spki.algorithm.oid.arcs()
        todo!("from spki: {spki:?}")
    }
}