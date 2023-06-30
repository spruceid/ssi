use ssi_jws::CompactJWSBuf;

use crate::{Proof, VcJwt};

impl<C> VcJwt<C> {
    /// Encode a JSON Web Token credential.
    pub async fn encode<N, L>(self, proof: Proof) -> CompactJWSBuf {
        unsafe {
            // SAFETY: `Self::into_signing_bytes` is guaranteed to return valid
            //         signing bytes to form a compact JWS.
            CompactJWSBuf::from_signing_bytes_and_signature_unchecked(
                self.into_signing_bytes(),
                proof.into_signature(),
            )
        }
    }
}
