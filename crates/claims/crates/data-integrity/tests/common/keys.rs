use ssi_claims_core::SignatureError;
use ssi_jwk::JWK;
use ssi_multicodec::MultiEncodedBuf;
use ssi_verification_methods::{multikey::MultikeyPair, AnyMethod};
use std::{borrow::Cow, collections::HashMap};

#[derive(Default)]
pub struct MultikeyRing {
    map: HashMap<String, MultikeyPair>,
}

impl MultikeyRing {
    pub fn insert(&mut self, key_pair: MultikeyPair) {
        self.map
            .insert(format!("did:key:{0}#{0}", &key_pair.public), key_pair);
    }
}

impl ssi_verification_methods::Signer<AnyMethod> for MultikeyRing {
    type MessageSigner = JWK;

    async fn for_method(
        &self,
        method: Cow<'_, AnyMethod>,
    ) -> Result<Option<Self::MessageSigner>, SignatureError> {
        match method.as_ref() {
            AnyMethod::Multikey(m) => match self.map.get(m.id.as_str()) {
                Some(pair) => {
                    let (_, decoded) = pair.secret.decode().unwrap();
                    let multi_encoded = MultiEncodedBuf::new(decoded).unwrap();
                    Ok(Some(JWK::from_multicodec(&multi_encoded).unwrap()))
                }
                None => Ok(None),
            },
            _ => todo!(),
        }
    }
}
