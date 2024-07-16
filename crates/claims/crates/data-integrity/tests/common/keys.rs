use std::{borrow::Cow, collections::HashMap};

use iref::UriBuf;
use ssi_claims_core::SignatureError;
use ssi_jwk::JWK;
use ssi_multicodec::MultiEncodedBuf;
use ssi_verification_methods::{
    multikey::{self, MultikeyPair},
    AnyMethod, Multikey, ReferenceOrOwnedRef, VerificationMethodResolutionError,
    VerificationMethodResolver,
};

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

impl VerificationMethodResolver for MultikeyRing {
    type Method = AnyMethod;

    async fn resolve_verification_method_with(
        &self,
        _issuer: Option<&iref::Iri>,
        method: Option<ReferenceOrOwnedRef<'_, Self::Method>>,
        _options: ssi_verification_methods::ResolutionOptions,
    ) -> Result<Cow<Self::Method>, VerificationMethodResolutionError> {
        match method {
            Some(ReferenceOrOwnedRef::Owned(method)) => Ok(Cow::Owned(method.clone())),
            Some(ReferenceOrOwnedRef::Reference(id)) => match self.map.get(id.as_str()) {
                Some(pair) => {
                    let controller: UriBuf = match id.fragment() {
                        Some(fragment) => UriBuf::new(
                            id[0..(id.len() - 1 - fragment.len())]
                                .to_owned()
                                .into_bytes(),
                        )
                        .unwrap(),
                        None => UriBuf::new(id.to_string().into_bytes()).unwrap(),
                    };

                    Ok(Cow::Owned(AnyMethod::Multikey(Multikey {
                        id: id.to_owned(),
                        controller,
                        public_key: multikey::PublicKey::from_multibase(pair.public.clone()),
                    })))
                }
                None => Err(VerificationMethodResolutionError::UnknownKey),
            },
            None => Err(VerificationMethodResolutionError::MissingVerificationMethod),
        }
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
