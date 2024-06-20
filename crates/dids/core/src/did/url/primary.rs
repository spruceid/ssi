use std::{borrow::Borrow, ops::Deref};

use crate::{DIDURLBuf, Fragment, DIDURL};

/// DID URL without fragment.
#[repr(transparent)]
pub struct PrimaryDIDURL([u8]);

impl PrimaryDIDURL {
    /// Creates a new primary DID URL without checking the data.
    ///
    /// # Safety
    ///
    /// The input `data` must be a valid primary DID URL.
    pub unsafe fn new_unchecked(data: &[u8]) -> &Self {
        std::mem::transmute(data)
    }

    pub fn as_did_url(&self) -> &DIDURL {
        unsafe { DIDURL::new_unchecked(&self.0) }
    }
}

impl Deref for PrimaryDIDURL {
    type Target = DIDURL;

    fn deref(&self) -> &Self::Target {
        self.as_did_url()
    }
}

impl ToOwned for PrimaryDIDURL {
    type Owned = PrimaryDIDURLBuf;

    fn to_owned(&self) -> Self::Owned {
        unsafe { PrimaryDIDURLBuf::new_unchecked(self.0.to_vec()) }
    }
}

impl<'a> From<&'a PrimaryDIDURL> for PrimaryDIDURLBuf {
    fn from(value: &'a PrimaryDIDURL) -> Self {
        value.to_owned()
    }
}

/// DID URL without fragment.
pub struct PrimaryDIDURLBuf(Vec<u8>);

impl PrimaryDIDURLBuf {
    /// Creates a new primary DID URL without checking the data.
    ///
    /// # Safety
    ///
    /// The input `data` must be a valid primary DID URL.
    pub unsafe fn new_unchecked(data: Vec<u8>) -> Self {
        Self(data)
    }

    pub fn as_primary_did_url(&self) -> &PrimaryDIDURL {
        unsafe { PrimaryDIDURL::new_unchecked(&self.0) }
    }

    /// Append a [fragment](https://www.w3.org/TR/did-core/#fragment) to construct a DID URL.
    ///
    /// The opposite of [DIDURL::without_fragment].
    pub fn with_fragment(self, fragment: &Fragment) -> DIDURLBuf {
        let mut result = self.0;
        result.push(b'#');
        result.extend(fragment.as_bytes());
        unsafe { DIDURLBuf::new_unchecked(result) }
    }

    pub fn into_did_url(self) -> DIDURLBuf {
        unsafe { DIDURLBuf::new_unchecked(self.0) }
    }
}

impl Deref for PrimaryDIDURLBuf {
    type Target = PrimaryDIDURL;

    fn deref(&self) -> &Self::Target {
        self.as_primary_did_url()
    }
}

impl Borrow<PrimaryDIDURL> for PrimaryDIDURLBuf {
    fn borrow(&self) -> &PrimaryDIDURL {
        self.as_primary_did_url()
    }
}
