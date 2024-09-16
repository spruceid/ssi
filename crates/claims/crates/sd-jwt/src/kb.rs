pub struct SdJwtKb(str);

impl SdJwtKb {
	/// Returns references to each part of this SD-JWT.
    pub fn parts(&self) -> PartsRef {
        let mut chars = self.0.char_indices();
        
        // Find issuer-signed JWT.
        let jwt = loop {
            if let Some((i, '~')) = chars.next() {
                break unsafe {
                    // SAFETY: we already validated the SD-JWT and know it
                    // starts with a valid JWT.
                    Jws::new_unchecked(self.0[..i].as_bytes())
                }
            }
        };

        let mut disclosures = Vec::new();
        let mut i = jwt.len() + 1;
        
        let key_binding_jwt = loop {
            match chars.next() {
                Some((j, '~')) => {
                    disclosures.push(unsafe {
                        // SAFETY: we already validated the SD-JWT and know
                        // it is composed of valid disclosures.
                        Disclosure::new_unchecked(self.0[i..j].as_bytes())
                    });
                    i = j + 1;
                }
                Some(_) => (),
                None => {
                    break if i < self.0.len() {
                        Some(unsafe {
                            // SAFETY: we already validated the SD-JWT and know
                            // it ends with a valid JWT.
                            Jws::new_unchecked(self.0[i..].as_bytes())
                        })
                    } else {
                        None
                    }
                }
            }
        };

        PartsRef {
            jwt,
            disclosures,
            key_binding_jwt
        }
    }
}

/// SD-JWT components to be presented for decoding and validation whether coming
/// from a compact representation, enveloping JWT, etc.
#[derive(Debug, PartialEq)]
pub struct PartsRef<'a> {
    /// JWT who's claims can be selectively disclosed.
    pub jwt: &'a Jws,

    /// Disclosures for associated JWT
    pub disclosures: Vec<&'a Disclosure>,

    /// Key binding JWT.
    pub key_binding_jwt: Option<&'a Jws>
}