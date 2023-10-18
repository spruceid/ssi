#![cfg_attr(docsrs, feature(doc_auto_cfg))]

// TODO reinstate Error::MissingFeatures ?

pub mod error;
pub use base64::DecodeError as Base64DecodeError;
use rdf_types::{Vocabulary, Interpretation};
use core::fmt;
pub use error::Error;
use linked_data::{rdf_types, LinkedDataPredicateObjects, LinkedDataResource, LinkedDataSubject, RdfTermRef, LinkedDataDeserializeSubject, LinkedDataDeserializePredicateObjects};
use serde::{Deserialize, Serialize};
use ssi_jwk::{Algorithm, Base64urlUInt, Params as JWKParams, JWK};
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::ops::Deref;
use std::str::FromStr;

pub type VerificationWarnings = Vec<String>;

// RFC 7515 - JSON Web Signature (JWS)
// RFC 7797 - JSON Web Signature (JWS) Unencoded Payload Option

/// JWS in compact serialized form.
#[repr(transparent)]
pub struct CompactJWS([u8]);

impl CompactJWS {
    pub fn new(data: &[u8]) -> Result<&Self, InvalidCompactJWS<&[u8]>> {
        if Self::check(data) {
            Ok(unsafe { Self::new_unchecked(data) })
        } else {
            Err(InvalidCompactJWS(data))
        }
    }

    /// Creates a new compact JWS without checking the data.
    ///
    /// # Safety
    ///
    /// The input `data` must represent a valid compact JWS.
    pub unsafe fn new_unchecked(data: &[u8]) -> &Self {
        std::mem::transmute(data)
    }

    pub fn check(data: &[u8]) -> bool {
        enum State {
            Header,
            Payload,
            Signature,
        }

        let mut state = State::Header;

        for &b in data {
            match state {
                State::Header => match b {
                    b'.' => state = State::Payload,
                    b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' | b'+' | b'/' => (),
                    _ => return false,
                },
                State::Payload => {
                    if b == b'.' {
                        state = State::Signature
                    }
                }
                State::Signature => (),
            }
        }

        matches!(state, State::Signature)
    }

    pub fn check_signing_bytes(data: &[u8]) -> bool {
        for &b in data {
            match b {
                b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' | b'+' | b'/' => (),
                b'.' => return true,
                _ => return false,
            }
        }

        false
    }

    fn header_end(&self) -> usize {
        self.0.iter().position(|b| *b == b'.').unwrap()
    }

    fn signature_start(&self) -> usize {
        self.0.len() - self.0.iter().rev().position(|b| *b == b'.').unwrap()
    }

    fn payload_start(&self) -> usize {
        self.header_end() + 1
    }

    fn payload_end(&self) -> usize {
        self.signature_start() - 1
    }

    /// Returns the Base64 encoded header.
    pub fn header(&self) -> &[u8] {
        &self.0[..self.header_end()]
    }

    pub fn decode_header(&self) -> Result<Header, InvalidHeader> {
        Header::decode(self.header())
    }

    /// Returns the Base64 encoded payload.
    pub fn payload(&self) -> &[u8] {
        &self.0[self.payload_start()..self.payload_end()]
    }

    /// Decode the payload bytes.
    ///
    /// The header is necessary to know how the payload is encoded.
    pub fn decode_payload(&self, header: &Header) -> Result<Cow<[u8]>, Base64DecodeError> {
        if header.base64urlencode_payload.unwrap_or(true) {
            Ok(Cow::Owned(base64::decode_config(
                self.payload(),
                base64::URL_SAFE_NO_PAD,
            )?))
        } else {
            Ok(Cow::Borrowed(self.payload()))
        }
    }

    /// Returns the Base64 encoded signature.
    pub fn signature(&self) -> &str {
        unsafe { std::str::from_utf8_unchecked(&self.0[self.signature_start()..]) }
    }

    pub fn decode_signature(&self) -> Result<Vec<u8>, Base64DecodeError> {
        base64::decode_config(self.signature(), base64::URL_SAFE_NO_PAD)
    }

    /// Decodes the entire JWS.
    pub fn decode(&self) -> Result<JWSParts, DecodeError> {
        let header = self.decode_header().map_err(DecodeError::Header)?;
        let payload = self.decode_payload(&header).map_err(DecodeError::Payload)?;
        let signature = self.decode_signature().map_err(DecodeError::Signature)?;
        Ok((header, payload, signature))
    }

    /// Returns the signing bytes.
    ///
    /// It is the concatenation of the Base64 encoded headers, a period '.' and
    /// the Base64 encoded payload.
    pub fn signing_bytes(&self) -> &[u8] {
        &self.0[..self.payload_end()]
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

pub type JWSParts<'a> = (Header, Cow<'a, [u8]>, Vec<u8>);

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("invalid header: {0}")]
    Header(InvalidHeader),

    #[error("invalid payload: {0}")]
    Payload(Base64DecodeError),

    #[error("invalid signature: {0}")]
    Signature(Base64DecodeError),
}

#[derive(Debug, thiserror::Error)]
#[error("invalid compact JWS")]
pub struct InvalidCompactJWS<B = String>(pub B);

/// JWS in UTF-8 compact serialized form.
///
/// Contrarily to [`CompactJWS`], this type guarantees that the payload is
/// a valid UTF-8 string, meaning the whole compact JWS is an UTF-8 string.
/// This does not necessarily mean the payload is base64 encoded.
#[repr(transparent)]
pub struct CompactJWSStr(CompactJWS);

impl CompactJWSStr {
    pub fn new(data: &str) -> Result<&Self, InvalidCompactJWS<&str>> {
        let inner = CompactJWS::new(data.as_bytes()).map_err(|_| InvalidCompactJWS(data))?;
        Ok(unsafe { std::mem::transmute(inner) })
    }

    /// Creates a new compact JWS without checking the data.
    ///
    /// # Safety
    ///
    /// The input `data` must represent a valid compact JWS where the payload
    /// is an UTF-8 string.
    pub unsafe fn new_unchecked(data: &[u8]) -> &Self {
        std::mem::transmute(data)
    }

    pub fn as_str(&self) -> &str {
        unsafe {
            // Safety: we already checked that the bytes are a valid UTF-8
            // string.
            std::str::from_utf8_unchecked(self.0.as_bytes())
        }
    }
}

impl Deref for CompactJWSStr {
    type Target = CompactJWS;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for CompactJWSStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(f)
    }
}

impl fmt::Debug for CompactJWSStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(f)
    }
}

impl serde::Serialize for CompactJWSStr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_str().serialize(serializer)
    }
}

/// JWS in compact serialized form.
pub struct CompactJWSBuf(Vec<u8>);

impl CompactJWSBuf {
    pub fn new(bytes: Vec<u8>) -> Result<Self, InvalidCompactJWS<Vec<u8>>> {
        if CompactJWS::check(&bytes) {
            Ok(Self(bytes))
        } else {
            Err(InvalidCompactJWS(bytes))
        }
    }

    /// # Safety
    ///
    /// The input `bytes` must represent a valid compact JWS.
    pub unsafe fn new_unchecked(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn from_signing_bytes_and_signature(
        signing_bytes: Vec<u8>,
        signature: &[u8],
    ) -> Result<Self, InvalidCompactJWS<Vec<u8>>> {
        let mut bytes = signing_bytes;
        bytes.push(b'.');
        bytes.extend(signature.iter().copied());
        Self::new(bytes)
    }

    /// Creates a new detached JWS.
    ///
    /// Detached means the payload will not appear in the JWS.
    pub fn new_detached(header: Header, signature: &[u8]) -> Self {
        let mut bytes = header.encode();
        bytes.extend([b'.', b'.']);
        bytes.extend(signature.iter().copied());
        unsafe { Self::new_unchecked(bytes) }
    }

    /// # Safety
    ///
    /// The input `signing_bytes` and `signature` must form a valid compact JWS
    /// once concatenated with a `.`.
    pub unsafe fn from_signing_bytes_and_signature_unchecked(
        signing_bytes: Vec<u8>,
        signature: Vec<u8>,
    ) -> Self {
        let mut bytes = signing_bytes;
        bytes.push(b'.');
        bytes.extend(signature);
        Self::new_unchecked(bytes)
    }

    pub fn as_compact_jws(&self) -> &CompactJWS {
        unsafe { CompactJWS::new_unchecked(&self.0) }
    }

    pub fn into_signing_bytes(mut self) -> Vec<u8> {
        self.0.truncate(self.payload_end()); // remove the signature.
        self.0
    }
}

impl Deref for CompactJWSBuf {
    type Target = CompactJWS;

    fn deref(&self) -> &Self::Target {
        self.as_compact_jws()
    }
}

/// JWS in compact serialized form, with a base64 payload.
///
/// Contrarily to [`CompactJWS`], this type guarantees that the payload is
/// a valid UTF-8 string, meaning the whole compact JWS is an UTF-8 string.
/// This does not necessarily mean the payload is base64 encoded.
#[derive(Clone, serde::Serialize)]
#[serde(transparent)]
pub struct CompactJWSString(String);

impl CompactJWSString {
    pub fn new(bytes: Vec<u8>) -> Result<Self, InvalidCompactJWS<Vec<u8>>> {
        match String::from_utf8(bytes) {
            Ok(string) => {
                if CompactJWS::check(string.as_bytes()) {
                    Ok(Self(string))
                } else {
                    Err(InvalidCompactJWS(string.into_bytes()))
                }
            }
            Err(e) => Err(InvalidCompactJWS(e.into_bytes())),
        }
    }

    pub fn from_string(string: String) -> Result<Self, InvalidCompactJWS<String>> {
        if CompactJWS::check(string.as_bytes()) {
            Ok(Self(string))
        } else {
            Err(InvalidCompactJWS(string))
        }
    }

    /// # Safety
    ///
    /// The input `bytes` must represent a valid compact JWS where the payload
    /// is UTF-8 encoded.
    pub unsafe fn new_unchecked(bytes: Vec<u8>) -> Self {
        Self(String::from_utf8_unchecked(bytes))
    }

    pub fn from_signing_bytes_and_signature(
        signing_bytes: Vec<u8>,
        signature: impl IntoIterator<Item = u8>,
    ) -> Result<Self, InvalidCompactJWS<Vec<u8>>> {
        let mut bytes = signing_bytes;
        bytes.push(b'.');
        bytes.extend(signature);
        Self::new(bytes)
    }

    /// Creates a new detached JWS from a header and base64-encoded signature.
    ///
    /// Detached means the payload will not appear in the JWS.
    pub fn new_detached(
        header: Header,
        b64_signature: &[u8],
    ) -> Result<Self, InvalidCompactJWS<Vec<u8>>> {
        let mut bytes = header.encode();
        bytes.extend(b"..");
        bytes.extend(b64_signature.iter().copied());
        Self::new(bytes)
    }

    /// Creates a new detached JWS from a header and unencoded signature.
    ///
    /// Detached means the payload will not appear in the JWS.
    pub fn encode_detached(header: Header, signature: &[u8]) -> Self {
        let b64_signature = base64::encode_config(signature, base64::URL_SAFE_NO_PAD);
        Self::new_detached(header, b64_signature.as_bytes()).unwrap()
    }

    /// # Safety
    ///
    /// The input `signing_bytes` and `signature` must form a valid compact JWS
    /// once concatenated with a `.`.
    pub unsafe fn from_signing_bytes_and_signature_unchecked(
        signing_bytes: Vec<u8>,
        signature: Vec<u8>,
    ) -> Self {
        let mut bytes = signing_bytes;
        bytes.push(b'.');
        bytes.extend(signature);
        Self::new_unchecked(bytes)
    }

    pub fn as_compact_jws_str(&self) -> &CompactJWSStr {
        unsafe { CompactJWSStr::new_unchecked(self.0.as_bytes()) }
    }

    pub fn into_signing_bytes(mut self) -> String {
        self.0.truncate(self.payload_end()); // remove the signature.
        self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl Deref for CompactJWSString {
    type Target = CompactJWSStr;

    fn deref(&self) -> &Self::Target {
        self.as_compact_jws_str()
    }
}

impl fmt::Display for CompactJWSString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(f)
    }
}

impl fmt::Debug for CompactJWSString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(f)
    }
}

impl FromStr for CompactJWSString {
    type Err = InvalidCompactJWS;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_string(s.to_owned())
    }
}

impl<V: Vocabulary, I: Interpretation> LinkedDataResource<I, V> for CompactJWSString {
    fn interpretation(
        &self,
        _vocabulary: &mut V,
        _interpretation: &mut I,
    ) -> linked_data::ResourceInterpretation<I, V> {
        use linked_data::{xsd_types::ValueRef, CowRdfTerm, RdfLiteralRef, ResourceInterpretation};
        ResourceInterpretation::Uninterpreted(Some(CowRdfTerm::Borrowed(RdfTermRef::Literal(
            RdfLiteralRef::Xsd(ValueRef::String(&self.0)),
        ))))
    }
}

impl<V: Vocabulary, I: Interpretation> LinkedDataSubject<I, V> for CompactJWSString {
    fn visit_subject<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: linked_data::SubjectVisitor<I, V>,
    {
        serializer.end()
    }
}

impl<V: Vocabulary, I: Interpretation> LinkedDataDeserializeSubject<I, V> for CompactJWSString
where
    V: linked_data::rdf_types::Vocabulary<Type = linked_data::rdf_types::literal::Type<<V as linked_data::rdf_types::IriVocabulary>::Iri, <V as linked_data::rdf_types::LanguageTagVocabulary>::LanguageTag>>,
    V::Value: AsRef<str>,
    I: linked_data::rdf_types::ReverseLiteralInterpretation<Literal = V::Literal>
{
    fn deserialize_subject<D>(
        vocabulary: &V,
        interpretation: &I,
        _dataset: &D,
        _graph: &D::Graph,
        resource: &I::Resource,
    ) -> Result<Self, linked_data::FromLinkedDataError>
    where
        D: linked_data::grdf::Dataset<
            Subject = I::Resource,
            Predicate = I::Resource,
            Object = I::Resource,
            GraphLabel = I::Resource,
        >
    {
        use linked_data::rdf_types::literal;
        let mut is_literal = false;

        for l in interpretation.literals_of(resource) {
            is_literal = true;
            let literal = vocabulary.literal(l).unwrap();
            if let literal::Type::Any(ty) = literal.type_() {
                if let Some(ty_iri) = vocabulary.iri(ty) {
                    if ty_iri == linked_data::xsd_types::XSD_STRING {
                        return literal.value().as_ref().parse().map_err(|_| linked_data::FromLinkedDataError::InvalidLiteral)
                    }
                }
            }
        }

        if is_literal {
            Err(linked_data::FromLinkedDataError::LiteralTypeMismatch)
        } else {
            Err(linked_data::FromLinkedDataError::ExpectedLiteral)
        }
    }
}

impl<V: Vocabulary, I: Interpretation> LinkedDataPredicateObjects<I, V> for CompactJWSString {
    fn visit_objects<S>(&self, mut visitor: S) -> Result<S::Ok, S::Error>
    where
        S: linked_data::PredicateObjectsVisitor<I, V>,
    {
        visitor.object(self)?;
        visitor.end()
    }
}

impl<V: Vocabulary, I: Interpretation> LinkedDataDeserializePredicateObjects<I, V> for CompactJWSString
where
    V: linked_data::rdf_types::Vocabulary<Type = linked_data::rdf_types::literal::Type<<V as linked_data::rdf_types::IriVocabulary>::Iri, <V as linked_data::rdf_types::LanguageTagVocabulary>::LanguageTag>>,
    V::Value: AsRef<str>,
    I: linked_data::rdf_types::ReverseLiteralInterpretation<Literal = V::Literal>
{
    fn deserialize_objects<'a, D>(
        vocabulary: &V,
        interpretation: &I,
        dataset: &D,
        graph: &D::Graph,
        objects: impl IntoIterator<Item = &'a I::Resource>,
    ) -> Result<Self, linked_data::FromLinkedDataError>
    where
        I::Resource: 'a,
        D: linked_data::grdf::Dataset<
            Subject = I::Resource,
            Predicate = I::Resource,
            Object = I::Resource,
            GraphLabel = I::Resource,
        >
    {
        let mut objects = objects.into_iter();
        match objects.next() {
            Some(object) => {
                if objects.next().is_none() {
                    Self::deserialize_subject(vocabulary, interpretation, dataset, graph, object)
                } else {
                    Err(linked_data::FromLinkedDataError::TooManyValues)
                }
            }
            None => {
                Err(linked_data::FromLinkedDataError::MissingRequiredValue)
            }
        }
    }
}

impl<'de> serde::Deserialize<'de> for CompactJWSString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = CompactJWSString;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("compact JWS")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_string(v.to_owned())
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                CompactJWSString::from_string(v).map_err(|e| E::custom(e))
            }
        }

        deserializer.deserialize_string(Visitor)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
pub struct Header {
    #[serde(rename = "alg")]
    pub algorithm: Algorithm,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "jku")]
    pub jwk_set_url: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwk: Option<JWK>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "kid")]
    pub key_id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "x5u")]
    pub x509_url: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "x5c")]
    pub x509_certificate_chain: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "x5t")]
    pub x509_thumbprint_sha1: Option<Base64urlUInt>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "x5t#S256")]
    pub x509_thumbprint_sha256: Option<Base64urlUInt>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "typ")]
    pub type_: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "cty")]
    pub content_type: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "crit")]
    pub critical: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "b64")]
    pub base64urlencode_payload: Option<bool>,

    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    #[serde(flatten)]
    pub additional_parameters: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, thiserror::Error)]
pub enum InvalidHeader {
    #[error(transparent)]
    Base64(Base64DecodeError),

    #[error(transparent)]
    Json(serde_json::Error),
}

impl From<Base64DecodeError> for InvalidHeader {
    fn from(value: Base64DecodeError) -> Self {
        InvalidHeader::Base64(value)
    }
}

impl From<serde_json::Error> for InvalidHeader {
    fn from(value: serde_json::Error) -> Self {
        InvalidHeader::Json(value)
    }
}

impl Header {
    /// Create a new header for a JWS with detached payload.
    ///
    /// Unencoded means the payload will not be base64 encoded
    /// when the `encode_signing_bytes` function is called.
    /// This is done by setting the `b64` header parameter to `true`,
    /// while adding `b64` to the list of critical parameters the
    /// receiver must understand to decode the JWS.
    pub fn new_unencoded(algorithm: Algorithm, key_id: Option<String>) -> Self {
        Self {
            algorithm,
            key_id,
            base64urlencode_payload: Some(false),
            critical: Some(vec!["b64".to_string()]),
            ..Default::default()
        }
    }

    /// Decode a JWS Protected Header.
    pub fn decode(base_64: &[u8]) -> Result<Self, InvalidHeader> {
        let header_json = base64::decode_config(base_64, base64::URL_SAFE_NO_PAD)?;
        Ok(serde_json::from_slice(&header_json)?)
    }

    pub fn to_json_string(&self) -> String {
        serde_json::to_string(self).unwrap()
    }

    pub fn encode(&self) -> Vec<u8> {
        base64::encode_config(self.to_json_string(), base64::URL_SAFE_NO_PAD).into_bytes()
    }

    pub fn encode_signing_bytes(&self, payload: &[u8]) -> Vec<u8> {
        let mut result = self.encode();
        result.push(b'.');

        if self.base64urlencode_payload.unwrap_or(true) {
            let encoded_payload = base64::encode_config(payload, base64::URL_SAFE_NO_PAD);
            result.extend(encoded_payload.into_bytes())
        } else {
            result.extend(payload)
        }

        result
    }
}

fn base64_encode_json<T: Serialize>(object: &T) -> Result<String, Error> {
    let json = serde_json::to_string(&object)?;
    Ok(base64::encode_config(json, base64::URL_SAFE_NO_PAD))
}

#[allow(unreachable_code, unused_variables)]
pub fn sign_bytes(algorithm: Algorithm, data: &[u8], key: &JWK) -> Result<Vec<u8>, Error> {
    let signature = match &key.params {
        #[cfg(feature = "ring")]
        JWKParams::RSA(rsa_params) => {
            rsa_params.validate_key_size()?;
            let key_pair = ring::signature::RsaKeyPair::try_from(rsa_params)?;
            let padding_alg: &dyn ring::signature::RsaEncoding = match algorithm {
                Algorithm::RS256 => &ring::signature::RSA_PKCS1_SHA256,
                Algorithm::PS256 => &ring::signature::RSA_PSS_SHA256,
                _ => return Err(Error::AlgorithmNotImplemented),
            };
            let mut sig = vec![0u8; key_pair.public_modulus_len()];
            let rng = ring::rand::SystemRandom::new();
            key_pair.sign(padding_alg, &rng, data, &mut sig)?;
            sig
        }
        #[cfg(feature = "rsa")]
        JWKParams::RSA(rsa_params) => {
            rsa_params.validate_key_size()?;
            let private_key = rsa::RsaPrivateKey::try_from(rsa_params)?;
            let padding;
            let hashed;
            match algorithm {
                Algorithm::RS256 => {
                    let hash = rsa::hash::Hash::SHA2_256;
                    padding = rsa::padding::PaddingScheme::new_pkcs1v15_sign(Some(hash));
                    hashed = ssi_crypto::hashes::sha256::sha256(data);
                }
                Algorithm::PS256 => {
                    let hash = rsa::hash::Hash::SHA2_256;
                    let rng = rand::rngs::OsRng {};
                    padding =
                        rsa::PaddingScheme::new_pss_with_salt::<sha2::Sha256, _>(rng, hash.size());
                    hashed = ssi_crypto::hashes::sha256::sha256(data);
                }
                _ => return Err(Error::AlgorithmNotImplemented),
            }
            private_key
                .sign(padding, &hashed)
                .map_err(ssi_jwk::Error::from)?
        }
        #[cfg(any(feature = "ring", feature = "ed25519"))]
        JWKParams::OKP(okp) => {
            use blake2::digest::{consts::U32, Digest};
            if algorithm != Algorithm::EdDSA && algorithm != Algorithm::EdBlake2b {
                return Err(Error::UnsupportedAlgorithm);
            }
            if okp.curve != *"Ed25519" {
                return Err(ssi_jwk::Error::CurveNotImplemented(okp.curve.to_string()).into());
            }
            let hash = match algorithm {
                Algorithm::EdBlake2b => <blake2::Blake2b<U32> as Digest>::new_with_prefix(data)
                    .finalize()
                    .to_vec(),
                _ => data.to_vec(),
            };
            #[cfg(feature = "ring")]
            {
                let key_pair = ring::signature::Ed25519KeyPair::try_from(okp)?;
                key_pair.sign(&hash).as_ref().to_vec()
            }
            // TODO: SymmetricParams
            #[cfg(all(feature = "ed25519", not(feature = "ring")))]
            {
                let keypair = ed25519_dalek::Keypair::try_from(okp)?;
                use ed25519_dalek::Signer;
                keypair.sign(&hash).to_bytes().to_vec()
            }
        }
        #[allow(unused)]
        JWKParams::EC(ec) => {
            match algorithm {
                #[cfg(feature = "p384")]
                Algorithm::ES384 => {
                    use p384::ecdsa::signature::{Signature, Signer};
                    let curve = ec.curve.as_ref().ok_or(ssi_jwk::Error::MissingCurve)?;
                    let secret_key = p384::SecretKey::try_from(ec)?;
                    let signing_key = p384::ecdsa::SigningKey::from(secret_key);
                    let sig: p384::ecdsa::Signature =
                        signing_key.try_sign(data).map_err(ssi_jwk::Error::from)?;
                    sig.as_bytes().to_vec()
                }
                #[cfg(feature = "p256")]
                Algorithm::ES256 => {
                    use p256::ecdsa::signature::{Signature, Signer};
                    let curve = ec.curve.as_ref().ok_or(ssi_jwk::Error::MissingCurve)?;
                    let secret_key = p256::SecretKey::try_from(ec)?;
                    let signing_key = p256::ecdsa::SigningKey::from(secret_key);
                    let sig: p256::ecdsa::Signature =
                        signing_key.try_sign(data).map_err(ssi_jwk::Error::from)?;
                    sig.as_bytes().to_vec()
                }
                #[cfg(feature = "secp256k1")]
                Algorithm::ES256K => {
                    use k256::ecdsa::signature::{Signature, Signer};
                    let curve = ec.curve.as_ref().ok_or(ssi_jwk::Error::MissingCurve)?;
                    let secret_key = k256::SecretKey::try_from(ec)?;
                    let signing_key = k256::ecdsa::SigningKey::from(secret_key);
                    let sig: k256::ecdsa::Signature =
                        signing_key.try_sign(data).map_err(ssi_jwk::Error::from)?;
                    sig.as_bytes().to_vec()
                }
                #[cfg(feature = "secp256k1")]
                Algorithm::ES256KR => {
                    use k256::ecdsa::signature::{digest::Digest, DigestSigner, Signature, Signer};
                    let curve = ec.curve.as_ref().ok_or(Error::MissingCurve)?;
                    let secret_key = k256::SecretKey::try_from(ec)?;
                    let signing_key = k256::ecdsa::SigningKey::from(secret_key);
                    let sig: k256::ecdsa::recoverable::Signature = signing_key
                        .try_sign_digest(<sha2::Sha256 as Digest>::new_with_prefix(data))?;
                    sig.as_bytes().to_vec()
                }
                #[cfg(feature = "secp256k1")]
                Algorithm::ESKeccakKR => {
                    use k256::ecdsa::signature::{Signature, Signer};
                    let curve = ec.curve.as_ref().ok_or(ssi_jwk::Error::MissingCurve)?;
                    let secret_key = k256::SecretKey::try_from(ec)?;
                    let signing_key = k256::ecdsa::SigningKey::from(secret_key);
                    let sig: k256::ecdsa::recoverable::Signature =
                        signing_key.try_sign(data).map_err(ssi_jwk::Error::from)?;
                    sig.as_bytes().to_vec()
                }
                #[cfg(feature = "p256")]
                Algorithm::ESBlake2b => {
                    use p256::ecdsa::signature::{
                        digest::{consts::U32, Digest},
                        DigestSigner, Signature,
                    };
                    let curve = ec.curve.as_ref().ok_or(Error::MissingCurve)?;
                    let secret_key = p256::SecretKey::try_from(ec)?;
                    let signing_key = p256::ecdsa::SigningKey::from(secret_key);
                    let sig: p256::ecdsa::Signature = signing_key
                        .try_sign_digest(<blake2::Blake2b<U32> as Digest>::new_with_prefix(data))?;
                    sig.as_bytes().to_vec()
                }
                #[cfg(feature = "secp256k1")]
                Algorithm::ESBlake2bK => {
                    use k256::ecdsa::signature::{
                        digest::{consts::U32, Digest},
                        DigestSigner, Signature,
                    };
                    let curve = ec.curve.as_ref().ok_or(Error::MissingCurve)?;
                    let secret_key = k256::SecretKey::try_from(ec)?;
                    let signing_key = k256::ecdsa::SigningKey::from(secret_key);
                    let sig: k256::ecdsa::Signature = signing_key
                        .try_sign_digest(<blake2::Blake2b<U32> as Digest>::new_with_prefix(data))?;
                    sig.as_bytes().to_vec()
                }
                _ => {
                    return Err(Error::UnsupportedAlgorithm);
                }
            }
        }
        _ => return Err(Error::JWK(ssi_jwk::Error::KeyTypeNotImplemented)),
    };
    clear_on_drop::clear_stack(1);
    Ok(signature)
}

pub fn sign_bytes_b64(algorithm: Algorithm, data: &[u8], key: &JWK) -> Result<String, Error> {
    let signature = sign_bytes(algorithm, data, key)?;
    let sig_b64 = base64::encode_config(signature, base64::URL_SAFE_NO_PAD);
    Ok(sig_b64)
}

#[allow(unreachable_code, unused_variables, unused_mut)]
pub fn verify_bytes_warnable(
    algorithm: Algorithm,
    data: &[u8],
    key: &JWK,
    signature: &[u8],
) -> Result<VerificationWarnings, Error> {
    let mut warnings = VerificationWarnings::default();
    if let Some(key_algorithm) = key.algorithm {
        if key_algorithm != algorithm
            && !(key_algorithm == Algorithm::EdDSA && algorithm == Algorithm::EdBlake2b)
            && !(key_algorithm == Algorithm::ES256 && algorithm == Algorithm::ESBlake2b)
            && !(key_algorithm == Algorithm::ES256K && algorithm == Algorithm::ESBlake2bK)
            && !(key_algorithm == Algorithm::ES256KR && algorithm == Algorithm::ESBlake2bK)
        {
            return Err(Error::AlgorithmMismatch);
        }
    }
    match &key.params {
        #[cfg(feature = "ring")]
        JWKParams::RSA(rsa_params) => {
            rsa_params.validate_key_size()?;
            use ring::signature::RsaPublicKeyComponents;
            let public_key = RsaPublicKeyComponents::try_from(rsa_params)?;
            let parameters = match algorithm {
                Algorithm::RS256 => &ring::signature::RSA_PKCS1_2048_8192_SHA256,
                Algorithm::PS256 => &ring::signature::RSA_PSS_2048_8192_SHA256,
                _ => return Err(Error::AlgorithmNotImplemented),
            };
            public_key.verify(parameters, data, signature)?
        }
        #[cfg(feature = "rsa")]
        JWKParams::RSA(rsa_params) => {
            rsa_params.validate_key_size()?;
            use rsa::PublicKey;
            let public_key =
                rsa::RsaPublicKey::try_from(rsa_params).map_err(ssi_jwk::Error::from)?;
            let padding;
            let hashed;
            match algorithm {
                Algorithm::RS256 => {
                    let hash = rsa::hash::Hash::SHA2_256;
                    padding = rsa::padding::PaddingScheme::new_pkcs1v15_sign(Some(hash));
                    hashed = ssi_crypto::hashes::sha256::sha256(data);
                }
                Algorithm::PS256 => {
                    let rng = rand::rngs::OsRng {};
                    padding = rsa::PaddingScheme::new_pss::<sha2::Sha256, _>(rng);
                    hashed = ssi_crypto::hashes::sha256::sha256(data);
                }
                _ => return Err(Error::AlgorithmNotImplemented),
            }
            public_key
                .verify(padding, &hashed, signature)
                .map_err(ssi_jwk::Error::from)?;
        }
        // TODO: SymmetricParams
        #[cfg(any(feature = "ring", feature = "ed25519"))]
        JWKParams::OKP(okp) => {
            use blake2::digest::{consts::U32, Digest};
            if okp.curve != *"Ed25519" {
                return Err(ssi_jwk::Error::CurveNotImplemented(okp.curve.to_string()).into());
            }
            let hash = match algorithm {
                Algorithm::EdBlake2b => <blake2::Blake2b<U32> as Digest>::new_with_prefix(data)
                    .finalize()
                    .to_vec(),
                _ => data.to_vec(),
            };
            #[cfg(feature = "ring")]
            {
                use ring::signature::UnparsedPublicKey;
                let verification_algorithm = &ring::signature::ED25519;
                let public_key = UnparsedPublicKey::new(verification_algorithm, &okp.public_key.0);
                public_key.verify(&hash, signature)?;
            }
            #[cfg(feature = "ed25519")]
            {
                use ed25519_dalek::Verifier;
                let public_key = ed25519_dalek::PublicKey::try_from(okp)?;
                let signature = ed25519_dalek::Signature::from_bytes(signature)
                    .map_err(ssi_jwk::Error::from)?;
                public_key
                    .verify(&hash, &signature)
                    .map_err(ssi_jwk::Error::from)?;
            }
        }
        #[allow(unused)]
        JWKParams::EC(ec) => match algorithm {
            #[cfg(feature = "p256")]
            Algorithm::ES256 => {
                use p256::ecdsa::signature::Verifier;
                let curve = ec.curve.as_ref().ok_or(ssi_jwk::Error::MissingCurve)?;
                let public_key = p256::PublicKey::try_from(ec)?;
                let verifying_key = p256::ecdsa::VerifyingKey::from(public_key);
                let sig =
                    p256::ecdsa::Signature::try_from(signature).map_err(ssi_jwk::Error::from)?;
                verifying_key
                    .verify(data, &sig)
                    .map_err(ssi_jwk::Error::from)?;
            }
            #[cfg(feature = "secp256k1")]
            Algorithm::ES256K => {
                use k256::ecdsa::signature::Verifier;
                let curve = ec.curve.as_ref().ok_or(ssi_jwk::Error::MissingCurve)?;
                let public_key = k256::PublicKey::try_from(ec)?;
                let verifying_key = k256::ecdsa::VerifyingKey::from(public_key);
                let sig =
                    k256::ecdsa::Signature::try_from(signature).map_err(ssi_jwk::Error::from)?;
                let normalized_sig = if let Some(s) = sig.normalize_s() {
                    // For user convenience, output the normalized signature.
                    let sig_normalized_b64 = base64::encode_config(s, base64::URL_SAFE_NO_PAD);
                    warnings.push(format!(
                        "Non-normalized ES256K signature. Normalized: {}",
                        sig_normalized_b64
                    ));
                    s
                } else {
                    sig
                };
                verifying_key
                    .verify(data, &normalized_sig)
                    .map_err(ssi_jwk::Error::from)?;
            }
            #[cfg(feature = "secp256k1")]
            Algorithm::ES256KR => {
                use k256::ecdsa::signature::{
                    digest::{consts::U32, Digest},
                    DigestVerifier, Verifier,
                };
                let curve = ec.curve.as_ref().ok_or(ssi_jwk::Error::MissingCurve)?;
                let public_key = k256::PublicKey::try_from(ec)?;
                let verifying_key = k256::ecdsa::VerifyingKey::from(public_key);
                let sig = k256::ecdsa::recoverable::Signature::try_from(signature)
                    .map_err(ssi_jwk::Error::from)?;
                if let Err(_e) = verifying_key
                    .verify_digest(<sha2::Sha256 as Digest>::new_with_prefix(data), &sig)
                {
                    // Legacy mode: allow using Keccak-256 instead of SHA-256
                    verify_bytes(Algorithm::ESKeccakKR, data, key, signature)?;
                    warnings
                        .push("Signature uses legacy mode ES256K-R with Keccak-256".to_string());
                }
            }
            #[cfg(feature = "eip")]
            Algorithm::ESKeccakKR => {
                use k256::ecdsa::signature::Verifier;
                let curve = ec.curve.as_ref().ok_or(ssi_jwk::Error::MissingCurve)?;
                let public_key = k256::PublicKey::try_from(ec)?;
                let verifying_key = k256::ecdsa::VerifyingKey::from(public_key);
                let sig = k256::ecdsa::recoverable::Signature::try_from(signature)
                    .map_err(ssi_jwk::Error::from)?;
                verifying_key
                    .verify(data, &sig)
                    .map_err(ssi_jwk::Error::from)?;
            }
            #[cfg(feature = "p256")]
            Algorithm::ESBlake2b => {
                use p256::ecdsa::signature::{
                    digest::{consts::U32, Digest},
                    DigestVerifier, Signature,
                };
                let curve = ec.curve.as_ref().ok_or(ssi_jwk::Error::MissingCurve)?;
                let public_key = p256::PublicKey::try_from(ec)?;
                let verifying_key = p256::ecdsa::VerifyingKey::from(public_key);
                let sig =
                    p256::ecdsa::Signature::try_from(signature).map_err(ssi_jwk::Error::from)?;
                verifying_key
                    .verify_digest(
                        <blake2::Blake2b<U32> as Digest>::new_with_prefix(data),
                        &sig,
                    )
                    .map_err(ssi_jwk::Error::from)?;
            }
            #[cfg(feature = "secp256k1")]
            Algorithm::ESBlake2bK => {
                use k256::ecdsa::signature::{
                    digest::{consts::U32, Digest},
                    DigestVerifier,
                };
                let curve = ec.curve.as_ref().ok_or(ssi_jwk::Error::MissingCurve)?;
                let public_key = k256::PublicKey::try_from(ec)?;
                let verifying_key = k256::ecdsa::VerifyingKey::from(public_key);
                let sig =
                    k256::ecdsa::Signature::try_from(signature).map_err(ssi_jwk::Error::from)?;
                verifying_key
                    .verify_digest(
                        <blake2::Blake2b<U32> as Digest>::new_with_prefix(data),
                        &sig,
                    )
                    .map_err(ssi_jwk::Error::from)?;
            }
            #[cfg(feature = "secp384r1")]
            Algorithm::ES384 => {
                use p384::ecdsa::signature::Verifier;
                let curve = ec.curve.as_ref().ok_or(ssi_jwk::Error::MissingCurve)?;
                let public_key = p384::PublicKey::try_from(ec)?;
                let verifying_key = p384::ecdsa::VerifyingKey::from(public_key);
                let sig =
                    p384::ecdsa::Signature::try_from(signature).map_err(ssi_jwk::Error::from)?;
                verifying_key
                    .verify(data, &sig)
                    .map_err(ssi_jwk::Error::from)?;
            }
            _ => {
                return Err(Error::UnsupportedAlgorithm);
            }
        },
        _ => return Err(Error::JWK(ssi_jwk::Error::KeyTypeNotImplemented)),
    }
    Ok(warnings)
}

pub fn verify_bytes(
    algorithm: Algorithm,
    data: &[u8],
    key: &JWK,
    signature: &[u8],
) -> Result<(), Error> {
    verify_bytes_warnable(algorithm, data, key, signature)?;
    Ok(())
}

/// Recover a key from a signature and message, if the algorithm supports this.  (e.g.
/// [ES256K-R](https://github.com/decentralized-identity/EcdsaSecp256k1RecoverySignature2020#es256k-r))
pub fn recover(algorithm: Algorithm, data: &[u8], signature: &[u8]) -> Result<JWK, Error> {
    match algorithm {
        #[cfg(feature = "secp256k1")]
        Algorithm::ES256KR => {
            let sig = k256::ecdsa::recoverable::Signature::try_from(signature)
                .map_err(ssi_jwk::Error::from)?;
            let hash = ssi_crypto::hashes::sha256::sha256(data);
            let digest = k256::elliptic_curve::FieldBytes::<k256::Secp256k1>::from_slice(&hash);
            let recovered_key = sig
                .recover_verifying_key_from_digest_bytes(digest)
                .map_err(ssi_jwk::Error::from)?;
            use ssi_jwk::ECParams;
            let jwk = JWK {
                params: JWKParams::EC(ECParams::try_from(
                    &k256::PublicKey::from_sec1_bytes(&recovered_key.to_bytes())
                        .map_err(ssi_jwk::Error::from)?,
                )?),
                public_key_use: None,
                key_operations: None,
                algorithm: None,
                key_id: None,
                x509_url: None,
                x509_certificate_chain: None,
                x509_thumbprint_sha1: None,
                x509_thumbprint_sha256: None,
            };
            Ok(jwk)
        }
        #[cfg(feature = "secp256k1")]
        Algorithm::ESKeccakKR => {
            let sig = k256::ecdsa::recoverable::Signature::try_from(signature)
                .map_err(ssi_jwk::Error::from)?;
            let recovered_key = sig
                .recover_verifying_key(data)
                .map_err(ssi_jwk::Error::from)?;
            use ssi_jwk::ECParams;
            let jwk = JWK::from(JWKParams::EC(ECParams::try_from(
                &k256::PublicKey::from_sec1_bytes(&recovered_key.to_bytes())
                    .map_err(ssi_jwk::Error::from)?,
            )?));
            Ok(jwk)
        }
        _ => {
            let _ = data;
            let _ = signature;
            Err(Error::UnsupportedAlgorithm)
        }
    }
}

pub fn detached_sign_unencoded_payload(
    algorithm: Algorithm,
    payload: &[u8],
    key: &JWK,
) -> Result<String, Error> {
    let header = Header {
        algorithm,
        key_id: key.key_id.clone(),
        critical: Some(vec!["b64".to_string()]),
        base64urlencode_payload: Some(false),
        ..Default::default()
    };
    let header_b64 = base64_encode_json(&header)?;
    let signing_input = [header_b64.as_bytes(), b".", payload].concat();
    let sig_b64 = sign_bytes_b64(header.algorithm, &signing_input, key)?;
    let jws = header_b64 + ".." + &sig_b64;
    Ok(jws)
}

pub fn prepare_detached_unencoded_payload(
    algorithm: Algorithm,
    payload: &[u8],
) -> Result<(Header, Vec<u8>), Error> {
    let header = Header {
        algorithm,
        critical: Some(vec!["b64".to_string()]),
        base64urlencode_payload: Some(false),
        ..Default::default()
    };
    let header_b64 = base64_encode_json(&header)?;
    let signing_input = [header_b64.as_bytes(), b".", payload].concat().to_vec();
    Ok((header, signing_input))
}

pub fn complete_sign_unencoded_payload(header: &Header, sig_b64: &str) -> Result<String, Error> {
    let header_b64 = base64_encode_json(header)?;
    let jws = header_b64 + ".." + sig_b64;
    Ok(jws)
}

pub fn encode_sign(algorithm: Algorithm, payload: &str, key: &JWK) -> Result<String, Error> {
    let header = Header {
        algorithm,
        key_id: key.key_id.clone(),
        ..Default::default()
    };
    encode_sign_custom_header(payload, key, &header)
}

pub fn encode_sign_custom_header(
    payload: &str,
    key: &JWK,
    header: &Header,
) -> Result<String, Error> {
    let header_b64 = base64_encode_json(header)?;
    let payload_b64 = base64::encode_config(payload, base64::URL_SAFE_NO_PAD);
    let signing_input = header_b64 + "." + &payload_b64;
    let sig_b64 = sign_bytes_b64(header.algorithm, signing_input.as_bytes(), key)?;
    let jws = [signing_input, sig_b64].join(".");
    Ok(jws)
}

pub fn encode_unsigned(payload: &str) -> Result<String, Error> {
    let header = Header {
        algorithm: Algorithm::None,
        ..Default::default()
    };
    let header_b64 = base64_encode_json(&header)?;
    let payload_b64 = base64::encode_config(payload, base64::URL_SAFE_NO_PAD);
    Ok(header_b64 + "." + &payload_b64 + ".")
}

pub fn split_jws(jws: &str) -> Result<(&str, &str, &str), Error> {
    let mut parts = jws.splitn(3, '.');
    Ok(
        match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(a), Some(b), Some(c), None) => (a, b, c),
            _ => return Err(Error::InvalidJWS),
        },
    )
}

pub fn split_detached_jws(jws: &str) -> Result<(&str, &str), Error> {
    let (header_b64, omitted_payload, signature_b64) = split_jws(jws)?;
    if !omitted_payload.is_empty() {
        return Err(Error::InvalidJWS);
    }
    Ok((header_b64, signature_b64))
}

#[derive(Clone, PartialEq, Eq)]
pub struct DecodedJWS {
    pub header: Header,
    pub signing_input: Vec<u8>,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Decode JWS parts (JOSE header, payload, and signature) into useful values.
/// The payload argument is bytes since it may be unencoded if the b64:false header parameter is used; otherwise it must be a base64url-encoded string. Header and signature are always expected to be base64url-encoded.
/// "crit" (critical) header parameters are checked and disallowed if unrecognized/unsupported.
pub fn decode_jws_parts(
    header_b64: &str,
    payload_enc: &[u8],
    signature_b64: &str,
) -> Result<DecodedJWS, Error> {
    let signature = base64::decode_config(signature_b64, base64::URL_SAFE_NO_PAD)?;
    let header = Header::decode(header_b64.as_bytes())?;
    let payload = if header.base64urlencode_payload.unwrap_or(true) {
        base64::decode_config(payload_enc, base64::URL_SAFE_NO_PAD)?
    } else {
        payload_enc.to_vec()
    };
    for name in header.critical.iter().flatten() {
        match name.as_str() {
            "alg" | "jku" | "jwk" | "kid" | "x5u" | "x5c" | "x5t" | "x5t#S256" | "typ" | "cty"
            | "crit" => return Err(Error::InvalidCriticalHeader),
            "b64" => {}
            _ => return Err(Error::UnknownCriticalHeader),
        }
    }
    let signing_input = [header_b64.as_bytes(), b".", payload_enc].concat();
    Ok(DecodedJWS {
        header,
        signing_input,
        payload,
        signature,
    })
}

/// Verify a JWS with detached payload. Returns the JWS header on success.
pub fn detached_verify(jws: &str, payload_enc: &[u8], key: &JWK) -> Result<Header, Error> {
    let (header_b64, signature_b64) = split_detached_jws(jws)?;
    let DecodedJWS {
        header,
        signing_input,
        payload: _,
        signature,
    } = decode_jws_parts(header_b64, payload_enc, signature_b64)?;
    verify_bytes(header.algorithm, &signing_input, key, &signature)?;
    Ok(header)
}

/// Recover a JWK from a JWS and payload, if the algorithm supports that (such as [ES256K-R](https://github.com/decentralized-identity/EcdsaSecp256k1RecoverySignature2020#es256k-r)).
pub fn detached_recover(jws: &str, payload_enc: &[u8]) -> Result<(Header, JWK), Error> {
    let (header_b64, signature_b64) = split_detached_jws(jws)?;
    let DecodedJWS {
        header,
        signing_input,
        payload: _,
        signature,
    } = decode_jws_parts(header_b64, payload_enc, signature_b64)?;
    let key = recover(header.algorithm, &signing_input, &signature)?;
    Ok((header, key))
}

pub fn detached_recover_legacy_keccak_es256kr(
    jws: &str,
    payload_enc: &[u8],
) -> Result<(Header, JWK), Error> {
    let (header_b64, signature_b64) = split_detached_jws(jws)?;
    let DecodedJWS {
        mut header,
        signing_input,
        payload: _,
        signature,
    } = decode_jws_parts(header_b64, payload_enc, signature_b64)?;
    // Allow ESKeccakK-R misimplementation of ES256K-R, for legacy reasons.
    if header.algorithm != Algorithm::ES256KR {
        return Err(Error::AlgorithmMismatch);
    }
    header.algorithm = Algorithm::ESKeccakKR;
    let key = recover(header.algorithm, &signing_input, &signature)?;
    Ok((header, key))
}

pub fn decode_verify(jws: &str, key: &JWK) -> Result<(Header, Vec<u8>), Error> {
    let (header_b64, payload_enc, signature_b64) = split_jws(jws)?;
    let DecodedJWS {
        header,
        signing_input,
        payload,
        signature,
    } = decode_jws_parts(header_b64, payload_enc.as_bytes(), signature_b64)?;
    verify_bytes(header.algorithm, &signing_input, key, &signature)?;
    Ok((header, payload))
}

pub fn decode_unverified(jws: &str) -> Result<(Header, Vec<u8>), Error> {
    let (header_b64, payload_enc, signature_b64) = split_jws(jws)?;
    let DecodedJWS {
        header,
        signing_input: _,
        payload,
        signature: _,
    } = decode_jws_parts(header_b64, payload_enc.as_bytes(), signature_b64)?;
    Ok((header, payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "rsa")]
    fn jws_encode() {
        // https://tools.ietf.org/html/rfc7515#appendix-A.2
        let payload =
            "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";

        use serde_json::json;
        // https://tools.ietf.org/html/rfc7515#page-41
        let key: JWK = serde_json::from_value(json!({"kty":"RSA",
         "n":"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
         "e":"AQAB",
         "d":"Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ",
         "p":"4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc", "q":"uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc",
         "dp":"BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0",
         "dq":"h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU",
         "qi":"IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U"
        }))
        .unwrap();

        // https://tools.ietf.org/html/rfc7515#page-43
        let jws = encode_sign(Algorithm::RS256, payload, &key).unwrap();
        assert_eq!(jws, "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw");

        decode_verify(&jws, &key).unwrap();
    }

    #[test]
    #[cfg(feature = "secp256k1")]
    fn secp256k1_sign_verify() {
        let key = JWK::generate_secp256k1().unwrap();
        let data = b"asdf";
        let bad_data = b"no";
        let sig = sign_bytes(Algorithm::ES256K, data, &key).unwrap();
        verify_bytes(Algorithm::ES256K, data, &key, &sig).unwrap();
        verify_bytes(Algorithm::ES256K, bad_data, &key, &sig).unwrap_err();

        // ES256K-R
        let key = JWK {
            algorithm: Some(Algorithm::ES256KR),
            ..key
        };
        verify_bytes(Algorithm::ES256KR, data, &key, &sig).unwrap_err();
        verify_bytes(Algorithm::ES256KR, bad_data, &key, &sig).unwrap_err();

        // Test recovery
        let sig = sign_bytes(Algorithm::ES256KR, data, &key).unwrap();
        verify_bytes(Algorithm::ES256KR, data, &key, &sig).unwrap();
        verify_bytes(Algorithm::ES256KR, bad_data, &key, &sig).unwrap_err();
        let recovered_key = recover(Algorithm::ES256KR, data, &sig).unwrap();
        verify_bytes(Algorithm::ES256KR, data, &recovered_key, &sig).unwrap();
        let other_key = JWK::generate_secp256k1().unwrap();
        verify_bytes(Algorithm::ES256KR, data, &other_key, &sig).unwrap_err();
    }

    #[test]
    #[cfg(feature = "eip")]
    fn keccak_sign_verify() {
        let key = JWK::generate_secp256k1().unwrap();
        let data = b"asdf";
        let bad_data = b"no";
        // ESKeccakK-R
        let key = JWK {
            algorithm: Some(Algorithm::ESKeccakKR),
            ..key
        };

        let sig = sign_bytes(Algorithm::ES256KR, data, &key).unwrap();
        let other_key = JWK::generate_secp256k1().unwrap();
        // TODO check the error type
        verify_bytes(Algorithm::ESKeccakKR, data, &key, &sig).unwrap_err();
        verify_bytes(Algorithm::ESKeccakKR, bad_data, &key, &sig).unwrap_err();

        // Test recovery (ESKeccakK-R)
        let sig = sign_bytes(Algorithm::ESKeccakKR, data, &key).unwrap();
        verify_bytes(Algorithm::ESKeccakKR, data, &key, &sig).unwrap();
        verify_bytes(Algorithm::ESKeccakKR, bad_data, &key, &sig).unwrap_err();
        let recovered_key = recover(Algorithm::ESKeccakKR, data, &sig).unwrap();
        verify_bytes(Algorithm::ESKeccakKR, data, &recovered_key, &sig).unwrap();
        verify_bytes(Algorithm::ESKeccakKR, data, &other_key, &sig).unwrap_err();
    }

    #[test]
    #[cfg(feature = "p256")]
    fn p256_sign_verify() {
        let key = JWK::generate_p256().unwrap();
        let data = b"asdf";
        let bad_data = b"no";
        let sig = sign_bytes(Algorithm::ES256, data, &key).unwrap();
        verify_bytes(Algorithm::ES256, data, &key, &sig).unwrap();
        verify_bytes(Algorithm::ES256, bad_data, &key, &sig).unwrap_err();

        let key: JWK =
            serde_json::from_str(include_str!("../../tests/secp256r1-2021-03-18.json")).unwrap();
        let payload = "{\"iss\":\"did:example:foo\",\"vp\":{\"@context\":[\"https://www.w3.org/2018/credentials/v1\"],\"type\":\"VerifiablePresentation\"}}";
        let jws = encode_sign(Algorithm::ES256, payload, &key).unwrap();
        assert_eq!(jws, "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJkaWQ6ZXhhbXBsZTpmb28iLCJ2cCI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJ0eXBlIjoiVmVyaWZpYWJsZVByZXNlbnRhdGlvbiJ9fQ.rJzO6MmTNS8Tn-L3baIf9_2Jr9OoK8E06MxJtofz8xMUGSom6eRUmWGZ7oQVjgP3HogOD80miTvuvKTWa54Nvw");
        decode_verify(&jws, &key).unwrap();
    }

    #[test]
    #[cfg(feature = "p384")]
    fn p384_sign_verify() {
        let key = JWK::generate_p384().unwrap();
        let data = b"asdf";
        let bad_data = b"no";
        let sig = sign_bytes(Algorithm::ES384, data, &key).unwrap();
        verify_bytes(Algorithm::ES384, data, &key, &sig).unwrap();
        verify_bytes(Algorithm::ES384, bad_data, &key, &sig).unwrap_err();

        let key: JWK =
            serde_json::from_str(include_str!("../../tests/secp384r1-2022-05-10.json")).unwrap();
        let payload = "{\"iss\":\"did:example:foo\",\"vp\":{\"@context\":[\"https://www.w3.org/2018/credentials/v1\"],\"type\":\"VerifiablePresentation\"}}";
        let jws = encode_sign(Algorithm::ES384, payload, &key).unwrap();
        dbg!(&jws);
        decode_verify(&jws, &key).unwrap();

        const JWS: &str = "eyJhbGciOiJFUzM4NCJ9.eyJpc3MiOiJkaWQ6ZXhhbXBsZTpmb28iLCJ2cCI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJ0eXBlIjoiVmVyaWZpYWJsZVByZXNlbnRhdGlvbiJ9fQ.2vpBSFN7DxuS57epgq_e7-NyNiJ5eOOrExmi65C_wtZOC2-9i6fVvMnfUig7QmgiirznAg1wr_b7_kH-bbMCI5Pdf8pAnxQg3LL9I9OhzttyG06qAl9L7BE6aNS-aqnf";
        decode_verify(&JWS, &key).unwrap();
    }
}
