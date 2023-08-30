use std::hash::Hash;

use linked_data::LinkedData;
use rdf_types::VocabularyMut;
use ssi_jwk::JWK;
use ssi_jws::{CompactJWSStr, CompactJWSString};
use ssi_security::PROOF_VALUE;
use ssi_verification_methods::{covariance_rule, InvalidSignature, Referencable};

mod eip712;

pub use eip712::*;

#[derive(Debug, Default, Clone)]
pub struct AnySignature {
    pub proof_value: Option<String>,

    pub signature_value: Option<String>,

    pub jws: Option<CompactJWSString>,

    pub eip712: Option<Eip712Metadata>,

    pub public_key_jwk: Option<Box<JWK>>,

    pub public_key_multibase: Option<String>,
}

impl Referencable for AnySignature {
    type Reference<'a> = AnySignatureRef<'a> where Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_> {
        AnySignatureRef {
            proof_value: self.proof_value.as_deref(),
            signature_value: self.signature_value.as_deref(),
            jws: self.jws.as_deref(),
            eip712: self.eip712.as_ref(),
            public_key_jwk: self.public_key_jwk.as_deref(),
            public_key_multibase: self.public_key_multibase.as_deref(),
        }
    }

    covariance_rule!();
}

#[derive(Debug, Clone, Copy)]
pub struct AnySignatureRef<'a> {
    pub proof_value: Option<&'a str>,

    pub signature_value: Option<&'a str>,

    pub jws: Option<&'a CompactJWSStr>,

    pub eip712: Option<&'a Eip712Metadata>,

    pub public_key_jwk: Option<&'a JWK>,

    pub public_key_multibase: Option<&'a str>,
}

/// Common signature format where the proof value is multibase-encoded.
#[derive(Debug, Clone, LinkedData)]
#[ld(prefix("sec" = "https://w3id.org/security#"))]
pub struct MultibaseSignature {
    /// Multibase encoded signature.
    #[ld("sec:proofValue")]
    pub proof_value: String,
}

impl Referencable for MultibaseSignature {
    type Reference<'a> = MultibaseSignatureRef<'a> where Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_> {
        MultibaseSignatureRef {
            proof_value: &self.proof_value,
        }
    }

    covariance_rule!();
}

impl From<MultibaseSignature> for AnySignature {
    fn from(value: MultibaseSignature) -> Self {
        AnySignature {
            proof_value: Some(value.proof_value),
            ..Default::default()
        }
    }
}

// impl<V: VocabularyMut, I> ssi_verification_methods::json_ld::FlattenIntoJsonLdNode<V, I>
//     for MultibaseSignature
// where
//     V::Iri: Eq + Hash,
//     V::BlankId: Eq + Hash,
// {
//     fn flatten_into_json_ld_node(
//         self,
//         vocabulary: &mut V,
//         _interpretation: &I,
//         node: &mut json_ld::Node<<V>::Iri, <V>::BlankId, ()>,
//     ) {
//         let properties = node.properties_mut();

//         properties.insert(
//             Meta(json_ld::Id::iri(vocabulary.insert(PROOF_VALUE)), ()),
//             Meta(
//                 json_ld::Indexed::new(
//                     json_ld::Object::Value(json_ld::Value::Literal(
//                         json_ld::object::Literal::String(json_ld::object::LiteralString::Inferred(
//                             self.proof_value,
//                         )),
//                         None,
//                     )),
//                     None,
//                 ),
//                 (),
//             ),
//         );
//     }
// }

#[derive(Debug, Clone, Copy)]
pub struct MultibaseSignatureRef<'a> {
    /// Multibase encoded signature.
    pub proof_value: &'a str,
}

impl<'a> TryFrom<AnySignatureRef<'a>> for MultibaseSignatureRef<'a> {
    type Error = InvalidSignature;

    fn try_from(value: AnySignatureRef<'a>) -> Result<Self, Self::Error> {
        match value.proof_value {
            Some(v) => Ok(Self { proof_value: v }),
            None => Err(InvalidSignature::MissingValue),
        }
    }
}

#[derive(Debug, Clone)]
pub struct JwsSignature {
    pub jws: CompactJWSString,
}

impl Referencable for JwsSignature {
    type Reference<'a> = JwsSignatureRef<'a> where Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_> {
        JwsSignatureRef { jws: &self.jws }
    }

    covariance_rule!();
}

impl From<JwsSignature> for AnySignature {
    fn from(value: JwsSignature) -> Self {
        AnySignature {
            jws: Some(value.jws),
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct JwsSignatureRef<'a> {
    pub jws: &'a CompactJWSStr,
}

impl<'a> TryFrom<AnySignatureRef<'a>> for JwsSignatureRef<'a> {
    type Error = InvalidSignature;

    fn try_from(value: AnySignatureRef<'a>) -> Result<Self, Self::Error> {
        match value.jws {
            Some(v) => Ok(Self { jws: v }),
            None => Err(InvalidSignature::MissingValue),
        }
    }
}
