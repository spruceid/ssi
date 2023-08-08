use std::hash::Hash;

use iref::{Iri, IriBuf};
use rdf_types::{literal, Id, Literal, Object, Quad, VocabularyMut};
use serde::{Deserialize, Serialize};
use ssi_jwk::JWK;
use ssi_security::BLOCKCHAIN_ACCOUNT_ID;
use static_iref::iri;
use treeldr_rust_prelude::{locspan::Meta, AsJsonLdObjectMeta, IntoJsonLdObjectMeta};

use crate::{
    ExpectedType, LinkedDataVerificationMethod, VerificationMethod,
    CONTROLLER_IRI, RDF_TYPE_IRI, XSD_STRING, VerificationError, Referencable,
};

// mod context;
// pub use context::*;

pub const EIP712_METHOD_2021_IRI: Iri<'static> = iri!("https://w3id.org/security#Eip712Method2021");

pub const EIP712_METHOD_2021_TYPE: &str = "Eip712Method2021";

/// `Eip712Method2021`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename = "Eip712Method2021")]
pub struct Eip712Method2021 {
	/// Key identifier.
	pub id: IriBuf,

	/// Controller of the verification method.
	pub controller: IriBuf,

	/// Blockchain accound ID.
	#[serde(rename = "blockchainAccountId")]
	pub blockchain_account_id: ssi_caips::caip10::BlockchainAccountId
}

impl Eip712Method2021 {
	pub fn verify_bytes(
		&self,
		data: &[u8],
		signature_bytes: &[u8]
	) -> Result<bool, VerificationError> {
		// Interpret the signature.
		let signature = k256::ecdsa::Signature::try_from(&signature_bytes[..64]).map_err(|_| VerificationError::InvalidSignature)?;
        
		// Recover the signing key.
		let rec_id = k256::ecdsa::recoverable::Id::try_from(signature_bytes[64] % 27)
            .map_err(|_| VerificationError::InvalidSignature)?;
        let sig =
            k256::ecdsa::recoverable::Signature::new(&signature, rec_id).map_err(|_| VerificationError::InvalidSignature)?;
		let recovered_key = sig
            .recover_verifying_key(data)
            .map_err(|_| VerificationError::InvalidSignature)?;

		// Check the signing key.
        let jwk = JWK {
            params: ssi_jwk::Params::EC(ssi_jwk::ECParams::try_from(
                &k256::PublicKey::from_sec1_bytes(&recovered_key.to_bytes())
                    .unwrap(),
            ).unwrap()),
            public_key_use: None,
            key_operations: None,
            algorithm: None,
            key_id: None,
            x509_url: None,
            x509_certificate_chain: None,
            x509_thumbprint_sha1: None,
            x509_thumbprint_sha256: None,
        };
		self.blockchain_account_id.verify(&jwk).map_err(|_| VerificationError::InvalidKey)?;

		Ok(true)
	}
}

impl Referencable for Eip712Method2021 {
    type Reference<'a> = &'a Self where Self: 'a;
    
    fn as_reference(&self) -> Self::Reference<'_> {
        self
    }
}

impl VerificationMethod for Eip712Method2021 {
    fn id(&self) -> Iri {
        self.id.as_iri()
    }

    fn controller(&self) -> Option<Iri> {
        Some(self.controller.as_iri())
    }

    fn expected_type() -> Option<ExpectedType> {
        Some(EIP712_METHOD_2021_TYPE.to_string().into())
    }

    fn type_(&self) -> &str {
        EIP712_METHOD_2021_TYPE
    }
}

impl LinkedDataVerificationMethod for Eip712Method2021 {
    fn quads(&self, quads: &mut Vec<Quad>) -> Object {
        quads.push(Quad(
            Id::Iri(self.id.clone()),
            RDF_TYPE_IRI.into(),
            Object::Id(Id::Iri(EIP712_METHOD_2021_IRI.into())),
            None,
        ));

        quads.push(Quad(
            Id::Iri(self.id.clone()),
            CONTROLLER_IRI.into(),
            Object::Id(Id::Iri(self.controller.clone())),
            None,
        ));

        quads.push(Quad(
			Id::Iri(self.id.clone()),
			BLOCKCHAIN_ACCOUNT_ID.into(),
			Object::Literal(Literal::new(
				self.blockchain_account_id.to_string(),
				literal::Type::Any(XSD_STRING.into()),
			)),
			None,
		));

        rdf_types::Object::Id(rdf_types::Id::Iri(self.id.clone()))
    }
}

impl<V: VocabularyMut, I, M: Clone> IntoJsonLdObjectMeta<V, I, M> for Eip712Method2021
where
    V::Iri: Eq + Hash,
    V::BlankId: Eq + Hash,
{
    fn into_json_ld_object_meta(
        self,
        vocabulary: &mut V,
        _interpretation: &I,
        meta: M,
    ) -> json_ld::IndexedObject<V::Iri, V::BlankId, M> {
        let mut node = json_ld::Node::with_id(json_ld::syntax::Entry::new(
            meta.clone(),
            Meta(
                json_ld::Id::Valid(Id::Iri(vocabulary.insert(self.id.as_iri()))),
                meta.clone(),
            ),
        ));

        let controller_prop = Meta(
            json_ld::Id::Valid(Id::Iri(vocabulary.insert(CONTROLLER_IRI))),
            meta.clone(),
        );
        let controller_value = json_ld::Node::with_id(json_ld::syntax::Entry::new(
            meta.clone(),
            Meta(
                json_ld::Id::Valid(Id::Iri(vocabulary.insert(self.controller.as_iri()))),
                meta.clone(),
            ),
        ));
        node.insert(
            controller_prop,
            Meta(
                json_ld::Indexed::new(json_ld::Object::Node(Box::new(controller_value)), None),
                meta.clone(),
            ),
        );

        let key_prop = Meta(
			json_ld::Id::Valid(Id::Iri(vocabulary.insert(BLOCKCHAIN_ACCOUNT_ID))),
			meta.clone(),
		);
		let key_value = json_ld::Value::Literal(
			json_ld::object::Literal::String(json_ld::object::LiteralString::Inferred(
				self.blockchain_account_id.to_string()
			)),
			None,
		);
		node.insert(
			key_prop,
			Meta(
				json_ld::Indexed::new(json_ld::Object::Value(key_value), None),
				meta.clone(),
			),
		);

        Meta(
            json_ld::Indexed::new(json_ld::Object::Node(Box::new(node)), None),
            meta,
        )
    }
}

impl<V: VocabularyMut, I, M: Clone> AsJsonLdObjectMeta<V, I, M> for Eip712Method2021
where
    V::Iri: Eq + Hash,
    V::BlankId: Eq + Hash,
{
    fn as_json_ld_object_meta(
        &self,
        vocabulary: &mut V,
        _interpretation: &I,
        meta: M,
    ) -> json_ld::IndexedObject<V::Iri, V::BlankId, M> {
        let mut node = json_ld::Node::with_id(json_ld::syntax::Entry::new(
            meta.clone(),
            Meta(
                json_ld::Id::Valid(Id::Iri(vocabulary.insert(self.id.as_iri()))),
                meta.clone(),
            ),
        ));

        let controller_prop = Meta(
            json_ld::Id::Valid(Id::Iri(vocabulary.insert(CONTROLLER_IRI))),
            meta.clone(),
        );
        let controller_value = json_ld::Node::with_id(json_ld::syntax::Entry::new(
            meta.clone(),
            Meta(
                json_ld::Id::Valid(Id::Iri(vocabulary.insert(self.controller.as_iri()))),
                meta.clone(),
            ),
        ));
        node.insert(
            controller_prop,
            Meta(
                json_ld::Indexed::new(json_ld::Object::Node(Box::new(controller_value)), None),
                meta.clone(),
            ),
        );

        let key_prop = Meta(
			json_ld::Id::Valid(Id::Iri(vocabulary.insert(BLOCKCHAIN_ACCOUNT_ID))),
			meta.clone(),
		);
		let key_value = json_ld::Value::Literal(
			json_ld::object::Literal::String(json_ld::object::LiteralString::Inferred(
				self.blockchain_account_id.to_string()
			)),
			None,
		);
		node.insert(
			key_prop,
			Meta(
				json_ld::Indexed::new(json_ld::Object::Value(key_value), None),
				meta.clone(),
			),
		);

        Meta(
            json_ld::Indexed::new(json_ld::Object::Node(Box::new(node)), None),
            meta,
        )
    }
}
