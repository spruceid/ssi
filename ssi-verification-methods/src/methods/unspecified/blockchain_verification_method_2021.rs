use std::hash::Hash;

use iref::{Iri, IriBuf};
use rdf_types::{Quad, Object, Id, Literal, literal, VocabularyMut};
use ssi_security::BLOCKCHAIN_ACCOUNT_ID;
use static_iref::iri;
use serde::{Serialize, Deserialize};
use treeldr_rust_prelude::{IntoJsonLdObjectMeta, locspan::Meta, AsJsonLdObjectMeta};

use crate::{VerificationMethod, ExpectedType, LinkedDataVerificationMethod, RDF_TYPE_IRI, CONTROLLER_IRI, XSD_STRING, Referencable};

pub const BLOCKCHAIN_VERIFICATION_METHOD_2021_IRI: Iri<'static> = iri!("https://w3id.org/security#BlockchainVerificationMethod2021");

pub const BLOCKCHAIN_VERIFICATION_METHOD_2021_TYPE: &str = "BlockchainVerificationMethod2021";

/// BlockchainVerificationMethod2021.
/// 
/// See: <https://w3id.org/security#BlockchainVerificationMethod2021>.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename = "BlockchainVerificationMethod2021")]
pub struct BlockchainVerificationMethod2021 {
	/// Key identifier.
	pub id: IriBuf,

	/// Controller of the verification method.
	pub controller: IriBuf,

	/// Blockchain accound ID.
	#[serde(rename = "blockchainAccountId")]
	pub blockchain_account_id: ssi_caips::caip10::BlockchainAccountId
}

impl Referencable for BlockchainVerificationMethod2021 {
    type Reference<'a> = &'a Self where Self: 'a;
    
    fn as_reference(&self) -> Self::Reference<'_> {
        self
    }
}

impl VerificationMethod for BlockchainVerificationMethod2021 {
    fn id(&self) -> Iri {
        self.id.as_iri()
    }

    fn controller(&self) -> Option<Iri> {
        Some(self.controller.as_iri())
    }

    fn expected_type() -> Option<ExpectedType> {
        Some(BLOCKCHAIN_VERIFICATION_METHOD_2021_TYPE.to_string().into())
    }

    fn type_(&self) -> &str {
        BLOCKCHAIN_VERIFICATION_METHOD_2021_TYPE
    }
}

impl LinkedDataVerificationMethod for BlockchainVerificationMethod2021 {
    fn quads(&self, quads: &mut Vec<Quad>) -> Object {
        quads.push(Quad(
            Id::Iri(self.id.clone()),
            RDF_TYPE_IRI.into(),
            Object::Id(Id::Iri(BLOCKCHAIN_VERIFICATION_METHOD_2021_IRI.into())),
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

impl<V: VocabularyMut, I, M: Clone> IntoJsonLdObjectMeta<V, I, M> for BlockchainVerificationMethod2021
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

impl<V: VocabularyMut, I, M: Clone> AsJsonLdObjectMeta<V, I, M> for BlockchainVerificationMethod2021
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
