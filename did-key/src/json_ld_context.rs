use ssi_dids::{
    document::representation,
    json_ld::{
        syntax::context::{
            term_definition::{Expanded, Id, Type, TypeKeyword},
            Definition, TermDefinition,
        },
        Entry, Nullable,
    },
};
use static_iref::iri;

use crate::VerificationMethodType;

#[derive(Debug, Default)]
pub struct JsonLdContext {
    ed25519_verification_key_2018: bool,
    ecdsa_secp256k1_verification_key_2019: bool,
    ecdsa_secp256r1_verification_key_2019: bool,
    json_web_key_2020: bool,
    bls12381g2_key_2020: bool,
}

impl JsonLdContext {
    pub fn add_verification_method_type(&mut self, vm_type: VerificationMethodType) {
        match vm_type {
            VerificationMethodType::Ed25519VerificationKey2018 => {
                self.ed25519_verification_key_2018 = true
            }
            VerificationMethodType::EcdsaSecp256k1VerificationKey2019 => {
                self.ecdsa_secp256k1_verification_key_2019 = true
            }
            VerificationMethodType::EcdsaSecp256r1VerificationKey2019 => {
                self.ecdsa_secp256r1_verification_key_2019 = true
            }
            VerificationMethodType::JsonWebKey2020 => self.json_web_key_2020 = true,
            VerificationMethodType::Bls12381G2Key2020 => self.bls12381g2_key_2020 = true,
        }
    }

    pub fn into_entries(self) -> Vec<representation::json_ld::ContextEntry> {
        let mut def = Definition::new();

        let mut public_key_jwk = false;
        let mut public_key_base_58 = false;
        let mut public_key_multibase = false;

        if self.ed25519_verification_key_2018 {
            let ty = VerificationMethodType::Ed25519VerificationKey2018;
            def.bindings.insert(
                ty.name().into(),
                TermDefinition::Simple(ty.iri().to_owned().into()).into(),
            );

            public_key_base_58 = true;
        }

        if self.ecdsa_secp256k1_verification_key_2019 {
            let ty = VerificationMethodType::EcdsaSecp256k1VerificationKey2019;
            def.bindings.insert(
                ty.name().into(),
                TermDefinition::Simple(ty.iri().to_owned().into()).into(),
            );

            public_key_jwk = true;
        }

        if self.ecdsa_secp256r1_verification_key_2019 {
            let ty = VerificationMethodType::EcdsaSecp256r1VerificationKey2019;
            def.bindings.insert(
                ty.name().into(),
                TermDefinition::Simple(ty.iri().to_owned().into()).into(),
            );

            public_key_multibase = true;
        }

        if self.json_web_key_2020 {
            let ty = VerificationMethodType::JsonWebKey2020;
            def.bindings.insert(
                ty.name().into(),
                TermDefinition::Simple(ty.iri().to_owned().into()).into(),
            );

            public_key_jwk = true;
        }

        if self.bls12381g2_key_2020 {
            let ty = VerificationMethodType::Bls12381G2Key2020;
            def.bindings.insert(
                ty.name().into(),
                TermDefinition::Simple(ty.iri().to_owned().into()).into(),
            );

            public_key_jwk = true;
        }

        if public_key_jwk {
            def.bindings.insert(
                "publicKeyJwk".into(),
                TermDefinition::Expanded(Box::new(Expanded {
                    id: Some(Entry::new(Nullable::Some(Id::Term(
                        iri!("https://w3id.org/security#publicKeyJwk")
                            .to_owned()
                            .into_string(),
                    )))),
                    type_: Some(Entry::new(Nullable::Some(Type::Keyword(TypeKeyword::Json)))),
                    ..Default::default()
                }))
                .into(),
            );
        }

        if public_key_base_58 {
            def.bindings.insert(
                "publicKeyBase58".into(),
                TermDefinition::Simple(
                    iri!("https://w3id.org/security#publicKeyBase58")
                        .to_owned()
                        .into(),
                )
                .into(),
            );
        }

        if public_key_multibase {
            def.bindings.insert(
                "publicKeyMultibase".into(),
                TermDefinition::Simple(
                    iri!("https://w3id.org/security#publicKeyMultibase")
                        .to_owned()
                        .into(),
                )
                .into(),
            );
        }

        let mut entries = Vec::new();

        entries.push(representation::json_ld::ContextEntry::Definition(def));

        entries
    }
}
