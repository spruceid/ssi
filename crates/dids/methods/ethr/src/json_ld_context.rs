use ssi_dids_core::{
    document::representation,
    ssi_json_ld::{
        syntax::context::{
            term_definition::{Expanded, Id, Type, TypeKeyword},
            Definition, TermDefinition,
        },
        Nullable,
    },
};
use static_iref::iri;

use crate::VerificationMethodType;

#[derive(Debug, Default)]
pub struct JsonLdContext {
    ecdsa_secp256k1_verification_key_2019: bool,
    ecdsa_secp256k1_recovery_method_2020: bool,
    ed25519_verification_key_2020: bool,
    x25519_key_agreement_key_2020: bool,
    eip712_method_2021: bool,
    public_key_jwk: bool,
    public_key_multibase: bool,
}

impl JsonLdContext {
    pub fn add_verification_method_type(&mut self, vm_type: VerificationMethodType) {
        match vm_type {
            VerificationMethodType::EcdsaSecp256k1VerificationKey2019 => {
                self.ecdsa_secp256k1_verification_key_2019 = true
            }
            VerificationMethodType::EcdsaSecp256k1RecoveryMethod2020 => {
                self.ecdsa_secp256k1_recovery_method_2020 = true
            }
            VerificationMethodType::Ed25519VerificationKey2020 => {
                self.ed25519_verification_key_2020 = true
            }
            VerificationMethodType::X25519KeyAgreementKey2020 => {
                self.x25519_key_agreement_key_2020 = true
            }
            VerificationMethodType::Eip712Method2021 => self.eip712_method_2021 = true,
        }
    }

    pub fn add_property(&mut self, prop: &str) {
        match prop {
            "publicKeyJwk" => self.public_key_jwk = true,
            "publicKeyMultibase" => self.public_key_multibase = true,
            _ => {}
        }
    }

    pub fn into_entries(self) -> Vec<representation::json_ld::ContextEntry> {
        let mut def = Definition::new();

        let mut blockchain_account_id = false;

        if self.ecdsa_secp256k1_verification_key_2019 {
            let ty = VerificationMethodType::EcdsaSecp256k1VerificationKey2019;
            def.bindings.insert(
                ty.name().into(),
                TermDefinition::Simple(ty.iri().to_owned().into()).into(),
            );
        }

        if self.ecdsa_secp256k1_recovery_method_2020 {
            let ty = VerificationMethodType::EcdsaSecp256k1RecoveryMethod2020;
            def.bindings.insert(
                ty.name().into(),
                TermDefinition::Simple(ty.iri().to_owned().into()).into(),
            );

            blockchain_account_id = true;
        }

        if self.ed25519_verification_key_2020 {
            let ty = VerificationMethodType::Ed25519VerificationKey2020;
            def.bindings.insert(
                ty.name().into(),
                TermDefinition::Simple(ty.iri().to_owned().into()).into(),
            );
        }

        if self.x25519_key_agreement_key_2020 {
            let ty = VerificationMethodType::X25519KeyAgreementKey2020;
            def.bindings.insert(
                ty.name().into(),
                TermDefinition::Simple(ty.iri().to_owned().into()).into(),
            );
        }

        if self.eip712_method_2021 {
            let ty = VerificationMethodType::Eip712Method2021;
            def.bindings.insert(
                ty.name().into(),
                TermDefinition::Simple(ty.iri().to_owned().into()).into(),
            );

            blockchain_account_id = true;
        }

        if self.public_key_jwk {
            def.bindings.insert(
                "publicKeyJwk".into(),
                TermDefinition::Expanded(Box::new(Expanded {
                    id: Some(Nullable::Some(Id::Term(
                        iri!("https://w3id.org/security#publicKeyJwk")
                            .to_owned()
                            .into_string(),
                    ))),
                    type_: Some(Nullable::Some(Type::Keyword(TypeKeyword::Json))),
                    ..Default::default()
                }))
                .into(),
            );
        }

        if self.public_key_multibase {
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

        if blockchain_account_id {
            def.bindings.insert(
                "blockchainAccountId".into(),
                TermDefinition::Simple(
                    iri!("https://w3id.org/security#blockchainAccountId")
                        .to_owned()
                        .into(),
                )
                .into(),
            );
        }

        vec![representation::json_ld::ContextEntry::Definition(def)]
    }
}
