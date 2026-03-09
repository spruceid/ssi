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
    eip712_method_2021: bool,
    public_key_hex: bool,
    public_key_base64: bool,
    public_key_base58: bool,
    public_key_pem: bool,
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
            VerificationMethodType::Eip712Method2021 => self.eip712_method_2021 = true,
        }
    }

    pub fn add_property(&mut self, prop: &str) {
        match prop {
            "publicKeyHex" => self.public_key_hex = true,
            "publicKeyBase64" => self.public_key_base64 = true,
            "publicKeyBase58" => self.public_key_base58 = true,
            "publicKeyPem" => self.public_key_pem = true,
            _ => {}
        }
    }

    pub fn into_entries(self) -> Vec<representation::json_ld::ContextEntry> {
        let mut def = Definition::new();

        let mut public_key_jwk = false;
        let mut blockchain_account_id = false;
        // let mut public_key_base_58 = false;
        // let mut public_key_multibase = false;

        // if self.ed25519_verification_key_2018 {
        //     let ty = VerificationMethodType::Ed25519VerificationKey2018;
        //     def.bindings.insert(
        //         ty.name().into(),
        //         TermDefinition::Simple(ty.iri().to_owned().into()).into(),
        //     );

        //     public_key_base_58 = true;
        // }

        if self.ecdsa_secp256k1_verification_key_2019 {
            let ty = VerificationMethodType::EcdsaSecp256k1VerificationKey2019;
            def.bindings.insert(
                ty.name().into(),
                TermDefinition::Simple(ty.iri().to_owned().into()).into(),
            );

            public_key_jwk = true;
        }

        if self.ecdsa_secp256k1_recovery_method_2020 {
            let ty = VerificationMethodType::EcdsaSecp256k1RecoveryMethod2020;
            def.bindings.insert(
                ty.name().into(),
                TermDefinition::Simple(ty.iri().to_owned().into()).into(),
            );

            blockchain_account_id = true;
        }

        if self.eip712_method_2021 {
            let ty = VerificationMethodType::Eip712Method2021;
            def.bindings.insert(
                ty.name().into(),
                TermDefinition::Simple(ty.iri().to_owned().into()).into(),
            );

            blockchain_account_id = true;
        }

        if public_key_jwk {
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

        if self.public_key_hex {
            def.bindings.insert(
                "publicKeyHex".into(),
                TermDefinition::Simple(
                    iri!("https://w3id.org/security#publicKeyHex")
                        .to_owned()
                        .into(),
                )
                .into(),
            );
        }

        if self.public_key_base64 {
            def.bindings.insert(
                "publicKeyBase64".into(),
                TermDefinition::Simple(
                    iri!("https://w3id.org/security#publicKeyBase64")
                        .to_owned()
                        .into(),
                )
                .into(),
            );
        }

        if self.public_key_base58 {
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

        if self.public_key_pem {
            def.bindings.insert(
                "publicKeyPem".into(),
                TermDefinition::Simple(
                    iri!("https://w3id.org/security#publicKeyPem")
                        .to_owned()
                        .into(),
                )
                .into(),
            );
        }

        vec![representation::json_ld::ContextEntry::Definition(def)]
    }
}
