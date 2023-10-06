use ssi_dids::json_ld::{syntax::context::{TermDefinition, term_definition::{Expanded, Type, TypeKeyword}}, Entry, Nullable};

use crate::{PkhVerificationMethod, PkhVerificationMethodType};

#[derive(Debug, Default)]
struct JsonLdContext {
    ed25519_verification_key_2018: bool,
    ecdsa_secp256k1_recovery_method_2020: bool,
    solana_method_2021: bool,
    blockchain_verification_method_2021: bool,
    // ed_25519_public_key_blake2b_digest_size_20_base58_check_encoded2021: bool,
    // p256_public_key_blake2b_digest_size_20_base58_check_encoded2021: bool,
    blockchain_account_id: bool,
    public_key_jwk: bool,
}

impl JsonLdContext {
    pub fn add_verification_method(&mut self, m: &PkhVerificationMethod) {
        // self.blockchain_account_id |= m.blockchain_account_id.is_some();
        self.blockchain_account_id = true;
        self.public_key_jwk |= m.public_key_jwk.is_some();
        self.add_verification_method_type(m.type_);
    }

    pub fn add_verification_method_type(&mut self, ty: PkhVerificationMethodType) {
        match ty {
            VerificationMethodType::EcdsaSecp256k1RecoveryMethod2020 => {
                self.ecdsa_secp256k1_recovery_method_2020 = true
            }
            VerificationMethodType::Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021 => {
                self.ed_25519_public_key_blake2b_digest_size_20_base58_check_encoded2021 = true
            }
            VerificationMethodType::P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021 => {
                self.p256_public_key_blake2b_digest_size_20_base58_check_encoded2021 = true
            }
        }
    }
}

impl From<JsonLdContext> for representation::json_ld::ContextEntry {
    fn from(value: JsonLdContext) -> Self {
        use representation::json_ld::context::{Definition, TermDefinition};
        let mut def = Definition::new();

        if value.ecdsa_secp256k1_recovery_method_2020 {
            let ty = VerificationMethodType::EcdsaSecp256k1RecoveryMethod2020;
            def.bindings.insert(
                ty.name().into(),
                TermDefinition::Simple(ty.as_iri().to_owned().into()).into(),
            );
        }

        if value.ed_25519_public_key_blake2b_digest_size_20_base58_check_encoded2021 {
            let ty =
                VerificationMethodType::Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021;
            def.bindings.insert(
                ty.name().into(),
                TermDefinition::Simple(ty.as_iri().to_owned().into()).into(),
            );
        }

        if value.p256_public_key_blake2b_digest_size_20_base58_check_encoded2021 {
            let ty = VerificationMethodType::P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021;
            def.bindings.insert(
                ty.name().into(),
                TermDefinition::Simple(ty.as_iri().to_owned().into()).into(),
            );
        }

        if value.blockchain_account_id {
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

        if value.public_key_jwk {
            def.bindings.insert(
                "publicKeyJwk".into(),
                TermDefinition::Expanded(Box::new(Expanded {
                    id: Some(Entry::new(Nullable::Some(iri!("https://w3id.org/security#publicKeyJwk").to_owned()))),
                    type_: Some(Entry::new(Nullable::Some(Type::Keyword(TypeKeyword::Json)))),
                    ..Default::default()
                }))
            );
        }

        Self::Definition(def)
    }
}