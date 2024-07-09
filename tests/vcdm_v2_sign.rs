use serde_json::json;
use ssi::JWK;
use ssi_claims::{
    data_integrity::{AnySuite, CryptographicSuite, ProofOptions},
    vc::v2::JsonCredential,
    VerificationParameters,
};
use ssi_dids::{AnyDidMethod, VerificationMethodDIDResolver};
use ssi_verification_methods::{AnyMethod, SingleSecretSigner};
use static_iref::iri;

#[cfg(feature = "secp256r1")]
#[async_std::test]
async fn ecdsa_secp256r1_2020() {
    let jwk: JWK = serde_json::from_value(json!({
        "kty": "EC",
        "crv": "P-256",
        "x": "c01opxmxLeRMYhyTaiOKzvOF6DDjEajzb968ClJWB9Q",
        "y": "oM3B1R0J-Cynleb00D-PManSGnlltcgsMJaoPbPOewU",
        "d": "g-jUBRnfkbsxOQhtrBZd9l_ElOAw8BoJufTFUut2uHI"
    }))
    .unwrap();
    let resolver = VerificationMethodDIDResolver::<_, AnyMethod>::new(AnyDidMethod::default());
    let vc: JsonCredential = serde_json::from_value(json!({
      "@context": [
        "https://www.w3.org/ns/credentials/v2"
      ],
      "type": [
        "VerifiableCredential"
      ],
      "credentialSubject": {
        "id": "did:key:z6MkhTNL7i2etLerDK8Acz5t528giE5KA4p75T6ka1E1D74r"
      },
      "id": "urn:uuid:7a6cafb9-11c3-41a8-98d8-8b5a45c2548f",
      "issuer": "did:key:zDnaeqRNmCGRy8f4RgNSoj9YiwG697iWB7htXNX89G8Nu3Hxo"
    }))
    .unwrap();
    let signed_vc = AnySuite::EcdsaSecp256r1Signature2019
        .sign(
            vc,
            &resolver,
            SingleSecretSigner::new(jwk).into_local(),
            ProofOptions::from_method(iri!("did:key:zDnaeqRNmCGRy8f4RgNSoj9YiwG697iWB7htXNX89G8Nu3Hxo#zDnaeqRNmCGRy8f4RgNSoj9YiwG697iWB7htXNX89G8Nu3Hxo").into()),
        )
        .await
        .unwrap();
    signed_vc
        .verify(VerificationParameters::from_resolver(resolver))
        .await
        .unwrap()
        .unwrap();
}

#[cfg(feature = "secp256r1")]
#[async_std::test]
async fn ecdsa_rdfc_2019_p256() {
    let jwk: JWK = serde_json::from_value(json!({
        "kty": "EC",
        "crv": "P-256",
        "x": "c01opxmxLeRMYhyTaiOKzvOF6DDjEajzb968ClJWB9Q",
        "y": "oM3B1R0J-Cynleb00D-PManSGnlltcgsMJaoPbPOewU",
        "d": "g-jUBRnfkbsxOQhtrBZd9l_ElOAw8BoJufTFUut2uHI"
    }))
    .unwrap();
    let resolver = VerificationMethodDIDResolver::<_, AnyMethod>::new(AnyDidMethod::default());
    let vc: JsonCredential = serde_json::from_value(json!({
      "@context": [
        "https://www.w3.org/ns/credentials/v2"
      ],
      "type": [
        "VerifiableCredential"
      ],
      "credentialSubject": {
        "id": "did:key:z6MkhTNL7i2etLerDK8Acz5t528giE5KA4p75T6ka1E1D74r"
      },
      "id": "urn:uuid:7a6cafb9-11c3-41a8-98d8-8b5a45c2548f",
      "issuer": "did:key:zDnaeqRNmCGRy8f4RgNSoj9YiwG697iWB7htXNX89G8Nu3Hxo"
    }))
    .unwrap();
    let signed_vc = AnySuite::EcdsaRdfc2019
        .sign(
            vc,
            &resolver,
            SingleSecretSigner::new(jwk).into_local(),
            ProofOptions::from_method(iri!("did:key:zDnaeqRNmCGRy8f4RgNSoj9YiwG697iWB7htXNX89G8Nu3Hxo#zDnaeqRNmCGRy8f4RgNSoj9YiwG697iWB7htXNX89G8Nu3Hxo").into()),
        )
        .await
        .unwrap();
    signed_vc
        .verify(VerificationParameters::from_resolver(resolver))
        .await
        .unwrap()
        .unwrap();
}

#[cfg(feature = "secp384r1")]
#[async_std::test]
async fn ecdsa_rdfc_2019_p384() {
    let jwk: JWK = serde_json::from_value(json!({
        "kty": "EC",
        "crv": "P-384",
        "x": "G09OCsHnoen7IWnA9ETEKl7NmPwakpHo9KOH5bUB2nJzyn5Zco-qqBchqUi1-uaz",
        "y": "_CtCA3SUZS4IEOJN999aLTEIQOOWOX9biXqbFs4OCa1OMvjoVzzC2BimVnHrrcQ7",
        "d": "qCiwiC8sASQ3chYPN8BodDImdVbn-didbDeQdQAnGJYoRWryN3xF1xX96w6SJTx6"
    }))
    .unwrap();
    let resolver = VerificationMethodDIDResolver::<_, AnyMethod>::new(AnyDidMethod::default());
    let vc: JsonCredential = serde_json::from_value(json!({
      "@context": [
        "https://www.w3.org/ns/credentials/v2"
      ],
      "type": [
        "VerifiableCredential"
      ],
      "credentialSubject": {
        "id": "did:key:z6MkhTNL7i2etLerDK8Acz5t528giE5KA4p75T6ka1E1D74r"
      },
      "id": "urn:uuid:7a6cafb9-11c3-41a8-98d8-8b5a45c2548f",
      "issuer": "did:key:z82LkvutaARmY8poLhUnMCAhFbts88q4yDBmkqwRFYbxpFvmE1nbGUGLKf9fD66LGUbXDce"
    }))
    .unwrap();
    let signed_vc = AnySuite::EcdsaRdfc2019
        .sign(
            vc,
            &resolver,
            SingleSecretSigner::new(jwk).into_local(),
            ProofOptions::from_method(iri!("did:key:z82LkvutaARmY8poLhUnMCAhFbts88q4yDBmkqwRFYbxpFvmE1nbGUGLKf9fD66LGUbXDce#z82LkvutaARmY8poLhUnMCAhFbts88q4yDBmkqwRFYbxpFvmE1nbGUGLKf9fD66LGUbXDce").into()),
        )
        .await
        .unwrap();
    signed_vc
        .verify(VerificationParameters::from_resolver(resolver))
        .await
        .unwrap()
        .unwrap();
}

#[cfg(all(feature = "w3c", feature = "bbs"))]
#[async_std::test]
async fn bbs_2023() {
    use json_syntax::Value;

    let jwk = JWK::generate_bls12381g2();
    let did_url = ssi::dids::DIDKey::generate_url(&jwk).unwrap();

    let resolver = VerificationMethodDIDResolver::<_, AnyMethod>::new(AnyDidMethod::default());
    let vc: JsonCredential = serde_json::from_value(json!({
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            {
                "foo": "http://example.org/#foo",
                "bar": "http://example.org/#bar"
            }
        ],
        "type": [
            "VerifiableCredential"
        ],
        "credentialSubject": {
            "id": "did:key:z6MkhTNL7i2etLerDK8Acz5t528giE5KA4p75T6ka1E1D74r",
            "foo": "value1",
            "bar": "value2"
        },
        "id": "urn:uuid:7a6cafb9-11c3-41a8-98d8-8b5a45c2548f",
        "issuer": did_url.to_string()
    }))
    .unwrap();

    let base_vc = AnySuite::Bbs2023
        .sign(
            vc,
            &resolver,
            SingleSecretSigner::new(jwk).into_local(),
            ProofOptions::from_method(did_url.into_iri().into()),
        )
        .await
        .unwrap();

    let params = VerificationParameters::from_resolver(&resolver);
    let mut selection = ssi::claims::data_integrity::AnySelectionOptions::default();
    selection.selective_pointers = vec![
        "/id".parse().unwrap(),
        "/type".parse().unwrap(),
        "/credentialSubject/foo".parse().unwrap(),
        "/issuer".parse().unwrap(),
    ];
    let derived = base_vc
        .select(&params, selection)
        .await
        .unwrap()
        .map(|object| {
            ssi::json_ld::syntax::from_value::<JsonCredential>(Value::Object(object)).unwrap()
        });

    derived.verify(params).await.unwrap().unwrap();
}
