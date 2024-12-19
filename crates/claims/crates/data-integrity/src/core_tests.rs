use super::*;

#[test]
fn single_domain_de_serialization() {
    let json_proof = serde_json::json!(
        {
            "type": "DataIntegrityProof",
            "cryptosuite": "ecdsa-rdfc-2019",
            "created": "2024-12-18T10:31:42.962679Z",
            "verificationMethod": "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6IndPTjRDTmlHX1BxaWl1R0JEbnpRa1lqVG9jaDJnaTRBTHluWVIwdnN1c0kiLCJ5Ijoia2JlZ25iRzUxZHFETW9wdHgtOVIxcmpIU1B6TkhYLWdQbnFhbWJ6a1pzNCJ9#0",
            "proofPurpose": "authentication",
            "domain": "https://qa.veresexchanger.dev/exchangers/z19vRLNoFaBKDeDaMzRjUj8hi/exchanges/z19jYTCujFf4b6JFdCNMTXJ3s/openid/client/authorization/response",
            "challenge": "z19jYTCujFf4b6JFdCNMTXJ3s",
            "proofValue": "z3H5Bi3cF6BGEgoWdAqp13gQHEibVGtNtVbJECwfQStGmBio1gmjHrq2TGtjJ3L18pd1pKCsb4Pos9oMDpginN68h"
        }
    );
    let proof: Proof<AnySuite> =
        serde_json::from_value(json_proof.clone()).expect("Could not deserialize");
    assert_eq!(json_proof, serde_json::to_value(&proof).unwrap());
}
