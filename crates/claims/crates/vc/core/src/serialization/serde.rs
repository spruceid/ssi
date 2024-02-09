use std::marker::PhantomData;

use serde::Serialize;
use ssi_claims_core::serde::SerializeClaims;

use crate::verification::{Claims, ProofType};

impl<T: Serialize, P: ProofType> SerializeClaims for Claims<T, P>
where
    P::Prepared: Serialize,
{
    fn serialize_with_proof<U>(
        &self,
        proofs: &Self::Proof,
        serializer: U,
    ) -> Result<U::Ok, U::Error>
    where
        U: serde::Serializer,
    {
        use crate::syntax::value_or_array;

        #[derive(Serialize)]
        #[serde(bound = "T: Serialize, P: Serialize")]
        pub struct ClaimsWithProofs<'a, T, P> {
            #[serde(flatten)]
            claims: &'a T,

            #[serde(
                rename = "proof",
                with = "value_or_array",
                skip_serializing_if = "<[P]>::is_empty"
            )]
            proofs: &'a [P],
        }

        ClaimsWithProofs {
            claims: &**self,
            proofs,
        }
        .serialize(serializer)
    }
}
