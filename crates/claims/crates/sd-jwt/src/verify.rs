// impl SdJwt {
//     /// Verify this SD-JWT.
//     pub async fn verify<P>(&self, params: P) -> Result<Verification, ProofValidationError>
//     where
//         // T: ValidateJWSHeader<P> + ValidateClaims<P, JWSSignature>,
//         P: ResolverProvider<Resolver: JWKResolver>
//     {
//         // VerifiableClaims::verify(self, params).await
//         let decoded = self
//             .decode_any()
//             .map_err(ProofValidationError::input_data)?;
//         decoded.verify(params).await
//     }
// }

// impl<'a> DecodedSdJwtRef<'a> {
//     /// Verify this SD-JWT.
//     pub async fn verify<P>(&self, params: P) -> Result<Verification, ProofValidationError>
//     where
//         // T: ValidateJWSHeader<P> + ValidateClaims<P, JWSSignature>,
//         P: ResolverProvider<Resolver: JWKResolver>,
//         P: DateTimeProvider
//     {
//         match self.jwt.verify(params).await? {
//             Ok(()) => {
//                 let sd_alg = self.jwt.signing_bytes.payload.try_get::<SdAlg>()
//                     .map_err(ProofValidationError::input_data)?
//                     .ok_or_else(|| ProofValidationError::input_data("missing SD algorithm"))?
//                     .into_owned();

//                 // ...
//                 visit_claims(&mut payload_claims, &mut disclosures)?;
//                 for (_, disclosure) in disclosures {
//                     if !disclosure.found {
//                         return Err(DecodeError::UnusedDisclosure);
//                     }
//                 }

//                 todo!()
//             }
//             Err(e) => Ok(Err(e))
//         }
//         // // VerifiableClaims::verify(self, params).await
//         // let decoded = self
//         //     .decode_any()
//         //     .map_err(ProofValidationError::input_data)?;
//         // decoded.verify(params)
//     }
// }
