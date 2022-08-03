# RSA Accumulators

RSA-based dynamic accumulators use the accumulator and witness as both elements reduced by a modulus of unknown order. This
keeps their sizes constant and proofs can be generated fairly quickly. The bulk of the work comes from computing
the witness when updates have been applied to the accumulator. Insertions are computed as exponentiations to the current
witness value reduced by the modulus. One can think of this as RSA encryption. Removals can also be one reasonably fast.

This implementation uses the POKE2 method with proofs. RSA proofs can also be aggregated using Proof of Knowledge of
Coprime Roots which reduces the proof to be a single element.

# Features

- [x] Accumulators
   - [x] Add new members
   - [x] Remove existing members
- [x] Membership Witness
   - [x] Create
   - [x] Update
   - [ ] Aggregation
- [ ] Non-membership Witness
    - [x] Create
    - [x] Update
    - [ ] Aggregation
- [ ] Membership Proof
   - [x] Generate
   - [x] Verify
   - [ ] Aggregation
- [ ] Non-Membership Proof
   - [x] Generate 
   - [x] Verify 
   - [ ] Aggregation
- [ ] Vector Accumulator
   - [ ] Add new members
   - [ ] Remove existing members
    
# References

[Boneh, D., Bunz, B., Fisch, B., Batching Techniques for Accumulators with Applications to IOPs and Stateless Blockchains, 2018](https://eprint.iacr.org/2018/1188.pdf)