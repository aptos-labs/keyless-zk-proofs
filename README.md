# Keyless ZK circuit and ZK proving service

This repo contains:
1. The `circom` implementation of the Aptos Keyless ZK relation from AIP-61 in `circuit/templates/`
2. An implementation of a ZK proving service in `prover/`
3. A circom unit testing framework in `circuit/`
4. Some shared rust code in `keyless-common/`
5. A VK diff tool in `vk-diff` (see its [README](/vk-diff))


## TODOs

### Prover service

 - [ ] Why is the description of `keyless-common/` set to "Aptos Keyless circuit tests" in its `Cargo.toml`?
 - [ ] The `Cargo.toml` description of `circuit/` also seem inappropriate
 - [ ] Redundant `OnChainGroth16VerificationKey` struct
 - [ ] Move some shared `prover` and `vk-diff` code to `keyless-common`

### Circuit

 - [ ] Remove public inputs hash and do commit-and-prove
 - [ ] Pedersen-based keyless addresses and avoid Poseidon hashing, except for Fiat-Shamir maybe

