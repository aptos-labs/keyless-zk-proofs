# Keyless ZK circuit and ZK proving service

This repo contains:
1. The `circom` implementation of the Aptos Keyless ZK relation from AIP-61 in `circuit/templates/`.
2. An implementation of a ZK proving service in `prover-service/`. Its
   [README](./prover-service/README.md) contains instructions for building
   and running tests.
3. A circom unit testing framework in `circuit/`. Its
   [README](./circuit/README.md) contains instructions for running the
   circuit unit tests.
4. Some shared rust code in `keyless-common/`.
5. A VK diff tool in `vk-diff` (see its [README](/vk-diff) for details).
5. A folder/crate `automated-docker-test`, which allows for running an
   automated test of a prover service docker image. (See its [README](./automated-docker-test/README.md) 
   for details)

## Development environment setup

To setup your environment for both the prover service and the circuit, run
the following command:

```
./scripts/task.sh setup-dev-environment
```

Optionally, it is possible to install a precommit hook that checks whether
the circuit compiles before committing. To do this, run the following
command:

```
./scripts/task.sh misc install-circom-precommit-hook
```

For more information on the actions defined for this repo, see [the scripts
README](./scripts/README.md).

## TODOs

### Prover service

 - [x] Why is the description of `keyless-common/` set to "Aptos Keyless circuit tests" in its `Cargo.toml`?
   - Changed description to "Shared code that is used both by the prover service and circuit unit tests."
 - [x] The `Cargo.toml` description of `circuit/` also seem inappropriate
   - Changed description to "The Aptos Keyless circuit (circom) and unit tests (rust)."
 - [ ] Redundant `OnChainGroth16VerificationKey` struct
 - [ ] Move some shared `prover` and `vk-diff` code to `keyless-common`

### Circuit

 - [ ] Remove public inputs hash and do commit-and-prove
 - [ ] Pedersen-based keyless addresses and avoid Poseidon hashing, except for Fiat-Shamir maybe
 - [ ] The circuit is in the `circuit` directory, but its Cargo.toml sets
       the crate name to be `aptos-keyless-circuit`. Might be less
       confusing to have the directory name agree with the crate name?

