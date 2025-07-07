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

## Run prover service locally

### Get it running
Ensure you have done [dev environment setup](#development-environment-setup),
and run the following steps from a new terminal and with working directory being the repo root.
```bash
# Step 0: procure a testing setup to generate the Groth16 proving key. This can take ~10 minutes.
./scripts/task.sh setup procure-testing-setup

# Step 1: run
export CONFIG_FILE=./prover-service/config_local_testing.yml
export PRIVATE_KEY_0=$(cat ./prover-service/private_key_for_testing.txt)
cargo run -p prover-service
```

### Interact with the local prover service
Login to [send-it](https://send-it.aptoslabs.com/home/), find a real prover request payload as below.
1. Open browser developer tools (F12).
2. Navigate to Network Tab.
3. Select a request with name `prove`.
4. Go to its `Payload` detail page.

Save the payload as `/tmp/prover_request_payload.json`.

In a new terminal, make a request to the prover and expect it to finish normally.
```bash
curl -X POST -H "Content-Type: application/json" -d @/tmp/prover_request_payload.json http://localhost:8083/v0/prove
```

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

