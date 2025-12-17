# Keyless ZK Circuit and ZK Proving Service

This repo contains:
1. The `circom` implementation of the Aptos Keyless ZK relation from AIP-61 in `circuit/templates/`.
2. An implementation of a ZK proving service in `prover-service/`.
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

## Testing the prover service and circuit

The prover service already contains unit tests that verify prover request handling
and proof generation. Internally, these tests procure an untrusted setup corresponding
to the current circuit in this repository. For example, the unit tests will invoke the
following command before running the tests:
```
./scripts/task.sh setup procure-testing-setup
```

### Caching the testing setup

To avoid procuring the testing setup every time the tests are run, the setup will be cached
locally, and (optionally) uploaded to Google cloud via the gcloud CLI.

To clear the local testing setup cache, remove the setups in the local testing directory, e.g.,
```
~/.local/share/aptos-keyless
```

## Running the prover service locally

### Start the prover service
Ensure you have already completed the [development environment setup](#development-environment-setup) step,
and run the following command from a new terminal (with the working directory being the repo root):
```
./scripts/run_prover_service.sh
```

### Interact with the prover service
Next, login to [Aptos Connect](https://aptosconnect.app/), and find a real prover request payload as outlined below:
1. Open browser developer tools (F12).
2. Navigate to Network Tab.
3. Select a request with name `prove`.
4. Go to its `Payload` detail page.

Save the payload as `/tmp/prover_request_payload.json`.

In a new terminal, make a request to the prover and expect it to finish normally.
```bash
curl -X POST -H "Content-Type: application/json" -d @/tmp/prover_request_payload.json http://localhost:8083/v0/prove
```
