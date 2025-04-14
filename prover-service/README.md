# Aptos Keyless Prover Service

This repository contains the code for the Aptos Keyless Prover Service.

## Development environment setup

To setup your development environment, run the following command in the
repo root:

```bash
./scripts/task.sh setup-dev-environment
```

## Unit testing

After your environment is setup, run tests using `cargo test`. 

## Local e2e testing guide (beside UTs)

NOTE: all the commands below assume the working directory is the repo root.

First, initialize the environment. Instructions are above.

In terminal 0, prepare the mock on-chain data and mock a full node with a naive HTTP server.
```bash
export DYLD_LIBRARY_PATH=$(pwd)/prover/rust-rapidsnark/rapidsnark/package/lib:$DYLD_LIBRARY_PATH
export LD_LIBRARY_PATH=$(pwd)/prover/rust-rapidsnark/rapidsnark/package/lib:$LD_LIBRARY_PATH
cd prover
LOCAL_VK_IN=~/.local/share/aptos-prover-service/default/verification_key.json ONCHAIN_VK_OUT=groth16_vk.json cargo test groth16_vk_rewriter
LOCAL_TW_VK_IN=private_key_for_testing.txt ONCHAIN_KEYLESS_CONFIG_OUT=keyless_config.json cargo test tw_vk_rewriter
python3 -m http.server 4444
```

In terminal 1, run the prover.
```bash
export DYLD_LIBRARY_PATH=$(pwd)/prover/rust-rapidsnark/rapidsnark/package/lib:$DYLD_LIBRARY_PATH
export LD_LIBRARY_PATH=$(pwd)/prover/rust-rapidsnark/rapidsnark/package/lib:$LD_LIBRARY_PATH
cd prover
export PRIVATE_KEY_0=$(cat ./private_key_for_testing.txt) 
export CONFIG_FILE="config_local_testing.yml" 
cargo run | grep 'selected,'
```

Login to [send-it](https://send-it.aptoslabs.com/home/), find a real prover request payload as below.
1. Open browser developer tools (F12).
2. Navigate to Network Tab.
3. Select a request with name `prove`.
4. Go to its `Payload` detail page.

Save the payload as `prover_request_payload.json`.

In terminal 2, make a request to the prover and expect it to finish normally.
```bash
export DYLD_LIBRARY_PATH=$(pwd)/prover/rust-rapidsnark/rapidsnark/package/lib:$DYLD_LIBRARY_PATH
export LD_LIBRARY_PATH=$(pwd)/prover/rust-rapidsnark/rapidsnark/package/lib:$LD_LIBRARY_PATH
cd prover
./scripts/make_request.sh http://localhost:8083 prover_request_payload.json
```
