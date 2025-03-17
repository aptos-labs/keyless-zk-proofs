# Aptos Keyless Prover Service

This repository contains the code for the Aptos Keyless Prover Service.

## Development environment setup

To setup your development environment, run the following command in the
repo root:

```bash
./scripts/setup_environment.sh
```

## Unit testing

After your environment is setup, run tests using `cargo test`. 

## Local e2e testing guide (beside UTs)

NOTE: all the commands below assume the working directory is the repo root.

First, initialize the environment. Instructions are above.

The prover now works with a default training wheel key pair (already prepared at `private_key_for_testing.txt`)
and optionally a "next" one (already prepared at `private_key_for_testing_another.txt`).

The prover now works with a default circuit (prepared by `dev_setup` at `~/.local/share/aptos-prover-service/default`)
and optionally a "next" one (prepared by `dev_setup` at `~/.local/share/aptos-prover-service/new`).

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
export ONCHAIN_GROTH16_VK_URL=http://localhost:4444/groth16_vk.json
export ONCHAIN_TW_VK_URL=http://localhost:4444/keyless_config.json
export PRIVATE_KEY_0=$(cat ./private_key_for_testing.txt) 
export PRIVATE_KEY_1=$(cat ./private_key_for_testing_another.txt)
export CONFIG_FILE="config_local_testing_new_setup_specified.yml" 
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
In terminal 1, you should also see 2 log lines like:
```
{"timestamp":"...","level":"INFO","message":"Setup selected, ..., use_new_setup=false", ... }
{"timestamp":"...","level":"INFO","message":"TW keys selected, ..., use_new_twpk=false", ... }
```
, indicating the rotation has not happened yet.


If you rotate the training wheel keys and retry the request as follows.
(still in terminal 2, run:)
```bash
LOCAL_TW_VK_IN=private_key_for_testing_another.txt ONCHAIN_KEYLESS_CONFIG_OUT=keyless_config.json cargo test tw_vk_rewriter
sleep 11
./scripts/make_request.sh http://localhost:8083 prover_request_payload.json
```
The 2 new log lines should be in the following pattern, where `use_new_twpk` becomes `true`.
```
{"timestamp":"...","level":"INFO","message":"Setup selected, ..., use_new_setup=false", ... }
{"timestamp":"...","level":"INFO","message":"TW keys selected, ..., use_new_twpk=true", ... }
```

If you rotate the Groth16 VK and retry the request as follows.
(still in terminal 2, run:)
```bash
LOCAL_VK_IN=~/.local/share/aptos-prover-service/new/verification_key.json ONCHAIN_VK_OUT=groth16_vk.json cargo test groth16_vk_rewriter
sleep 11
./scripts/make_request.sh http://localhost:8083 prover_request_payload.json
```
The 2 new log lines should be in the following pattern, where `use_new_setup` becomes `true`.
```
{"timestamp":"...","level":"INFO","message":"Setup selected, ..., use_new_setup=true", ... }
{"timestamp":"...","level":"INFO","message":"TW keys selected, ..., use_new_twpk=true", ... }
```
