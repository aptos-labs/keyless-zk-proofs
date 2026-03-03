#!/bin/sh

# This file contains a simple script for running the prover service locally.

# Set appropriate script flags.
set -ex

# Procure a testing setup to generate the Groth16 proving key.
# Note: this can take ~10 minutes the first time it is run.
./scripts/task.sh setup procure-testing-setup

# Run the prover service.
# TODO: handle the libtbb.dylib issue on macOS.
cargo run -p prover-service -- \
--config-file-path ./prover-service/config_local_testing.yml \
--training-wheels-private-key-file-path ./prover-service/private_key_for_testing.txt
