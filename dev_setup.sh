#!/bin/bash

set -e
set -x
#./circuit/tools/install-deps.sh
export RESOURCES_DIR="$HOME/.local/share/aptos-prover-service"
python3 ./scripts/prepare_setups.py
./prover-service/scripts/dev_setup.sh
