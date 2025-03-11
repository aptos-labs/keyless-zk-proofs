#!/bin/bash

set -e
set -x
./circuit/tools/install-deps.sh
export RESOURCES_DIR="$HOME/.local/share/aptos-prover-service"
python3 ./scripts/prepare_setups.py
./prover/scripts/dev_setup.sh


# Install pre-commit hook
cp git-hooks/compile-circom-if-needed-pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
echo "Installed pre-commit hook for circom compilation successfully!"
