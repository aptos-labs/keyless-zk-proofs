#!/bin/sh

SCRIPT_DIR=$(dirname "$0")

cd "$SCRIPT_DIR/../circuit"

. ~/.nvm/nvm.sh

NPM_ROOT=$(npm root -g 2>/dev/null)

# Also include system npm root in case circomlib is installed there
SYSTEM_NPM_ROOT="/opt/homebrew/lib/node_modules"

circom -l "$NPM_ROOT" -l "$SYSTEM_NPM_ROOT" templates/main.circom --r1cs --O0 #--O2
