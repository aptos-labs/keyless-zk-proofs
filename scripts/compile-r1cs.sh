#!/bin/sh

SCRIPT_DIR=$(dirname "$0")

cd "$SCRIPT_DIR/../circuit"

circom -l templates/ -l $(. ~/.nvm/nvm.sh; npm root -g) templates/main.circom --r1cs --O2
