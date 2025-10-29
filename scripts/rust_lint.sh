#!/bin/sh

# This file contains the rust lint rules that are enforced in keyless-zk-proofs.
#
# Note, the script assumes you have already installed cargo-sort and cargo machete:
# cargo install cargo-sort
# cargo install cargo-machete
#
# These are also installed by default when running scripts/task.sh prover-service install-deps

# Make sure we're in the root of the repo.
if [ ! -d ".github" ]
then
    echo "Please run this from the root of keyless-zk-proofs!"
    exit 1
fi

# Run in check mode if requested.
CHECK_ARG=""
if [ "$1" = "--check" ]; then
    CHECK_ARG="--check"
fi

# Set appropriate script flags.
set -e
set -x

# Run clippy with the keyless-zk-proofs specific configuration.
cargo xclippy

# Run the formatter.
cargo fmt $CHECK_ARG

# Once cargo-sort correctly handles workspace dependencies,
# we can move to cleaner workspace dependency notation.
# See: https://github.com/DevinR528/cargo-sort/issues/47
cargo sort --grouped --workspace $CHECK_ARG

# Check for unused rust dependencies.
cargo machete
