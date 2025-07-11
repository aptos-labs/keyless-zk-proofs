# Aptos Keyless circuit

## Installing dependencies

The scripts in this repository will not work without installing the dependencies.

To install, please run the following from the repo root:

```
./scripts/task.sh circuit:install-deps
```

Optionally, you can also install a git pre-commit hook which checks that
the main circuit compiles before committing, as follows:

```
./scripts/task.sh circuit:install-deps misc:install-circom-precommit-hook
```

## Running circuit unit tests

```bash
# From the repo root:
cargo test -p aptos-keyless-circuit
# Or:
cd circuit
cargo test
```

## Running circuit benchmarks

First, do a:
```
# From the repo root
npm install
```

To run all benchmarks:
```
npm test
```

To filter by benchmark names:
```
npm test -- g "your_bench_name"
```

## Generating the proving key

To generate a sample prover and verifier key pair, run the following command from the repo root:

```
./scripts/task.sh trusted-setup:run-dummy-setup
```

## Generating a sample proof

To generate a sample proof and public input, run the following command:

```
./tools/create-proofs-for-testing.sh <prover-key> <output-dir>
```

where `<prover-key>` may be generated by `tools/trusted-setup.sh`

## Circuit stats

To obtain the current number of constraints and wires, run the following
command in this directory:

```
circom -l `npm root -g` templates/main.circom --r1cs
```

Output:
```
non-linear constraints: 1376867
linear constraints: 0
public inputs: 1
private inputs: 7858 (7745 belong to witness)
public outputs: 0
wires: 1343588
labels: 6286968
```
