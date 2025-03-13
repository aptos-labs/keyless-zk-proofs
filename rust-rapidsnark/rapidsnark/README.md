# Aptos version of RapidSnark

This c++ library is wrapped by the `rust-rapidsnark` crate, which is used
by the `prover-service` crate to compute proofs.

## Building

Running `cargo build` inside `rust-rapidsnark` or inside `prover-service`
will internally build the c++ code in this directory. If you wish to build
the c++ code separately for some reason, make sure your development
environment is setup (see `../../README.md`), and then run the following
inside the current directory:

```bash
./build_lib.sh
```

