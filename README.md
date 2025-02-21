# Keyless ZK circuit and ZK proving service

This repo contains:
1. The `circom` implementation of the Aptos Keyless ZK relation from AIP-61
2. An implementation of a ZK proving service

## Submodules

This repository uses a Git submodule for its [`rust-rapdisnark`](https://github.com/aptos-labs/rust-rapidsnark) dependency.
You should pull it via:

```
git submodule init
git submodule update
```

## TODOs

 - [] Why is the description of `keyless-common/` set to "Aptos Keyless circuit tests" in its `Cargo.toml`
 - [] The `Cargo.toml` description of `circuit/` also seem inappropriate
