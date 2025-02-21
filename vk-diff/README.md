# VK diff tool

This tool will compare a `snarkjs` Groth16 VK with the on-chain Groth16 VK.

It takes as input:
1. a URL to the `snarkjs` VK
2. a network name (`devnet`, `tesnet` or `mainnet`)

...and exits with 0 if they match or 1 otherwise.
It also prints the two VKs, if they differ.

## Examples

Below, we run the VK diff tool against `snarkjs` VK from an old ceremony that is no longer on `devnet`.
The tool correctly outputs "different":
```
cargo run -- \
    -j https://raw.githubusercontent.com/aptos-labs/aptos-keyless-trusted-setup-contributions-may-2024/refs/heads/main/verification_key_39f9c44b4342ed5e6941fae36cf6c87c52b1e17f.json \
    -n devnet
```

Or, below we use the tool to match the currently-deployed VK with the latest ceremony:
```
cargo run -- \
    -j https://raw.githubusercontent.com/aptos-labs/aptos-keyless-trusted-setup-contributions-jan-2025/refs/heads/main/verification_key.json \
    -n devnet
```
