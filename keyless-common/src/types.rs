// Copyright (c) Aptos Foundation

use serde::{Deserialize, Serialize};

// Useful type aliases for common keyless components
pub type EphemeralPublicKeyBlinder = Vec<u8>;
pub type PoseidonHash = [u8; 32];

/// This struct is a representation of a Groth16VerificationKey resource as found on-chain.
/// See, for example:
/// https://fullnode.testnet.aptoslabs.com/v1/accounts/0x1/resource/0x1::keyless_account::Groth16VerificationKey
///
/// Example JSON:
/// {
///   "type": "0x1::keyless_account::Groth16VerificationKey",
///   "data": {
///     "alpha_g1": "0xe2f26dbea299f5223b646cb1fb33eadb059d9407559d7441dfd902e3a79a4d2d",
///     "beta_g2": "0xabb73dc17fbc13021e2471e0c08bd67d8401f52b73d6d07483794cad4778180e0c06f33bbc4c79a9cadef253a68084d382f17788f885c9afd176f7cb2f036789",
///     "delta_g2": "0xb106619932d0ef372c46909a2492e246d5de739aa140e27f2c71c0470662f125219049cfe15e4d140d7e4bb911284aad1cad19880efb86f2d9dd4b1bb344ef8f",
///     "gamma_abc_g1": [
///       "0x6123b6fea40de2a7e3595f9c35210da8a45a7e8c2f7da9eb4548e9210cfea81a",
///       "0x32a9b8347c512483812ee922dc75952842f8f3083edb6fe8d5c3c07e1340b683"
///     ],
///     "gamma_g2": "0xedf692d95cbdde46ddda5ef7d422436779445c5e66006a42761e1f12efde0018c212f3aeb785e49712e7a9353349aaf1255dfb31b7bf60723a480d9293938e19"
///   }
/// }
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct OnChainGroth16VerificationKey {
    pub r#type: String, // Note: "type" is a reserved keyword, so we use raw identifier syntax
    pub data: VKeyData,
}

/// Data portion of the on-chain Groth16 VK
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct VKeyData {
    pub alpha_g1: String,
    pub beta_g2: String,
    pub delta_g2: String,
    pub gamma_abc_g1: Vec<String>,
    pub gamma_g2: String,
}
