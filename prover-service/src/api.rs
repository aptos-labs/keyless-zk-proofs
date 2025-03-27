// Copyright © Aptos Foundation

use aptos_crypto_derive::BCSCryptoHash;
use aptos_crypto_derive::CryptoHasher;
use aptos_types::{
    keyless::{Groth16Proof, Pepper},
    transaction::authenticator::EphemeralPublicKey,
};
use keyless_common::PoseidonHash;
use serde::{Deserialize, Serialize};

//#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
//pub struct EphemeralPublicKeyBlinder(pub(crate) Vec<u8>);

pub type EphemeralPublicKeyBlinder = Vec<u8>;

#[derive(Debug, Serialize, Deserialize, BCSCryptoHash, CryptoHasher)]
pub struct RequestInput {
    pub jwt_b64: String,
    pub epk: EphemeralPublicKey,
    #[serde(with = "hex")]
    pub epk_blinder: EphemeralPublicKeyBlinder,
    pub exp_date_secs: u64,
    pub exp_horizon_secs: u64,
    pub pepper: Pepper,
    pub uid_key: String,
    pub extra_field: Option<String>,
    pub idc_aud: Option<String>,
    #[serde(default)]
    pub use_insecure_test_jwk: bool,
    #[serde(default)]
    pub skip_aud_checks: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)] // EphemeralSignature has the WebAuthn (Passkey) variant which is large.
pub enum ProverServiceResponse {
    Success {
        proof: Groth16Proof,
        #[serde(with = "hex")]
        public_inputs_hash: PoseidonHash,
        #[serde(with = "hex")]
        training_wheels_signature: Vec<u8>,
    },
    Error {
        message: String,
    },
}
