use aptos_crypto::ed25519::Ed25519PrivateKey;
use aptos_keyless_common::input_processing::config::CircuitConfig;
use figment::{providers::Env, Figment};
use rust_rapidsnark::FullProver;
use serde::{Deserialize, Serialize};

use crate::config::{ProverServiceConfig, CONFIG};
use crate::groth16_vk::OnChainGroth16VerificationKey;
use crate::prover_key::TrainingWheelsKeyPair;
use tokio::sync::Mutex;

#[derive(Debug, Serialize, Deserialize)]
pub struct ProverServiceSecrets {
    /// The current training wheel key.
    pub private_key_0: Ed25519PrivateKey,
}

pub struct ProverServiceState {
    pub config: ProverServiceConfig,
    pub circuit_metadata: CircuitConfig,
    pub groth16_vk: OnChainGroth16VerificationKey,
    pub tw_keys: TrainingWheelsKeyPair,
    pub full_prover: Mutex<FullProver>,
}

impl ProverServiceState {
    pub fn init() -> Self {
        let ProverServiceSecrets {
            private_key_0: private_key,
        } = Figment::new()
            .merge(Env::raw())
            .extract()
            .expect("Couldn't load private key from environment variable PRIVATE_KEY");

        ProverServiceState {
            config: CONFIG.clone(),
            circuit_metadata: CONFIG.load_circuit_params(),
            groth16_vk: CONFIG.load_vk(),
            tw_keys: TrainingWheelsKeyPair::from_sk(private_key),
            full_prover: Mutex::new(FullProver::new(&CONFIG.zkey_path()).unwrap()),
        }
    }

    pub fn circuit_config(&self) -> &CircuitConfig {
        &self.circuit_metadata
    }
}
