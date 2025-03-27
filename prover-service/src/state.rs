use aptos_crypto::ed25519::Ed25519PrivateKey;
use figment::{providers::Env, Figment};
use keyless_common::input_processing::config::CircuitConfig;
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
    /// The training wheel key to use after the next key rotation.
    pub private_key_1: Option<Ed25519PrivateKey>,
}

pub struct SetupSpecificState {
    pub config: CircuitConfig,
    pub groth16_vk: OnChainGroth16VerificationKey,
    pub tw_keys: TrainingWheelsKeyPair,
    pub full_prover: Mutex<FullProver>,
}

pub struct ProverServiceState {
    pub config: ProverServiceConfig,
    pub default_setup: SetupSpecificState,
    pub new_setup: Option<SetupSpecificState>,
}

impl ProverServiceState {
    pub fn init() -> Self {
        let ProverServiceSecrets {
            private_key_0: private_key,
            private_key_1: private_key_new,
        } = Figment::new()
            .merge(Env::raw())
            .extract()
            .expect("Couldn't load private key from environment variable PRIVATE_KEY");

        let default_circuit = SetupSpecificState {
            config: CONFIG.load_circuit_params(false),
            groth16_vk: CONFIG.load_vk(false),
            tw_keys: TrainingWheelsKeyPair::from_sk(private_key),
            full_prover: Mutex::new(FullProver::new(&CONFIG.zkey_path(false)).unwrap()),
        };

        let new_circuit = if CONFIG.new_setup_dir.is_some() {
            let state = SetupSpecificState {
                config: CONFIG.load_circuit_params(true),
                groth16_vk: CONFIG.load_vk(true),
                tw_keys: TrainingWheelsKeyPair::from_sk(private_key_new.unwrap()),
                full_prover: Mutex::new(FullProver::new(&CONFIG.zkey_path(true)).unwrap()),
            };
            Some(state)
        } else {
            None
        };

        ProverServiceState {
            config: CONFIG.clone(),
            default_setup: default_circuit,
            new_setup: new_circuit,
        }
    }

    pub fn circuit_config(&self, use_new_setup: bool) -> &CircuitConfig {
        if use_new_setup {
            &self.new_setup.as_ref().unwrap().config
        } else {
            &self.default_setup.config
        }
    }
}
