// Copyright (c) Aptos Foundation

use aptos_crypto::ed25519::Ed25519PrivateKey;
use aptos_keyless_common::input_processing::config::CircuitConfig;
use figment::{providers::Env, Figment};
use rust_rapidsnark::FullProver;
use serde::{Deserialize, Serialize};

use crate::config::{ProverServiceConfig, CONFIG};
use crate::deployment_information::DeploymentInformation;
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
    pub deployment_information: DeploymentInformation,
    pub groth16_vk: OnChainGroth16VerificationKey,
    pub tw_keys: TrainingWheelsKeyPair,
    pub full_prover: Mutex<FullProver>,
}

impl ProverServiceState {
    pub fn init(deployment_information: DeploymentInformation) -> Self {
        let ProverServiceSecrets {
            private_key_0: private_key,
        } = Figment::new()
            .merge(Env::raw())
            .extract()
            .expect("Couldn't load private key from environment variable PRIVATE_KEY");

        ProverServiceState {
            config: CONFIG.clone(),
            circuit_metadata: CONFIG.load_circuit_params(),
            deployment_information,
            groth16_vk: CONFIG.load_test_verification_key(),
            tw_keys: TrainingWheelsKeyPair::from_sk(private_key),
            full_prover: Mutex::new(FullProver::new(&CONFIG.zkey_file_path()).unwrap()),
        }
    }

    /// Returns a reference to the circuit configuration
    pub fn circuit_config(&self) -> &CircuitConfig {
        &self.circuit_metadata
    }

    /// Returns a reference to the deployment information
    pub fn deployment_information(&self) -> &DeploymentInformation {
        &self.deployment_information
    }
}
