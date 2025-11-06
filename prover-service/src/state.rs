// Copyright (c) Aptos Foundation

use aptos_keyless_common::input_processing::config::CircuitConfig;
use rust_rapidsnark::FullProver;
use std::sync::Arc;

use crate::deployment_information::DeploymentInformation;
use crate::groth16_vk::OnChainGroth16VerificationKey;
use crate::prover_config::ProverServiceConfig;
use crate::prover_key::TrainingWheelsKeyPair;
use tokio::sync::Mutex;

pub struct ProverServiceState {
    pub prover_service_config: Arc<ProverServiceConfig>,
    pub circuit_config: CircuitConfig,
    pub deployment_information: DeploymentInformation,
    pub on_chain_groth16_verification_key: OnChainGroth16VerificationKey,
    pub training_wheels_key_pair: TrainingWheelsKeyPair,
    pub full_prover: Mutex<FullProver>,
}

impl ProverServiceState {
    pub fn init(
        training_wheels_key_pair: TrainingWheelsKeyPair,
        prover_service_config: Arc<ProverServiceConfig>,
        deployment_information: DeploymentInformation,
    ) -> Self {
        // Load the circuit configuration
        let circuit_configuration = prover_service_config.load_circuit_params();

        // Load the test verification key.
        // TODO: why is this called "test" verification key???
        let test_verification_key = prover_service_config.load_test_verification_key();

        // Create the full prover
        let full_prover = FullProver::new(&prover_service_config.zkey_file_path())
            .expect("Failed to create the full prover!");

        // Create the prover service state
        ProverServiceState {
            prover_service_config,
            circuit_config: circuit_configuration,
            deployment_information,
            on_chain_groth16_verification_key: test_verification_key,
            training_wheels_key_pair,
            full_prover: Mutex::new(full_prover),
        }
    }

    /// Returns a reference to the circuit configuration
    pub fn circuit_config(&self) -> &CircuitConfig {
        &self.circuit_config
    }

    /// Returns a reference to the deployment information
    pub fn deployment_information(&self) -> &DeploymentInformation {
        &self.deployment_information
    }
}
