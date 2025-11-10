// Copyright (c) Aptos Foundation

use crate::deployment_information::DeploymentInformation;
use crate::groth16_vk::OnChainGroth16VerificationKey;
use crate::keyless_config::OnChainKeylessConfiguration;
use crate::prover_config::ProverServiceConfig;
use aptos_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
use aptos_keyless_common::input_processing::config::CircuitConfig;
use rust_rapidsnark::FullProver;
use std::sync::Arc;
use tokio::sync::Mutex;

/// The shared state of the prover service (used across all requests)
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

/// The training wheels key pair struct
#[derive(Debug)]
pub struct TrainingWheelsKeyPair {
    pub signing_key: Ed25519PrivateKey,
    pub verification_key: Ed25519PublicKey,
    pub on_chain_repr: OnChainKeylessConfiguration,
}

impl TrainingWheelsKeyPair {
    pub fn from_sk(sk: Ed25519PrivateKey) -> Self {
        let verification_key = Ed25519PublicKey::from(&sk);
        let on_chain_repr = OnChainKeylessConfiguration::from_tw_pk(Some(verification_key.clone()));

        Self {
            signing_key: sk,
            verification_key,
            on_chain_repr,
        }
    }
}
