// Copyright (c) Aptos Foundation

use crate::groth16_vk::{OnChainGroth16VerificationKey, SnarkJsGroth16VerificationKey};
use crate::utils;
use aptos_keyless_common::input_processing::config::CircuitConfig;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// Constants for the prover service configuration file
const CIRCUIT_CONFIG_YML_FILE_NAME: &str = "circuit_config.yml";
const GENERATE_WITNESS_JS_FILE_NAME: &str = "generate_witness.js";
const MAIN_WASM_FILE_NAME: &str = "main.wasm";

/// A simple struct representing an OIDC provider
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct OidcProvider {
    pub iss: String,
    pub endpoint_url: String,
}

/// The prover service configuration
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ProverServiceConfig {
    pub setup_dir: String,
    pub resources_dir: String, // Directory with prover/verification key and witness gen binary
    pub zkey_filename: String,
    pub test_verification_key_filename: String,
    pub witness_gen_binary_filename: String,
    pub oidc_providers: Vec<OidcProvider>,
    pub jwk_refresh_rate_secs: u64,
    pub port: u16,
    pub metrics_port: u16,
    pub enable_debug_checks: bool,
    #[serde(default)]
    pub enable_test_provider: bool,
    #[serde(default)]
    pub enable_federated_jwks: bool,
    #[serde(default)]
    pub use_insecure_jwk_for_test: bool,
}

impl ProverServiceConfig {
    /// Returns the full path to the setup directory
    fn setup_directory_path(&self) -> PathBuf {
        PathBuf::from(&self.resources_dir).join(&self.setup_dir)
    }

    /// Returns the full path to the zkey file
    pub fn zkey_file_path(&self) -> String {
        let zkey_file_path = self.setup_directory_path().join(&self.zkey_filename);
        shell_expand_tilde(zkey_file_path)
    }

    /// Returns the full path to the witness generation binary
    pub fn witness_gen_binary_file_path(&self) -> String {
        let witness_gen_binary_file_path = self
            .setup_directory_path()
            .join(&self.witness_gen_binary_filename);
        shell_expand_tilde(witness_gen_binary_file_path)
    }

    /// Returns the full path to the test verification key file
    pub fn test_verification_key_file_path(&self) -> String {
        let test_verification_key_file_path = self
            .setup_directory_path()
            .join(&self.test_verification_key_filename);
        shell_expand_tilde(test_verification_key_file_path)
    }

    /// Returns the full path to the witness generation JS file
    pub fn witness_gen_js_file_path(&self) -> String {
        let witness_gen_js_file_path = self
            .setup_directory_path()
            .join(GENERATE_WITNESS_JS_FILE_NAME);
        shell_expand_tilde(witness_gen_js_file_path)
    }

    /// Returns the full path to the witness generation WASM file
    pub fn witness_gen_wasm_file_path(&self) -> String {
        let witness_gen_wasm_file_path = self.setup_directory_path().join(MAIN_WASM_FILE_NAME);
        shell_expand_tilde(witness_gen_wasm_file_path)
    }

    /// Returns the full path to the circuit configuration file
    pub fn circuit_config_file_path(&self) -> String {
        let circuit_config_file_path = self
            .setup_directory_path()
            .join(CIRCUIT_CONFIG_YML_FILE_NAME);
        shell_expand_tilde(circuit_config_file_path)
    }

    /// Loads the circuit parameters from the configuration file
    pub fn load_circuit_params(&self) -> CircuitConfig {
        // Load the yaml file
        let circuit_config_file_path = self.circuit_config_file_path();
        let circuit_config_yaml = utils::read_string_from_file_path(&circuit_config_file_path);

        // Deserialize the yaml content into a config
        match serde_yaml::from_str(&circuit_config_yaml) {
            Ok(config) => config,
            Err(error) => panic!(
                "Failed to parse circuit config yaml file: {}! Error: {}",
                circuit_config_file_path, error
            ),
        }
    }

    /// Loads the test Groth16 verification key from the configuration file
    pub fn load_test_verification_key(&self) -> OnChainGroth16VerificationKey {
        // Load the json file
        let test_verification_key_file_path = self.test_verification_key_file_path();
        let test_verification_key_json =
            utils::read_string_from_file_path(&test_verification_key_file_path);

        // Deserialize the json content into a snarkjs key
        let snarkjs_groth16_verification_key = match serde_json::from_str::<
            SnarkJsGroth16VerificationKey,
        >(&test_verification_key_json)
        {
            Ok(snarkjs_groth16_verification_key) => snarkjs_groth16_verification_key,
            Err(error) => panic!(
                "Failed to parse test verification key json file: {}! Error: {}",
                test_verification_key_file_path, error
            ),
        };

        // Convert the key to the on-chain representation
        match snarkjs_groth16_verification_key.try_as_onchain_repr() {
            Ok(on_chain_groth16_verification_key) => on_chain_groth16_verification_key,
            Err(error) => panic!(
                "Failed to convert test verification key to on-chain representation! Error: {}",
                error
            ),
        }
    }
}

/// Expands the tilde in a given path
fn shell_expand_tilde(path_buf: PathBuf) -> String {
    match path_buf.to_str() {
        Some(path_str) => shellexpand::tilde(path_str).into(),
        None => panic!("Failed to convert path to string: {:?}", path_buf),
    }
}
