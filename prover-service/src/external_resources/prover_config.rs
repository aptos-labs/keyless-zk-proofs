// Copyright (c) Aptos Foundation

use crate::external_resources::jwk_fetcher::JWKIssuer;
use crate::utils;
use aptos_keyless_common::input_processing::config::CircuitConfig;
use aptos_logger::info;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;

// Constants for the prover service configuration file
const CIRCUIT_CONFIG_YML_FILE_NAME: &str = "circuit_config.yml";
const GENERATE_WITNESS_JS_FILE_NAME: &str = "generate_witness.js";
const MAIN_WASM_FILE_NAME: &str = "main.wasm";

/// The prover service configuration
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(default, deny_unknown_fields)]
pub struct ProverServiceConfig {
    pub setup_dir: String,
    pub resources_dir: String, // Directory with prover/verification key and witness gen binary
    pub zkey_filename: String,
    pub verification_key_filename: String,
    pub witness_gen_binary_filename: String,
    pub jwk_issuers: Vec<JWKIssuer>,
    pub jwk_refresh_rate_secs: u64,
    pub port: u16,
    pub metrics_port: u16,
    #[serde(default)]
    pub enable_test_provider: bool,
    #[serde(default)]
    pub enable_federated_jwks: bool,
    #[serde(default)]
    pub use_insecure_jwk_for_test: bool,
    pub max_committed_epk_bytes: usize,
}

impl Default for ProverServiceConfig {
    fn default() -> Self {
        Self {
            setup_dir: "default".into(),                   // Default setup directory
            resources_dir: "/resources/ceremonies".into(), // Default resources directory
            zkey_filename: "prover_key.zkey".into(),       // Default zkey filename
            verification_key_filename: "verification_key.json".into(), // Default verification key filename
            witness_gen_binary_filename: "main_c".into(), // Default witness generation binary filename
            jwk_issuers: vec![],                          // No OIDC providers by default
            jwk_refresh_rate_secs: 10,                    // Refresh JWKs every 10 seconds
            port: 8083,                                   // Run the prover service on port 8083
            metrics_port: 9100,                           // Run the metrics service on port 9100
            enable_test_provider: false, // Don't enable the test OIDC provider by default
            enable_federated_jwks: false, // Disable federated JWKs by default
            use_insecure_jwk_for_test: false, // Don't use insecure JWK for testing by default
            max_committed_epk_bytes: 93, // 3 * BYTES_PACKED_PER_SCALAR (31) = 93
        }
    }
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

    /// Returns the full path to the verification key file
    pub fn verification_key_file_path(&self) -> String {
        let verification_key_file_path = self
            .setup_directory_path()
            .join(&self.verification_key_filename);
        shell_expand_tilde(verification_key_file_path)
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
}

/// Loads the prover service config from the specified file path.
/// If the file cannot be read or parsed, this function will panic.
pub fn load_prover_service_config(config_file_path: &str) -> Arc<ProverServiceConfig> {
    info!(
        "Loading the prover service config file from path: {}",
        config_file_path
    );

    // Read the config file contents
    let config_file_contents = utils::read_string_from_file_path(config_file_path);

    // Parse the config file contents into the config struct
    let prover_service_config = match serde_yaml::from_str(&config_file_contents) {
        Ok(prover_service_config) => {
            info!(
                "Loaded the prover service config: {:?}",
                prover_service_config
            );
            prover_service_config
        }
        Err(error) => panic!(
            "Failed to parse prover service config yaml file: {}! Error: {}",
            config_file_path, error
        ),
    };

    Arc::new(prover_service_config)
}

/// Expands the tilde in a given path
fn shell_expand_tilde(path_buf: PathBuf) -> String {
    match path_buf.to_str() {
        Some(path_str) => shellexpand::tilde(path_str).into(),
        None => panic!("Failed to convert path to string: {:?}", path_buf),
    }
}
