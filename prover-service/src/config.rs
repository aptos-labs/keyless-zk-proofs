// Copyright © Aptos Foundation

use crate::groth16_vk::{OnChainGroth16VerificationKey, SnarkJsGroth16VerificationKey};
use figment::providers::{Env, Format, Yaml};
use figment::Figment;
use keyless_common::input_processing::config::CircuitConfig;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::fs;

pub const CONFIG_FILE_PATH: &str = "config.yml";
pub const LOCAL_TESTING_CONFIG_FILE_PATH: &str = "config_local_testing.yml";
pub const CONFIG_FILE_PATH_ENVVAR: &str = "CONFIG_FILE";

fn default_true() -> bool {
    true
}

#[derive(Debug, Serialize, Deserialize, Clone)]
//#[serde(deny_unknown_fields)]
pub struct ProverServiceConfig {
    pub git_commit: Option<String>,
    pub default_setup_dir: String,
    pub new_setup_dir: Option<String>,
    /// Directory with prover/verification key and witness gen binary
    pub resources_dir: String,
    pub zkey_filename: String,
    pub test_verification_key_filename: String,
    pub witness_gen_binary_filename: String,

    pub oidc_providers: Vec<OidcProvider>,
    pub jwk_refresh_rate_secs: u64,
    pub port: u16,
    pub metrics_port: u16,
    // Whether to log sensitive data
    pub enable_dangerous_logging: bool,
    pub enable_debug_checks: bool,
    #[serde(default)]
    pub enable_test_provider: bool,
    #[serde(default)]
    pub enable_federated_jwks: bool,
    #[serde(default = "default_true")]
    pub enable_jwt_iat_not_in_future_check: bool,
    #[serde(default = "default_true")]
    pub enable_jwt_exp_not_in_the_past_check: bool,
    #[serde(default)]
    pub use_insecure_jwk_for_test: bool,
}

pub static CONFIG: Lazy<ProverServiceConfig> = Lazy::new(|| {
    let config_file_path =
        std::env::var(CONFIG_FILE_PATH_ENVVAR).unwrap_or(String::from(CONFIG_FILE_PATH));

    Figment::new()
        .merge(Yaml::file(config_file_path))
        .merge(Env::raw())
        .extract()
        .unwrap()
});

impl ProverServiceConfig {
    pub fn setup_dir(&self, use_new_setup: bool) -> &String {
        if use_new_setup {
            self.new_setup_dir.as_ref().unwrap()
        } else {
            &self.default_setup_dir
        }
    }

    pub fn zkey_path(&self, use_new_setup: bool) -> String {
        shellexpand::tilde(
            &(String::from(&self.resources_dir)
                + "/"
                + self.setup_dir(use_new_setup)
                + "/"
                + &self.zkey_filename),
        )
        .into_owned()
    }

    pub fn witness_gen_binary_path(&self, use_new_setup: bool) -> String {
        shellexpand::tilde(
            &(String::from(&self.resources_dir)
                + "/"
                + self.setup_dir(use_new_setup)
                + "/"
                + &self.witness_gen_binary_filename),
        )
        .into_owned()
    }

    pub fn verification_key_path(&self, use_new_setup: bool) -> String {
        shellexpand::tilde(
            &(String::from(&self.resources_dir)
                + "/"
                + self.setup_dir(use_new_setup)
                + "/"
                + &self.test_verification_key_filename),
        )
        .into_owned()
    }

    pub fn witness_gen_js_path(&self, use_new_setup: bool) -> String {
        shellexpand::tilde(
            &(String::from(&self.resources_dir)
                + "/"
                + self.setup_dir(use_new_setup)
                + "/generate_witness.js"),
        )
        .into_owned()
    }

    pub fn witness_gen_wasm_path(&self, use_new_setup: bool) -> String {
        shellexpand::tilde(
            &(String::from(&self.resources_dir)
                + "/"
                + self.setup_dir(use_new_setup)
                + "/main.wasm"),
        )
        .into_owned()
    }

    pub fn circuit_config_path(&self, use_new_setup: bool) -> String {
        shellexpand::tilde(
            &(String::from(&self.resources_dir)
                + "/"
                + self.setup_dir(use_new_setup)
                + "/circuit_config.yml"),
        )
        .into_owned()
    }

    pub fn load_circuit_params(&self, use_new_setup: bool) -> CircuitConfig {
        let path = self.circuit_config_path(use_new_setup);
        let circuit_config_yaml = std::fs::read_to_string(path).unwrap();
        serde_yaml::from_str(&circuit_config_yaml).unwrap()
    }

    pub fn load_vk(&self, from_new_setup: bool) -> OnChainGroth16VerificationKey {
        let path = self.verification_key_path(from_new_setup);
        let vk_json = fs::read_to_string(path).unwrap();
        let local_vk: SnarkJsGroth16VerificationKey =
            serde_json::from_str(vk_json.as_str()).unwrap();
        local_vk.try_as_onchain_repr().unwrap()
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct OidcProvider {
    pub iss: String,
    pub endpoint_url: String,
}
