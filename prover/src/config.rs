// Copyright © Aptos Foundation

use serde::{Deserialize, Serialize};

pub const CONFIG_FILE_PATH: &str = "config.yml";
pub const LOCAL_TESTING_CONFIG_FILE_PATH: &str = "config_local_testing.yml";
pub const CONFIG_FILE_PATH_ENVVAR: &str = "CONFIG_FILE";

#[derive(Debug, Serialize, Deserialize, Clone)]
//#[serde(deny_unknown_fields)]
pub struct ProverServiceConfig {
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
    #[serde(default)]
    pub disable_iat_in_past_check: bool,
    #[serde(default)]
    pub use_insecure_jwk_for_test: bool,
}

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
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct OidcProvider {
    pub iss: String,
    pub endpoint_url: String,
}
