// Copyright (c) Aptos Foundation

use crate::external_resources::prover_config::ProverServiceConfig;
use crate::request_handler::training_wheels;
use crate::request_handler::types::{EphemeralPublicKeyBlinder, RequestInput};
use crate::tests::utils::{RsaPrivateKey, RsaPublicKey};
use crate::utils;
use aptos_crypto::ed25519::Ed25519PrivateKey;
use aptos_crypto::encoding_type::EncodingType;
use aptos_crypto::PrivateKey;
use aptos_keyless_common::input_processing::encoding::FromFr;
use aptos_logger::info;
use aptos_types::{
    jwks::rsa::RSA_JWK, keyless::Pepper, transaction::authenticator::EphemeralPublicKey,
};
use jsonwebtoken::{Algorithm, Header};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

// The name of the local testing config file
const LOCAL_TESTING_CONFIG_FILE_NAME: &str = "config_local_testing.yml";

// Ensures that the local testing setup has been procured
static LOCAL_SETUP_PROCURED: Lazy<bool> = Lazy::new(|| {
    // Determine the repository root directory
    let mut repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root_found = repo_root.pop();

    // Run the setup script to procure the local testing setup
    if repo_root_found {
        Command::new("bash")
            .arg("scripts/task.sh")
            .arg("setup")
            .arg("procure-testing-setup")
            .current_dir(repo_root)
            .status()
            .is_ok()
    } else {
        false
    }
});

/// JWT payload struct for testing
#[derive(Serialize, Deserialize, Clone)]
pub struct TestJWTPayload {
    pub azp: String,
    pub aud: String,
    pub sub: Option<String>,
    pub email: Option<String>,
    pub hd: String,
    pub email_verified: Option<bool>,
    pub at_hash: String,
    pub name: String,
    pub picture: String,
    pub given_name: String,
    pub family_name: String,
    pub locale: String,
    pub iss: String,
    pub iat: u64,
    pub exp: u64,
    pub nonce: String,
}

impl TestJWTPayload {
    /// Creates a new TestJWTPayload with the given nonce
    fn new_with_nonce(&self, nonce: &str) -> Self {
        Self {
            nonce: String::from(nonce),
            ..self.clone()
        }
    }
}

impl Default for TestJWTPayload {
    fn default() -> Self {
        let start = SystemTime::now();
        let since_the_epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");

        TestJWTPayload {
        azp: String::from("407408718192.apps.googleusercontent.com"),
        aud: String::from("407408718192.apps.googleusercontent.com"),
        sub: Some(String::from("113990307082899718775")),
        email: Some(String::from("michael@aptoslabs.com")),
        hd: String::from("aptoslabs.com"),
        email_verified: Some(true),
        at_hash: String::from("bxIESuI59IoZb5alCASqBg"),
        name: String::from("Michael Straka"),
        picture: String::from("https://lh3.googleusercontent.com/a/ACg8ocJvY4kVUBRtLxe1IqKWL5i7tBDJzFp9YuWVXMzwPpbs=s96-c"),
        given_name: String::from("Michael"),
        family_name: String::from("Straka"),
        locale: String::from("en"),
        iss: String::from("test.oidc.provider"),
        iat: 0,
        exp: since_the_epoch.as_secs() + 3600,
        nonce: String::from(""),
    }
    }
}

/// Trait for test JWK key pairs
pub trait TestJWKKeyPair {
    fn pubkey_mod_b64(&self) -> String;
    fn kid(&self) -> &str;
    fn sign(&self, payload: &impl Serialize) -> String;
    fn get_rsa_jwk(&self) -> RSA_JWK;
}

/// Default implementation of TestJWKKeyPair using RSA keys
pub struct DefaultTestJWKKeyPair {
    kid: String,
    private_key: RsaPrivateKey,
}

impl DefaultTestJWKKeyPair {
    pub fn new_with_kid_and_exp<R>(
        rng: &mut R,
        kid: &str,
        exp: num_bigint::BigUint,
    ) -> Result<Self, anyhow::Error>
    where
        R: rsa::rand_core::CryptoRngCore + Sized,
    {
        Ok(Self {
            kid: String::from(kid),
            private_key: RsaPrivateKey::new_with_exp(rng, 2048, &exp)?,
        })
    }
}

impl TestJWKKeyPair for DefaultTestJWKKeyPair {
    fn pubkey_mod_b64(&self) -> String {
        RsaPublicKey::from(&self.private_key).as_mod_b64()
    }

    fn kid(&self) -> &str {
        &self.kid
    }

    #[allow(clippy::field_reassign_with_default)]
    fn sign(&self, payload: &impl Serialize) -> String {
        // Create the JWT header
        let mut header = Header::default();
        header.alg = Algorithm::RS256;
        header.kid = Some(self.kid.clone());

        // Create the JWT
        let jwt =
            jsonwebtoken::encode(&header, &payload, &self.private_key.as_encoding_key()).unwrap();

        // Verify the signature before returning (to ensure correctness)
        let jwk = RSA_JWK::new_256_aqab(self.kid.as_str(), &self.pubkey_mod_b64());
        assert!(jwk.verify_signature_without_exp_check(&jwt).is_ok());

        jwt
    }

    fn get_rsa_jwk(&self) -> RSA_JWK {
        RSA_JWK::new_256_aqab(&self.kid, &self.pubkey_mod_b64())
    }
}

/// Struct representing a proof test case
#[derive(Clone)]
pub struct ProofTestCase {
    pub prover_service_config: ProverServiceConfig,
    pub jwt_payload: TestJWTPayload,
    pub epk: EphemeralPublicKey,
    pub epk_blinder_fr: ark_bn254::Fr,
    pub pepper: Pepper,
    pub epk_expiry_time_secs: u64,
    pub epk_expiry_horizon_secs: u64,
    pub extra_field: Option<String>,
    pub uid_key: String,
    pub idc_aud: Option<String>,
    pub skip_aud_checks: bool,
}

impl ProofTestCase {
    /// Creates a default test case with the given JWT payload
    pub fn default_with_payload(jwt_payload: TestJWTPayload) -> Self {
        // Ensure that the local setup has been procured
        assert!(*LOCAL_SETUP_PROCURED);

        // Generate test ephemeral public key and blinder
        let epk = generate_test_ephemeral_pk();
        let epk_blinder = ark_bn254::Fr::from_str("42").unwrap();
        let pepper = Pepper::from_number(42);

        Self {
            prover_service_config: get_prover_service_config(),
            jwt_payload,
            epk,
            epk_blinder_fr: epk_blinder,
            pepper,
            epk_expiry_time_secs: 0,
            epk_expiry_horizon_secs: 100,
            extra_field: Some("name".into()),
            uid_key: "email".into(),
            idc_aud: None,
            skip_aud_checks: false,
        }
    }

    /// Computes the nonce and returns a new test case with the updated JWT payload
    pub fn compute_nonce(self) -> Self {
        // Ensure that the local setup has been procured
        assert!(*LOCAL_SETUP_PROCURED);

        // Compute the nonce
        let circuit_metadata = self.prover_service_config.load_circuit_params();
        let nonce = training_wheels::compute_nonce(
            self.epk_expiry_time_secs,
            &self.epk,
            self.epk_blinder_fr,
            &circuit_metadata,
        )
        .unwrap();

        // Create a new payload with the nonce
        let jwt_payload = self.jwt_payload.new_with_nonce(&nonce.to_string());

        Self {
            jwt_payload,
            ..self
        }
    }

    /// Converts the test case to a prover request input
    pub fn convert_to_prover_request(&self, jwk_keypair: &impl TestJWKKeyPair) -> RequestInput {
        RequestInput {
            jwt_b64: jwk_keypair.sign(&self.jwt_payload),
            epk: self.epk.clone(),
            epk_blinder: EphemeralPublicKeyBlinder::from_fr(&self.epk_blinder_fr),
            exp_date_secs: self.epk_expiry_time_secs,
            exp_horizon_secs: self.epk_expiry_horizon_secs,
            pepper: self.pepper.clone(),
            uid_key: self.uid_key.clone(),
            extra_field: self.extra_field.clone(),
            idc_aud: self.idc_aud.clone(),
            use_insecure_test_jwk: false,
            skip_aud_checks: self.skip_aud_checks,
        }
    }
}

/// Generates a test ephemeral public key
fn generate_test_ephemeral_pk() -> EphemeralPublicKey {
    // Generate a test Ed25519 ephemeral keypair
    let ed25519_private_key: Ed25519PrivateKey = EncodingType::Hex
        .decode_key(
            "zkid test ephemeral private key",
            "0x76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7"
                .as_bytes()
                .to_vec(),
        )
        .unwrap();
    let ed25519_public_key = ed25519_private_key.public_key();

    // Return the ephemeral public key
    EphemeralPublicKey::ed25519(ed25519_public_key)
}

/// Loads and returns the prover service config for local testing
fn get_prover_service_config() -> ProverServiceConfig {
    // Read the config file contents
    let config_file_contents = utils::read_string_from_file_path(LOCAL_TESTING_CONFIG_FILE_NAME);

    // Parse the config file contents into the config struct
    match serde_yaml::from_str(&config_file_contents) {
        Ok(prover_service_config) => {
            info!(
                "Loaded the prover service config: {:?}",
                prover_service_config
            );
            prover_service_config
        }
        Err(error) => panic!(
            "Failed to parse prover service config yaml file: {}! Error: {}",
            LOCAL_TESTING_CONFIG_FILE_NAME, error
        ),
    }
}
