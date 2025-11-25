// Copyright (c) Aptos Foundation

use self::types::{DefaultTestJWKKeyPair, TestJWKKeyPair, WithNonce};
use crate::external_resources::jwk_fetcher::Issuer;
use crate::external_resources::jwk_fetcher::KeyID;
use crate::external_resources::prover_config::ProverServiceConfig;
use crate::request_handler::deployment_information::DeploymentInformation;
use crate::request_handler::prover_state::{ProverServiceState, TrainingWheelsKeyPair};
use crate::request_handler::types::ProverServiceResponse;
use crate::request_handler::{handler, prover_handler};
use crate::tests::common::types::ProofTestCase;
use crate::{request_handler, training_wheels, utils};
use ::rsa::rand_core;
use aptos_crypto::{
    ed25519::{Ed25519PrivateKey, Ed25519PublicKey},
    encoding_type::EncodingType,
    Uniform,
};
use aptos_infallible::Mutex;
use aptos_keyless_common::input_processing::encoding::AsFr;
use aptos_logger::info;
use aptos_types::{
    jwks::rsa::RSA_JWK, keyless::Pepper, transaction::authenticator::EphemeralPublicKey,
};
use hyper::Body;
use rand::{rngs::ThreadRng, thread_rng};
use serde::Serialize;
use std::collections::HashMap;
use std::{str::FromStr, sync::Arc};
// TODO: clean up the existing tests, and add more tests!

pub mod rsa;
pub mod types;

// The name of the local testing config file
const LOCAL_TESTING_CONFIG_FILE_NAME: &str = "config_local_testing.yml";

const TEST_JWK_EXPONENT_STR: &str = "65537";

pub fn gen_test_ephemeral_pk() -> EphemeralPublicKey {
    let ephemeral_private_key: Ed25519PrivateKey = EncodingType::Hex
        .decode_key(
            "zkid test ephemeral private key",
            "0x76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7"
                .as_bytes()
                .to_vec(),
        )
        .unwrap();
    let ephemeral_public_key_unwrapped: Ed25519PublicKey =
        Ed25519PublicKey::from(&ephemeral_private_key);
    EphemeralPublicKey::ed25519(ephemeral_public_key_unwrapped)
}

pub fn gen_test_ephemeral_pk_blinder() -> ark_bn254::Fr {
    ark_bn254::Fr::from_str("42").unwrap()
}

pub fn gen_test_jwk_keypair() -> impl TestJWKKeyPair {
    gen_test_jwk_keypair_with_kid_override("test-rsa")
}

pub fn gen_test_jwk_keypair_with_kid_override(kid: &str) -> impl TestJWKKeyPair {
    let mut rng = rand_core::OsRng;
    DefaultTestJWKKeyPair::new_with_kid_and_exp(
        &mut rng,
        kid,
        num_bigint::BigUint::from_str(TEST_JWK_EXPONENT_STR).unwrap(),
    )
    .unwrap()
}

pub fn gen_test_training_wheels_keypair() -> (Ed25519PrivateKey, Ed25519PublicKey) {
    let mut csprng: ThreadRng = thread_rng();

    let priv_key = Ed25519PrivateKey::generate(&mut csprng);
    let pub_key: Ed25519PublicKey = (&priv_key).into();
    (priv_key, pub_key)
}

pub fn get_test_pepper() -> Pepper {
    Pepper::from_number(42)
}

pub fn get_config() -> ProverServiceConfig {
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

pub async fn convert_prove_and_verify(
    testcase: &ProofTestCase<impl Serialize + WithNonce + Clone>,
) -> Result<(), anyhow::Error> {
    let jwk_keypair = gen_test_jwk_keypair();
    let (tw_sk_default, tw_pk) = gen_test_training_wheels_keypair();

    let test_jwk: HashMap<KeyID, Arc<RSA_JWK>> =
        HashMap::from_iter([("test-rsa".to_owned(), Arc::new(jwk_keypair.into_rsa_jwk()))]);
    let jwk_cache: HashMap<Issuer, HashMap<KeyID, Arc<RSA_JWK>>> =
        HashMap::from_iter([("test.oidc.provider".into(), test_jwk)]);

    println!(
        "Prover service resources dir: {}",
        testcase.prover_service_config.resources_dir
    );
    println!(
        "Prover service setup dir: {}",
        testcase.prover_service_config.setup_dir
    );

    let prover_service_config = Arc::new(testcase.prover_service_config.clone());
    let state = ProverServiceState::init(
        TrainingWheelsKeyPair::from_sk(tw_sk_default),
        prover_service_config,
        DeploymentInformation::new(),
        Arc::new(Mutex::new(jwk_cache)),
    );

    let prover_request_input = testcase.convert_to_prover_request(&jwk_keypair);
    let serialized_prover_request_input = serde_json::to_string(&prover_request_input).unwrap();
    let prove_request = hyper::Request::new(Body::from(serialized_prover_request_input));

    println!(
        "Prover request: {}",
        serde_json::to_string_pretty(&prover_request_input).unwrap()
    );

    let prover_service_state = Arc::new(state);
    let prove_response = prover_handler::hande_prove_request(
        handler::MISSING_ORIGIN_STRING.into(),
        prove_request,
        prover_service_state,
    )
    .await;

    let response = match prove_response {
        Ok(response) => {
            let bytes = hyper::body::to_bytes(response.into_body())
                .await
                .expect("Couldn't read response body bytes");
            let body_str =
                String::from_utf8(bytes.to_vec()).expect("Response body not valid UTF-8");
            serde_json::from_str::<ProverServiceResponse>(&body_str)
                .expect("Couldn't deserialize prover response")
        }
        Err(e) => panic!("prove_handler returned an error: {:?}", e),
    };

    match response {
        ProverServiceResponse::Success {
            proof,
            public_inputs_hash,
            ..
        } => {
            let g16vk = request_handler::types::prepared_vk(
                &testcase.prover_service_config.verification_key_file_path(),
            )
            .unwrap();
            proof.verify_proof(public_inputs_hash.as_fr(), &g16vk)?;
            training_wheels::verify(&response, &tw_pk)
        }
        ProverServiceResponse::Error { message } => {
            panic!("returned ProverServiceResponse::Error: {}", message)
        }
    }
}
