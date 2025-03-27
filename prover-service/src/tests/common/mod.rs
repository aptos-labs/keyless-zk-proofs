// Copyright © Aptos Foundation

use self::types::{DefaultTestJWKKeyPair, TestJWKKeyPair, WithNonce};
use crate::load_vk::prepared_vk;
use crate::tests::common::types::ProofTestCase;
use crate::training_wheels;
use crate::{
    api::ProverServiceResponse,
    config::{self, ProverServiceConfig},
    handlers::prove_handler,
    jwk_fetching::{KeyID, DECODING_KEY_CACHE},
    state::ProverServiceState,
};
use aptos_crypto::{
    ed25519::{Ed25519PrivateKey, Ed25519PublicKey},
    encoding_type::EncodingType,
    Uniform,
};
use aptos_types::{
    jwks::rsa::RSA_JWK, keyless::Pepper, transaction::authenticator::EphemeralPublicKey,
};
use axum::{extract::State, Json};
use axum_extra::extract::WithRejection;
use dashmap::DashMap;
use figment::{
    providers::{Format as _, Yaml},
    Figment,
};
use keyless_common::input_processing::{config::CircuitConfig, encoding::AsFr};
use rand::{rngs::ThreadRng, thread_rng};
use rust_rapidsnark::FullProver;
use serde::Serialize;
use std::{fs, marker::PhantomData, str::FromStr, sync::Arc};
use tokio::sync::Mutex;

pub mod types;

use crate::groth16_vk::ON_CHAIN_GROTH16_VK;
use crate::prover_key::{TrainingWheelsKeyPair, ON_CHAIN_KEYLESS_CONFIG};
use crate::state::SetupSpecificState;

const TEST_JWK_EXPONENT_STR: &str = "65537";

pub fn init_test_full_prover(use_new_setup: bool) -> FullProver {
    let prover_server_config = Figment::new()
        .merge(Yaml::file(config::LOCAL_TESTING_CONFIG_FILE_PATH))
        .extract()
        .expect("Couldn't load config file");
    let config: ProverServiceConfig = prover_server_config;

    FullProver::new(&config.zkey_path(use_new_setup))
        .expect("failed to initialize rapidsnark prover")
}

pub fn get_test_circuit_config() -> CircuitConfig {
    serde_yaml::from_str(&fs::read_to_string("circuit_config.yml").expect("Unable to read file"))
        .expect("should parse correctly")
}

pub fn gen_test_ephemeral_pk() -> EphemeralPublicKey {
    let ephemeral_private_key: Ed25519PrivateKey = EncodingType::Hex
        .decode_key(
            "keyless test ephemeral private key",
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

pub fn gen_test_jwk_keypair() -> DefaultTestJWKKeyPair {
    gen_test_jwk_keypair_with_kid_override("test-rsa")
}

pub fn gen_test_jwk_keypair_with_kid_override(kid: &str) -> DefaultTestJWKKeyPair {
    let mut rng = rsa::rand_core::OsRng;
    DefaultTestJWKKeyPair::new_with_kid_and_exp(
        &mut rng,
        kid,
        num_bigint::BigUint::from_str(TEST_JWK_EXPONENT_STR).unwrap(),
    )
    .unwrap()
}

pub fn gen_test_training_wheels_keypair() -> TrainingWheelsKeyPair {
    let mut csprng: ThreadRng = thread_rng();

    let priv_key = Ed25519PrivateKey::generate(&mut csprng);

    TrainingWheelsKeyPair::from_sk(priv_key)
}

pub fn get_test_pepper() -> Pepper {
    Pepper::from_number(42)
}

pub fn get_config() -> ProverServiceConfig {
    Figment::new()
        .merge(Yaml::file(config::LOCAL_TESTING_CONFIG_FILE_PATH))
        .extract()
        .expect("Couldn't load config file")
}

pub async fn convert_prove_and_verify(
    testcase: &ProofTestCase<impl Serialize + WithNonce + Clone>,
) -> Result<(), anyhow::Error> {
    let jwk_keypair = gen_test_jwk_keypair();
    let tw_keypair_default = gen_test_training_wheels_keypair();
    let tw_keypair_new = gen_test_training_wheels_keypair();
    let tw_vk_new = tw_keypair_new.verification_key.clone();
    let prover_server_config = get_config();

    let new_vk = if prover_server_config.new_setup_dir.is_some() {
        Some(prover_server_config.load_vk(true))
    } else {
        None
    };

    let dm: DashMap<KeyID, Arc<RSA_JWK>> =
        DashMap::from_iter([("test-rsa".to_owned(), Arc::new(jwk_keypair.into_rsa_jwk()))]);

    // Fill external resource caches.
    ON_CHAIN_GROTH16_VK.write().unwrap().clone_from(&new_vk);
    *ON_CHAIN_KEYLESS_CONFIG.write().unwrap() = Some(tw_keypair_new.on_chain_repr.clone());

    DECODING_KEY_CACHE.insert(String::from("test.oidc.provider"), dm);

    let state = ProverServiceState {
        config: prover_server_config.clone(),
        default_setup: SetupSpecificState {
            config: get_test_circuit_config(),
            groth16_vk: prover_server_config.load_vk(false),
            tw_keys: tw_keypair_default,
            full_prover: Mutex::new(init_test_full_prover(false)),
        },
        new_setup: Some(SetupSpecificState {
            config: get_test_circuit_config(),
            groth16_vk: new_vk.unwrap(),
            tw_keys: tw_keypair_new,
            full_prover: Mutex::new(init_test_full_prover(true)),
        }),
    };

    let prover_request_input = testcase.convert_to_prover_request(&jwk_keypair);

    println!(
        "Prover request: {}",
        serde_json::to_string_pretty(&prover_request_input).unwrap()
    );

    let r = prove_handler(
        State(Arc::new(state)),
        WithRejection(Json(prover_request_input), PhantomData),
    )
    .await;
    let response = match r {
        Ok(Json(response)) => response,
        Err(e) => panic!("prove_handler returned an error: {:?}", e),
    };

    match response {
        ProverServiceResponse::Success {
            proof,
            public_inputs_hash,
            ..
        } => {
            let g16vk = prepared_vk(&prover_server_config.verification_key_path(true));
            proof.verify_proof(public_inputs_hash.as_fr(), &g16vk)?;
            training_wheels::verify(&response, &tw_vk_new)
        }
        ProverServiceResponse::Error { message } => {
            panic!("returned ProverServiceResponse::Error: {}", message)
        }
    }
}
