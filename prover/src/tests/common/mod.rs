// Copyright © Aptos Foundation

use self::types::{DefaultTestJWKKeyPair, TestJWKKeyPair, WithNonce};
use crate::load_vk::prepared_vk;
use crate::tests::common::types::ProofTestCase;
use crate::training_wheels;
use aptos_keyless_common::input_processing::{encoding::AsFr, config::CircuitPaddingConfig};
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
use rand::{rngs::ThreadRng, thread_rng};
use rust_rapidsnark::FullProver;
use serde::Serialize;
use std::{fs, marker::PhantomData, str::FromStr, sync::Arc};
use tokio::sync::Mutex;

pub mod types;

use crate::groth16_vk::{SnarkJsGroth16VerificationKey, ON_CHAIN_GROTH16_VK};
use crate::prover_key::{OnChainKeylessConfiguration, TrainingWheelsKeyPair, ON_CHAIN_TW_PK};

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

pub fn get_test_circuit_config() -> CircuitPaddingConfig {
    serde_yaml::from_str(&fs::read_to_string("conversion_config.yml").expect("Unable to read file"))
        .expect("should parse correctly")
}

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
    let mut rng = rsa::rand_core::OsRng;
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
    Figment::new()
        .merge(Yaml::file(config::LOCAL_TESTING_CONFIG_FILE_PATH))
        .extract()
        .expect("Couldn't load config file")
}

pub async fn convert_prove_and_verify(
    testcase: &ProofTestCase<impl Serialize + WithNonce + Clone>,
) -> Result<(), anyhow::Error> {
    let full_prover = init_test_full_prover(false);
    let full_prover_2 = init_test_full_prover(true);
    let circuit_config = get_test_circuit_config();
    let jwk_keypair = gen_test_jwk_keypair();
    let (tw_sk_default, _) = gen_test_training_wheels_keypair();
    let (tw_sk_new, tw_pk_new) = gen_test_training_wheels_keypair();
    let tw_keypair_default = TrainingWheelsKeyPair::from_sk(tw_sk_default);
    let tw_keypair_new = Some(TrainingWheelsKeyPair::from_sk(tw_sk_new));
    let prover_server_config = get_config();

    let new_vk = if prover_server_config.new_setup_dir.is_some() {
        let vk_json = fs::read_to_string(prover_server_config.verification_key_path(true)).unwrap();
        let local_vk: SnarkJsGroth16VerificationKey = serde_json::from_str(&vk_json).unwrap();
        Some(local_vk.try_as_onchain_repr().unwrap())
    } else {
        None
    };

    let dm: DashMap<KeyID, Arc<RSA_JWK>> =
        DashMap::from_iter([("test-rsa".to_owned(), Arc::new(jwk_keypair.into_rsa_jwk()))]);

    // Fill external resource caches.
    ON_CHAIN_GROTH16_VK.write().unwrap().clone_from(&new_vk);
    *ON_CHAIN_TW_PK.write().unwrap() = Some(OnChainKeylessConfiguration::from_tw_pk(Some(
        tw_pk_new.clone(),
    )));

    DECODING_KEY_CACHE.insert(String::from("test.oidc.provider"), dm);

    let state = ProverServiceState {
        full_prover_default: Mutex::new(full_prover),
        full_prover_new: Some(Mutex::new(full_prover_2)),
        new_groth16_vk: new_vk,
        tw_keypair_default,
        tw_keypair_new,
        config: prover_server_config.clone(),
        circuit_config: circuit_config.clone(),
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
            training_wheels::verify(&response, &tw_pk_new)
        }
        ProverServiceResponse::Error { message } => {
            panic!("returned ProverServiceResponse::Error: {}", message)
        }
    }
}
