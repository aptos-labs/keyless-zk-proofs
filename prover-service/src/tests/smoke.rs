// Copyright (c) Aptos Foundation

use crate::external_resources::jwk_types::{FederatedJWKs, Issuer, KeyID};
use crate::request_handler;
use crate::request_handler::deployment_information::DeploymentInformation;
use crate::request_handler::prover_state::{ProverServiceState, TrainingWheelsKeyPair};
use crate::request_handler::types::ProverServiceResponse;
use crate::request_handler::{handler, prover_handler, training_wheels, types};
use crate::tests::types::TestJWKKeyPair;
use crate::tests::types::{ProofTestCase, TestJWTPayload, WithNonce};
use crate::tests::utils;
use aptos_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
use aptos_crypto::Uniform;
use aptos_infallible::Mutex;
use aptos_keyless_common::input_processing::encoding::AsFr;
use aptos_types::jwks::rsa::RSA_JWK;
use hyper::Body;
use rand::prelude::ThreadRng;
use rand::thread_rng;
use rust_rapidsnark::FullProver;
use serde::Serialize;
use serial_test::serial;
use std::collections::HashMap;
use std::sync::Arc;

#[tokio::test]
#[serial]
async fn default_request() {
    let testcase = ProofTestCase::default_with_payload(TestJWTPayload::default()).compute_nonce();

    convert_prove_and_verify(&testcase).await.unwrap();
}

#[tokio::test]
#[serial]
async fn request_with_email() {
    let jwt_payload = TestJWTPayload {
        ..TestJWTPayload::default()
    };

    let testcase = ProofTestCase {
        uid_key: String::from("email"),
        ..ProofTestCase::default_with_payload(jwt_payload)
    }
    .compute_nonce();
    convert_prove_and_verify(&testcase).await.unwrap();
}

#[tokio::test]
#[serial]
async fn request_with_no_extra_field() {
    let jwt_payload = TestJWTPayload {
        ..TestJWTPayload::default()
    };

    let testcase = ProofTestCase {
        extra_field: None,
        ..ProofTestCase::default_with_payload(jwt_payload)
    }
    .compute_nonce();
    convert_prove_and_verify(&testcase).await.unwrap();
}

#[tokio::test]
#[serial]
async fn request_with_aud_recovery() {
    let jwt_payload = TestJWTPayload {
        ..TestJWTPayload::default()
    };

    let testcase = ProofTestCase {
        idc_aud: Some(String::from("original")),
        ..ProofTestCase::default_with_payload(jwt_payload)
    }
    .compute_nonce();
    convert_prove_and_verify(&testcase).await.unwrap();
}

#[tokio::test]
#[serial]
#[should_panic]
async fn request_sub_is_required_in_jwt() {
    let jwt_payload = TestJWTPayload {
        sub: None,
        ..TestJWTPayload::default()
    };

    let testcase = ProofTestCase {
        uid_key: String::from("email"),
        ..ProofTestCase::default_with_payload(jwt_payload)
    }
    .compute_nonce();
    convert_prove_and_verify(&testcase).await.unwrap();
}

#[tokio::test]
#[serial]
async fn request_with_sub() {
    let jwt_payload = TestJWTPayload {
        email: None,
        ..TestJWTPayload::default()
    };

    let testcase = ProofTestCase {
        uid_key: String::from("sub"),
        ..ProofTestCase::default_with_payload(jwt_payload)
    }
    .compute_nonce();
    convert_prove_and_verify(&testcase).await.unwrap();
}

#[tokio::test]
#[serial]
async fn request_with_sub_no_email_verified() {
    let jwt_payload = TestJWTPayload {
        email: None,
        email_verified: None,
        ..TestJWTPayload::default()
    };

    let testcase = ProofTestCase {
        uid_key: String::from("sub"),
        ..ProofTestCase::default_with_payload(jwt_payload)
    }
    .compute_nonce();
    convert_prove_and_verify(&testcase).await.unwrap();
}

#[tokio::test]
#[serial]
#[should_panic]
async fn request_with_wrong_uid_key() {
    let jwt_payload = TestJWTPayload {
        email: None,
        ..TestJWTPayload::default()
    };

    let testcase = ProofTestCase {
        uid_key: String::from("email"),
        ..ProofTestCase::default_with_payload(jwt_payload)
    }
    .compute_nonce();

    convert_prove_and_verify(&testcase).await.unwrap();
}

#[tokio::test]
#[serial]
#[should_panic]
async fn request_with_invalid_exp_date() {
    let jwt_payload = TestJWTPayload {
        ..TestJWTPayload::default()
    };

    let testcase = ProofTestCase {
        epk_expiry_horizon_secs: 100,
        epk_expiry_time_secs: 200,
        ..ProofTestCase::default_with_payload(jwt_payload)
    }
    .compute_nonce();

    convert_prove_and_verify(&testcase).await.unwrap();
}

#[tokio::test]
#[serial]
async fn request_jwt_exp_field_does_not_matter() {
    let jwt_payload = TestJWTPayload {
        exp: 234342342428348284,
        ..TestJWTPayload::default()
    };

    let testcase = ProofTestCase {
        ..ProofTestCase::default_with_payload(jwt_payload)
    }
    .compute_nonce();

    convert_prove_and_verify(&testcase).await.unwrap();
}

#[tokio::test]
#[serial]
#[should_panic]
async fn request_with_incorrect_nonce() {
    let jwt_payload = TestJWTPayload {
        nonce: String::from(""),
        ..TestJWTPayload::default()
    };

    let testcase = ProofTestCase {
        uid_key: String::from("email"),
        ..ProofTestCase::default_with_payload(jwt_payload)
    };
    convert_prove_and_verify(&testcase).await.unwrap();
}

#[tokio::test]
#[serial]
#[ignore]
async fn request_all_sub_lengths() {
    // to catch the "capacity overflow" bug (fixed). Disabled right now because it takes a long
    // time to finish.
    for i in 0..65 {
        let jwt_payload = TestJWTPayload {
            sub: Some("a".repeat(i)),
            ..TestJWTPayload::default()
        };

        let testcase = ProofTestCase::default_with_payload(jwt_payload).compute_nonce();

        convert_prove_and_verify(&testcase).await.unwrap();
    }
}

#[test]
#[ignore]
fn dummy_circuit_load_test() {
    let prover = FullProver::new("./resources/toy_circuit/toy_1.zkey").unwrap();

    for _i in 0..1000 {
        let (proof_json, _) = prover.prove("./resources/toy_circuit/toy.wtns").unwrap();

        let proof = types::encode_proof(&serde_json::from_str(proof_json).unwrap()).unwrap();
        let g16vk = types::prepared_vk("./resources/toy_circuit/toy_vk.json").unwrap();
        proof.verify_proof(2.into(), &g16vk).unwrap();
    }
}

async fn convert_prove_and_verify(
    testcase: &ProofTestCase<impl Serialize + WithNonce + Clone>,
) -> Result<(), anyhow::Error> {
    // Start the aptos logger (so test failures print logs)
    aptos_logger::Logger::init_for_testing();

    let jwk_keypair = utils::gen_test_jwk_keypair();
    let (tw_sk_default, tw_pk) = gen_test_training_wheels_keypair();

    let test_jwk: HashMap<KeyID, Arc<RSA_JWK>> =
        HashMap::from_iter([("test-rsa".to_owned(), Arc::new(jwk_keypair.into_rsa_jwk()))]);
    let jwk_cache: HashMap<Issuer, HashMap<KeyID, Arc<RSA_JWK>>> =
        HashMap::from_iter([("test.oidc.provider".into(), test_jwk)]);
    let federated_jwks = FederatedJWKs::new_empty();

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
        federated_jwks,
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
            training_wheels::verify(&response, &tw_pk).map_err(|error| {
                anyhow::anyhow!("Failed to verify training wheels signature: {}", error)
            })
        }
        ProverServiceResponse::Error { message } => {
            panic!("returned ProverServiceResponse::Error: {}", message)
        }
    }
}

pub fn gen_test_training_wheels_keypair() -> (Ed25519PrivateKey, Ed25519PublicKey) {
    let mut csprng: ThreadRng = thread_rng();

    let priv_key = Ed25519PrivateKey::generate(&mut csprng);
    let pub_key: Ed25519PublicKey = (&priv_key).into();
    (priv_key, pub_key)
}
