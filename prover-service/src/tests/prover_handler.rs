// Copyright (c) Aptos Foundation

use crate::external_resources::jwk_types::{FederatedJWKs, Issuer, KeyID};
use crate::request_handler::deployment_information::DeploymentInformation;
use crate::request_handler::prover_state::{ProverServiceState, TrainingWheelsKeyPair};
use crate::request_handler::types::ProverServiceResponse;
use crate::request_handler::{handler, prover_handler, training_wheels, types};
use crate::tests::types::TestJWKKeyPair;
use crate::tests::types::{ProofTestCase, TestJWTPayload};
use crate::tests::utils;
use anyhow::anyhow;
use aptos_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
use aptos_crypto::{PrivateKey, Uniform};
use aptos_infallible::Mutex;
use aptos_keyless_common::input_processing::encoding::AsFr;
use aptos_types::jwks::rsa::RSA_JWK;
use hyper::{body, Body};
use rand::prelude::ThreadRng;
use rand::thread_rng;
use rust_rapidsnark::FullProver;
use serial_test::serial;
use std::collections::HashMap;
use std::sync::Arc;

#[tokio::test]
#[serial]
async fn prove_default_request() {
    // Create a default JWT payload
    let jwt_payload = TestJWTPayload::default();
    let testcase = ProofTestCase::default_with_payload(jwt_payload).compute_nonce();

    // Handle the prove request, and verify the proof
    convert_prove_and_verify(&testcase).await.unwrap();
}

#[tokio::test]
#[serial]
async fn prove_request_with_email() {
    // Create a default JWT payload with an email field
    let jwt_payload = TestJWTPayload::default();
    let testcase = ProofTestCase {
        uid_key: String::from("email"),
        ..ProofTestCase::default_with_payload(jwt_payload)
    }
    .compute_nonce();

    // Handle the prove request, and verify the proof
    convert_prove_and_verify(&testcase).await.unwrap();
}

#[tokio::test]
#[serial]
async fn prove_request_with_no_extra_field() {
    // Create a default JWT payload without any extra field
    let jwt_payload = TestJWTPayload::default();
    let testcase = ProofTestCase {
        extra_field: None,
        ..ProofTestCase::default_with_payload(jwt_payload)
    }
    .compute_nonce();
    convert_prove_and_verify(&testcase).await.unwrap();
}

#[tokio::test]
#[serial]
async fn prove_request_with_aud_recovery() {
    // Create a default JWT payload with an audience field
    let jwt_payload = TestJWTPayload::default();
    let testcase = ProofTestCase {
        idc_aud: Some(String::from("original")),
        ..ProofTestCase::default_with_payload(jwt_payload)
    }
    .compute_nonce();

    // Handle the prove request, and verify the proof
    convert_prove_and_verify(&testcase).await.unwrap();
}

#[tokio::test]
#[serial]
#[should_panic]
async fn prove_request_sub_is_required_in_jwt() {
    // Create a JWT payload without a sub field
    let jwt_payload = TestJWTPayload {
        sub: None,
        ..TestJWTPayload::default()
    };
    let testcase = ProofTestCase {
        uid_key: String::from("email"),
        ..ProofTestCase::default_with_payload(jwt_payload)
    }
    .compute_nonce();

    // Handle the prove request, and verify the proof
    convert_prove_and_verify(&testcase).await.unwrap();
}

#[tokio::test]
#[serial]
async fn prove_request_with_sub() {
    // Create a JWT payload without an email field
    let jwt_payload = TestJWTPayload {
        email: None,
        ..TestJWTPayload::default()
    };
    let testcase = ProofTestCase {
        uid_key: String::from("sub"),
        ..ProofTestCase::default_with_payload(jwt_payload)
    }
    .compute_nonce();

    // Handle the prove request, and verify the proof
    convert_prove_and_verify(&testcase).await.unwrap();
}

#[tokio::test]
#[serial]
async fn prove_request_with_sub_no_email_verified() {
    // Create a JWT payload without an email or email_verified field
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

    // Handle the prove request, and verify the proof
    convert_prove_and_verify(&testcase).await.unwrap();
}

#[tokio::test]
#[serial]
#[should_panic]
async fn prove_request_with_wrong_uid_key() {
    // Create a JWT payload without an email field
    let jwt_payload = TestJWTPayload {
        email: None,
        ..TestJWTPayload::default()
    };
    let testcase = ProofTestCase {
        uid_key: String::from("email"),
        ..ProofTestCase::default_with_payload(jwt_payload)
    }
    .compute_nonce();

    // Handle the prove request, and verify the proof
    convert_prove_and_verify(&testcase).await.unwrap();
}

#[tokio::test]
#[serial]
#[should_panic]
async fn prove_request_with_invalid_exp_date() {
    // Create a default JWT payload with an invalid exp date
    let jwt_payload = TestJWTPayload::default();
    let testcase = ProofTestCase {
        epk_expiry_horizon_secs: 100,
        epk_expiry_time_secs: 200,
        ..ProofTestCase::default_with_payload(jwt_payload)
    }
    .compute_nonce();

    // Handle the prove request, and verify the proof
    convert_prove_and_verify(&testcase).await.unwrap();
}

#[tokio::test]
#[serial]
async fn request_jwt_exp_field_does_not_matter() {
    // Create a JWT payload with a far future exp date
    let jwt_payload = TestJWTPayload {
        exp: 234342342428348284,
        ..TestJWTPayload::default()
    };
    let testcase = ProofTestCase::default_with_payload(jwt_payload).compute_nonce();

    // Handle the prove request, and verify the proof
    convert_prove_and_verify(&testcase).await.unwrap();
}

#[tokio::test]
#[serial]
#[should_panic]
async fn request_with_incorrect_nonce() {
    // Create a JWT payload with an invalid nonce
    let jwt_payload = TestJWTPayload {
        nonce: String::from(""),
        ..TestJWTPayload::default()
    };
    let testcase = ProofTestCase {
        uid_key: String::from("email"),
        ..ProofTestCase::default_with_payload(jwt_payload)
    };

    // Handle the prove request, and verify the proof
    convert_prove_and_verify(&testcase).await.unwrap();
}

#[tokio::test]
#[serial]
#[ignore] // Currently ignored because it takes a long time to run
async fn prove_request_all_sub_lengths() {
    for i in 0..65 {
        // Create a JWT payload with varying lengths of the sub field
        let jwt_payload = TestJWTPayload {
            sub: Some("a".repeat(i)),
            ..TestJWTPayload::default()
        };
        let testcase = ProofTestCase::default_with_payload(jwt_payload).compute_nonce();

        // Handle the prove request, and verify the proof
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

/// Helper function that converts a test case to a prover request,
/// sends it to the prover handler, and verifies the returned proof.
async fn convert_prove_and_verify(testcase: &ProofTestCase) -> Result<(), anyhow::Error> {
    // Start the aptos logger (so test failures print logs)
    aptos_logger::Logger::init_for_testing();

    // Generate the JWK keypair and training wheels keypair
    let jwk_keypair = utils::generate_test_jwk_keypair();
    let (training_wheels_sk, training_wheels_pk) = generate_ed25519_keypair();
    let training_wheels_keypair = TrainingWheelsKeyPair::from_sk(training_wheels_sk);

    // Create the JWK cache with the test JWK
    let test_jwk: HashMap<KeyID, Arc<RSA_JWK>> =
        HashMap::from_iter([("test-rsa".to_owned(), Arc::new(jwk_keypair.get_rsa_jwk()))]);
    let jwk_cache: HashMap<Issuer, HashMap<KeyID, Arc<RSA_JWK>>> =
        HashMap::from_iter([("test.oidc.provider".into(), test_jwk)]);

    // Create empty federated JWKs
    let federated_jwks = FederatedJWKs::new_empty();

    // Initialize the prover service state
    let prover_service_config = Arc::new(testcase.prover_service_config.clone());
    let prover_service_state = ProverServiceState::init(
        training_wheels_keypair,
        prover_service_config,
        DeploymentInformation::new(),
        Arc::new(Mutex::new(jwk_cache)),
        federated_jwks,
    );

    // Create the prover request
    let prover_request_input = testcase.convert_to_prover_request(&jwk_keypair);
    let serialized_prover_request_input = serde_json::to_string(&prover_request_input).unwrap();
    let prove_request = hyper::Request::new(Body::from(serialized_prover_request_input));

    // Send the prove request to the prover handler
    let result = prover_handler::hande_prove_request(
        handler::MISSING_ORIGIN_STRING.into(),
        prove_request,
        Arc::new(prover_service_state),
    )
    .await;

    // Parse the prover response
    let prover_service_response = match result {
        Ok(response) => {
            let response_bytes = body::to_bytes(response.into_body()).await?;
            let response_body = String::from_utf8(response_bytes.to_vec())?;
            serde_json::from_str::<ProverServiceResponse>(&response_body)?
        }
        Err(error) => panic!("The prove handler returned an error! Error: {:?}", error),
    };

    // Process the prover service response
    match prover_service_response {
        ProverServiceResponse::Success {
            proof: groth16_proof,
            public_inputs_hash,
            ..
        } => {
            // Verify the returned proof
            let groth16_vk =
                types::prepared_vk(&testcase.prover_service_config.verification_key_file_path())
                    .unwrap();
            groth16_proof.verify_proof(public_inputs_hash.as_fr(), &groth16_vk)?;

            // Verify the training wheels signature
            training_wheels::verify(&prover_service_response, &training_wheels_pk)
                .map_err(|error| anyhow!("Failed to verify training wheels signature: {}", error))
        }
        ProverServiceResponse::Error { message } => {
            panic!("returned ProverServiceResponse::Error: {}", message)
        }
    }
}

/// Generates a new Ed25519 keypair (for signing training wheels signatures)
fn generate_ed25519_keypair() -> (Ed25519PrivateKey, Ed25519PublicKey) {
    // Generate a new Ed25519 keypair
    let mut rng: ThreadRng = thread_rng();
    let private_key = Ed25519PrivateKey::generate(&mut rng);
    let public_key = private_key.public_key();

    (private_key, public_key)
}
