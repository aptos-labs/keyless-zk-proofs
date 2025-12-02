// Copyright (c) Aptos Foundation

use crate::request_handler::training_wheels;
use crate::tests::types::TestJWKKeyPair;
use crate::tests::types::{ProofTestCase, TestJWTPayload};
use crate::tests::utils;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn test_validate_default_jwt() {
    // Create a default JWT payload
    let jwt_payload = TestJWTPayload {
        ..TestJWTPayload::default()
    };

    // Verify the JWT signature
    test_jwt_signature_validation(jwt_payload, true);
}

#[test]
fn test_validate_jwt_invalid_signature() {
    // Create a default JWT payload
    let jwt_payload = TestJWTPayload {
        ..TestJWTPayload::default()
    };

    // Create a test case and convert it to a prover request input
    let testcase = ProofTestCase::default_with_payload(jwt_payload).compute_nonce();
    let jwk_keypair = utils::generate_test_jwk_keypair();
    let prover_request_input = testcase.convert_to_prover_request(&jwk_keypair);

    // Verify the JWT signature using a different keypair to simulate an invalid signature
    let another_jwk_keypair = utils::generate_test_jwk_keypair();
    let result = training_wheels::validate_jwt_signature(
        &another_jwk_keypair.into_rsa_jwk(),
        &prover_request_input.jwt_b64,
    );

    // Expect the validation to fail
    assert!(result.is_err());
}

#[test]
fn test_validate_jwt_sig_and_dates_expired() {
    // Create a JWT payload with an expired expiration time
    let duration_since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    let jwt_payload = TestJWTPayload {
        exp: duration_since_epoch.as_secs() - 100,
        ..TestJWTPayload::default()
    };

    // Verify the JWT signature
    test_jwt_signature_validation(jwt_payload, false);
}

/// Helper function to test JWT signature validation
fn test_jwt_signature_validation(jwt_payload: TestJWTPayload, expect_success: bool) {
    // Create a test case and convert it to a prover request input
    let testcase = ProofTestCase::default_with_payload(jwt_payload).compute_nonce();
    let jwk_keypair = utils::generate_test_jwk_keypair();
    let prover_request_input = testcase.convert_to_prover_request(&jwk_keypair);

    // Verify the JWT signature
    let result = training_wheels::validate_jwt_signature(
        &jwk_keypair.into_rsa_jwk(),
        &prover_request_input.jwt_b64,
    );
    if expect_success {
        assert!(result.is_ok());
    } else {
        assert!(result.is_err());
    }
}
