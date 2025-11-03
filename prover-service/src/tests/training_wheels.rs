// Copyright (c) Aptos Foundation

use crate::tests::common::types::{ProofTestCase, TestJWTPayload};
use crate::tests::common::{gen_test_jwk_keypair, types::TestJWKKeyPair};
use crate::training_wheels::validate_jwt_sig;
use std::time::{SystemTime, UNIX_EPOCH};

fn test_jwt_validation(jwt_payload: TestJWTPayload) {
    let testcase = ProofTestCase::default_with_payload(jwt_payload).compute_nonce();

    let jwk_keypair = gen_test_jwk_keypair();
    let prover_request_input = testcase.convert_to_prover_request(&jwk_keypair);
    assert!(validate_jwt_sig(&jwk_keypair.into_rsa_jwk(), &prover_request_input.jwt_b64,).is_ok());
}

#[test]
fn test_validate_jwt_sig_and_dates() {
    let jwt_payload = TestJWTPayload {
        ..TestJWTPayload::default()
    };
    test_jwt_validation(jwt_payload);
}

#[test]
#[should_panic]
fn test_validate_jwt_sig_and_dates_expired() {
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");

    let jwt_payload = TestJWTPayload {
        exp: since_the_epoch.as_secs() - 100,
        ..TestJWTPayload::default()
    };
    test_jwt_validation(jwt_payload);
}
