use crate::jwk_fetching::get_federated_jwk;
use crate::tests::common::gen_test_jwk_keypair_with_kid_override;
use crate::tests::common::types::{ProofTestCase, TestJWTPayload};
use aptos_keyless_common::input_processing::encoding::DecodedJWT;

// This test uses a demo auth0 tenant owned by oliver.he@aptoslabs.com
#[tokio::test]
async fn test_federated_jwk_fetch() {
    // The endpoint can be found at https://dev-qtdgjv22jh0v1k7g.us.auth0.com/.well-known/jwks.json
    let iss = "https://dev-qtdgjv22jh0v1k7g.us.auth0.com/";
    let kid = "OYryNKGFtFhtHVOd1d_BU";
    let jwt_payload = TestJWTPayload {
        iss: String::from(iss),
        ..TestJWTPayload::default()
    };

    let testcase = ProofTestCase::default_with_payload(jwt_payload).compute_nonce();

    let jwk_keypair = gen_test_jwk_keypair_with_kid_override(kid);
    let prover_request_input = testcase.convert_to_prover_request(&jwk_keypair);
    let jwt = DecodedJWT::from_b64(&prover_request_input.jwt_b64).unwrap();
    assert!(get_federated_jwk(&jwt).await.is_ok());
}

#[tokio::test]
async fn test_federated_jwk_fetch_fails_for_bad_iss() {
    // bad iss
    let iss = "https://dev-qtdgjv22jh0v1k7g.us.random.com/";
    let kid = "OYryNKGFtFhtHVOd1d_BU";
    let jwt_payload = TestJWTPayload {
        iss: String::from(iss),
        ..TestJWTPayload::default()
    };

    let testcase = ProofTestCase::default_with_payload(jwt_payload).compute_nonce();

    let jwk_keypair = gen_test_jwk_keypair_with_kid_override(kid);
    let prover_request_input = testcase.convert_to_prover_request(&jwk_keypair);
    let jwt = DecodedJWT::from_b64(&prover_request_input.jwt_b64).unwrap();
    let error_message = get_federated_jwk(&jwt).await.unwrap_err().to_string();

    assert!(error_message.contains("not a federated iss"))
}

#[tokio::test]
async fn test_federated_jwk_fetch_fails_for_bad_kid() {
    let iss = "https://dev-qtdgjv22jh0v1k7g.us.auth0.com/";
    // bad kid
    let kid = "bad_kid";
    let jwt_payload = TestJWTPayload {
        iss: String::from(iss),
        ..TestJWTPayload::default()
    };

    let testcase = ProofTestCase::default_with_payload(jwt_payload).compute_nonce();

    let jwk_keypair = gen_test_jwk_keypair_with_kid_override(kid);
    let prover_request_input = testcase.convert_to_prover_request(&jwk_keypair);
    let jwt = DecodedJWT::from_b64(&prover_request_input.jwt_b64).unwrap();
    let error_message = get_federated_jwk(&jwt).await.unwrap_err().to_string();

    assert!(error_message.contains("unknown kid"))
}
