// Copyright (c) Aptos Foundation

use crate::external_resources::jwk_fetcher::{
    get_federated_jwk, AUTH0_ISSUER_NAME, AUTH0_REGEX_STR, COGNITO_ISSUER_NAME, COGNITO_REGEX_STR,
};
use crate::external_resources::jwk_types::{FederatedJWKIssuerInterface, FederatedJWKs, KeyID};
use crate::tests::types::{ProofTestCase, TestJWTPayload};
use crate::tests::utils;
use aptos_keyless_common::input_processing::jwt::DecodedJWT;
use aptos_types::jwks::rsa::{INSECURE_TEST_RSA_JWK, RSA_JWK};
use regex::Regex;
use std::collections::HashMap;
use std::ops::Deref;
use std::sync::Arc;

/// A mock federated JWK issuer (for testing JWK regex matching and fetching)
#[derive(Clone, Debug)]
struct MockFederatedJWKIssuer {
    issuer_name: String,
    jwks: HashMap<KeyID, Arc<RSA_JWK>>,
    regex: Regex,
}

impl MockFederatedJWKIssuer {
    pub fn new(
        issuer_name: String,
        jwks: HashMap<KeyID, Arc<RSA_JWK>>,
        regex_pattern: String,
    ) -> Self {
        let regex = Regex::new(&regex_pattern).expect("Failed to create regex!");
        Self {
            issuer_name,
            jwks,
            regex,
        }
    }
}

#[async_trait::async_trait]
impl FederatedJWKIssuerInterface for MockFederatedJWKIssuer {
    fn issuer_name(&self) -> String {
        self.issuer_name.clone()
    }

    async fn fetch_jwks(
        &self,
        _jwt_issuer: String,
    ) -> anyhow::Result<HashMap<KeyID, Arc<RSA_JWK>>> {
        Ok(self.jwks.clone())
    }

    fn regex(&self) -> &Regex {
        &self.regex
    }
}

#[tokio::test]
async fn test_federated_jwk_fetch() {
    // Create test jwks to be returned by the mock issuer
    let mut test_jwks: HashMap<KeyID, Arc<RSA_JWK>> = HashMap::new();
    let test_kid = "test_kid";
    let test_rsa_jwk = Arc::new(INSECURE_TEST_RSA_JWK.deref().clone());
    test_jwks.insert(test_kid.into(), test_rsa_jwk.clone());

    // Create the mock federated JWK issuer
    let mock_issuer =
        MockFederatedJWKIssuer::new(AUTH0_ISSUER_NAME.into(), test_jwks, AUTH0_REGEX_STR.into());
    let federated_jwks = FederatedJWKs::new(vec![mock_issuer]);

    // Create the test JWT payload with a valid auth0 issuer
    let iss = "https://test.us.auth0.com/";
    let jwt_payload = TestJWTPayload {
        iss: String::from(iss),
        ..TestJWTPayload::default()
    };

    // Get a decoded JWT with the correct kid
    let decoded_jwt = get_decoded_jwt(test_kid, jwt_payload);

    // Fetch the federated JWK
    let federated_jwk_result = get_federated_jwk(&decoded_jwt, federated_jwks).await;

    // Verify that the JWK was fetched successfully
    assert_eq!(federated_jwk_result.unwrap(), test_rsa_jwk);
}

#[tokio::test]
async fn test_federated_jwk_fetch_multiple_issuers() {
    // Create test jwks to be returned by the third issuer
    let mut test_jwks: HashMap<KeyID, Arc<RSA_JWK>> = HashMap::new();
    let test_kid = "falcon_kid";
    let test_rsa_jwk = Arc::new(INSECURE_TEST_RSA_JWK.deref().clone());
    test_jwks.insert(test_kid.into(), test_rsa_jwk.clone());

    // Create several mock federated JWK issuers
    let mock_issuer_1 = MockFederatedJWKIssuer::new(
        AUTH0_ISSUER_NAME.into(),
        HashMap::new(), // Empty JWKs
        AUTH0_REGEX_STR.into(),
    );
    let mock_issuer_2 = MockFederatedJWKIssuer::new(
        COGNITO_ISSUER_NAME.into(),
        HashMap::new(), // Empty JWKs
        COGNITO_REGEX_STR.into(),
    );
    let mock_issuer_3 = MockFederatedJWKIssuer::new(
        "falcon".into(),
        test_jwks,
        r"^https://[a-zA-Z0-9_-]+\.falcon\.com/".into(),
    );
    let federated_jwks = FederatedJWKs::new(vec![mock_issuer_1, mock_issuer_2, mock_issuer_3]);

    // Create the test JWT payload with an issuer that matches the third issuer
    let iss = "https://example.falcon.com/";
    let jwt_payload = TestJWTPayload {
        iss: String::from(iss),
        ..TestJWTPayload::default()
    };

    // Get a decoded JWT with the correct kid
    let decoded_jwt = get_decoded_jwt(test_kid, jwt_payload);

    // Fetch the federated JWK
    let federated_jwk_result = get_federated_jwk(&decoded_jwt, federated_jwks).await;

    // Verify that the JWK was fetched successfully
    assert_eq!(federated_jwk_result.unwrap(), test_rsa_jwk);
}

#[tokio::test]
async fn test_federated_jwk_fetch_fails_for_bad_issuer() {
    // Create the mock federated JWK issuer
    let mock_issuer = MockFederatedJWKIssuer::new(
        AUTH0_ISSUER_NAME.into(),
        HashMap::new(), // Empty JWKs
        AUTH0_REGEX_STR.into(),
    );
    let federated_jwks = FederatedJWKs::new(vec![mock_issuer]);

    // Create the test JWT payload with a bad issuer
    let iss = "https://test.us.random.com/";
    let kid = "kid";
    let jwt_payload = TestJWTPayload {
        iss: String::from(iss),
        ..TestJWTPayload::default()
    };

    // Get a decoded JWT with the correct kid
    let decoded_jwt = get_decoded_jwt(kid, jwt_payload);

    // Fetch the federated JWK
    let federated_jwk_result = get_federated_jwk(&decoded_jwt, federated_jwks).await;

    // Verify that the JWK issuer was not found
    let error_message = federated_jwk_result.unwrap_err().to_string();
    assert!(error_message.contains("Unsupported federated issuer: https://test.us.random.com/"));
}

#[tokio::test]
async fn test_federated_jwk_fetch_fails_for_missing_kid() {
    // Create the mock federated JWK issuer
    let mock_issuer = MockFederatedJWKIssuer::new(
        AUTH0_ISSUER_NAME.into(),
        HashMap::new(), // Empty JWKs
        AUTH0_REGEX_STR.into(),
    );
    let federated_jwks = FederatedJWKs::new(vec![mock_issuer]);

    // Create the test JWT payload with a valid issuer
    let iss = "https://test.us.auth0.com/";
    let kid = "missing_kid"; // This kid will not be found
    let jwt_payload = TestJWTPayload {
        iss: String::from(iss),
        ..TestJWTPayload::default()
    };

    // Get a decoded JWT with the correct kid
    let decoded_jwt = get_decoded_jwt(kid, jwt_payload);

    // Fetch the federated JWK
    let federated_jwk_result = get_federated_jwk(&decoded_jwt, federated_jwks).await;

    // Verify that the JWK was not found
    let error_message = federated_jwk_result.unwrap_err().to_string();
    assert!(error_message.contains("Unknown kid: missing_kid"));
}

/// Helper function to create a decoded JWT from a given kid and payload
fn get_decoded_jwt(kid: &str, jwt_payload: TestJWTPayload) -> DecodedJWT {
    // Create the prover request input
    let testcase = ProofTestCase::default_with_payload(jwt_payload).compute_nonce();
    let jwk_keypair = utils::gen_test_jwk_keypair_with_kid_override(kid);
    let prover_request_input = testcase.convert_to_prover_request(&jwk_keypair);

    // Return the decoded JWT
    DecodedJWT::from_b64(&prover_request_input.jwt_b64).unwrap()
}
