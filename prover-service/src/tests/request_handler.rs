// Copyright (c) Aptos Foundation

use crate::external_resources::jwk_types::{FederatedJWKs, JWKCache};
use crate::external_resources::prover_config::ProverServiceConfig;
use crate::request_handler::deployment_information::DeploymentInformation;
use crate::request_handler::handler;
use crate::request_handler::handler::{
    ABOUT_PATH, CONFIG_PATH, HEALTH_CHECK_PATH, JWK_PATH, PROVE_PATH,
};
use crate::request_handler::prover_state::{ProverServiceState, TrainingWheelsKeyPair};
use aptos_infallible::Mutex;
use aptos_types::jwks::rsa::SECURE_TEST_RSA_JWK;
use hyper::{
    header::{
        ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN,
    },
    Body, Method, Request, Response, StatusCode,
};
use reqwest::header::ACCESS_CONTROL_ALLOW_CREDENTIALS;
use std::ops::Deref;
use std::{collections::HashMap, sync::Arc};

#[tokio::test]
async fn test_options_request() {
    // Send an options request to the root path
    let response =
        send_request_to_path(Method::OPTIONS, "/", Body::empty(), None, None, None, None).await;

    // Assert that the response status is OK
    assert_eq!(response.status(), StatusCode::OK);

    // Verify the response headers
    let headers = response.headers();
    assert_eq!(headers.get(ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(), "");
    assert_eq!(
        headers.get(ACCESS_CONTROL_ALLOW_CREDENTIALS).unwrap(),
        "true"
    );
    assert_eq!(headers.get(ACCESS_CONTROL_ALLOW_HEADERS).unwrap(), "*");
    assert_eq!(
        headers.get(ACCESS_CONTROL_ALLOW_METHODS).unwrap(),
        "GET, POST, OPTIONS"
    );
}

#[tokio::test]
async fn test_get_about_request() {
    // Create a new deployment information object
    let mut deployment_information = DeploymentInformation::new();

    // Insert a test entry into the deployment information
    let test_key = "test_key".to_string();
    let test_value = "test_value".to_string();
    deployment_information.extend_deployment_information(test_key.clone(), test_value.clone());

    // Send a GET request to the about endpoint
    let response = send_request_to_path(
        Method::GET,
        ABOUT_PATH,
        Body::empty(),
        None,
        None,
        Some(deployment_information),
        None,
    )
    .await;

    // Assert that the response status is OK
    assert_eq!(response.status(), StatusCode::OK);

    // Parse the response body as a JSON map
    let body_string = get_response_body_string(response).await;
    let json_value: serde_json::Value = serde_json::from_str(&body_string).unwrap();
    let json_map = json_value.as_object().unwrap();

    // Verify the response body contains relevant build information
    assert!(json_map.contains_key("build_cargo_version"));
    assert!(json_map.contains_key("build_commit_hash"));
    assert!(json_map.contains_key("build_is_release_build"));

    // Verify the test entry is present in the response body
    assert_eq!(json_map.get(&test_key).unwrap(), test_value.as_str());
}

#[tokio::test]
async fn test_get_config_request() {
    // Create a new prover service config
    let prover_service_config = ProverServiceConfig {
        setup_dir: "custom/setup/directory/for/tests".into(),
        ..ProverServiceConfig::default()
    };
    let prover_service_config = Arc::new(prover_service_config);

    // Send a GET request to the config endpoint
    let response = send_request_to_path(
        Method::GET,
        CONFIG_PATH,
        Body::empty(),
        Some(prover_service_config.clone()),
        None,
        None,
        None,
    )
    .await;

    // Assert that the response is a 200
    assert_eq!(response.status(), StatusCode::OK);

    // Verify the config from the response body JSON
    let body_string = get_response_body_string(response).await;
    let response_config: ProverServiceConfig = serde_json::from_str(&body_string).unwrap();
    assert_eq!(&response_config, prover_service_config.deref());
}

#[tokio::test]
async fn test_health_check_request() {
    // Send a GET request to the health check endpoint
    let response = send_request_to_path(
        Method::GET,
        HEALTH_CHECK_PATH,
        Body::empty(),
        None,
        None,
        None,
        None,
    )
    .await;

    // Assert that the response status is OK
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_get_jwk_request() {
    // Create a JWK cache
    let jwk_cache = Arc::new(Mutex::new(HashMap::new()));

    // Send a GET request to the JWK endpoint
    let response = send_request_to_path(
        Method::GET,
        JWK_PATH,
        Body::empty(),
        None,
        None,
        None,
        Some(jwk_cache.clone()),
    )
    .await;

    // Assert that the response status is OK
    assert_eq!(response.status(), StatusCode::OK);

    // Parse the response body string and verify that it is an empty JSON map
    let body_string = get_response_body_string(response).await;
    let json_value: serde_json::Value = serde_json::from_str(&body_string).unwrap();
    let json_map = json_value.as_object().unwrap();
    assert!(json_map.is_empty());

    // Insert several test JWKs into the cache
    for i in 0..3 {
        // Create the test issuer and key ID
        let test_issuer = format!("test.issuer.{}", i);
        let test_key_id = format!("test.key.id.{}", i);

        // Insert the test JWK into the cache
        let mut jwk_cache = jwk_cache.lock();
        let issuer_entry = jwk_cache.entry(test_issuer.clone()).or_default();
        issuer_entry.insert(
            test_key_id.clone(),
            Arc::new(SECURE_TEST_RSA_JWK.deref().clone()),
        );
    }

    // Send a GET request to the JWK endpoint
    let response = send_request_to_path(
        Method::GET,
        JWK_PATH,
        Body::empty(),
        None,
        None,
        None,
        Some(jwk_cache.clone()),
    )
    .await;

    // Assert that the response status is OK
    assert_eq!(response.status(), StatusCode::OK);

    // Parse the response body as a JSON map, and verify the number of entries
    let body_string = get_response_body_string(response).await;
    let json_value: serde_json::Value = serde_json::from_str(&body_string).unwrap();
    let json_map = json_value.as_object().unwrap();
    assert_eq!(json_map.len(), 3);

    // Verify that the map contains the expected JWKs
    for i in 0..3 {
        // Create the test issuer and key ID
        let test_issuer = format!("test.issuer.{}", i);
        let test_key_id = format!("test.key.id.{}", i);

        // Verify that the map contains the issuer and key ID
        let issuer_entry = json_map.get(&test_issuer).unwrap().as_object().unwrap();
        assert_eq!(issuer_entry.len(), 1);
        assert!(issuer_entry.contains_key(&test_key_id));
    }
}

#[tokio::test]
async fn test_get_invalid_path_or_method_request() {
    // Send a GET request to an unknown endpoint and verify that it returns 404
    let response = send_request_to_path(
        Method::GET,
        "/invalid_path",
        Body::empty(),
        None,
        None,
        None,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // Send a GET request to an endpoint that only supports POST requests, and verify that it returns 405
    let response = send_request_to_path(
        Method::GET,
        PROVE_PATH,
        Body::empty(),
        None,
        None,
        None,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);

    // Send a POST request to an endpoint that only supports GET requests, and verify that it returns 405
    let response = send_request_to_path(
        Method::POST,
        ABOUT_PATH,
        Body::empty(),
        None,
        None,
        None,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn test_prove_request_bad_request() {
    // Send a POST request to the prove endpoint
    let response = send_request_to_path(
        Method::POST,
        PROVE_PATH,
        Body::empty(),
        None,
        None,
        None,
        None,
    )
    .await;

    // Assert that the response is a 400 (bad request, since no body was provided)
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Send another POST request with an invalid JSON body
    let response = send_request_to_path(
        Method::POST,
        PROVE_PATH,
        Body::from("invalid_json"),
        None,
        None,
        None,
        None,
    )
    .await;

    // Assert that the response is a 400 (bad request, since the body was invalid JSON)
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

/// Gets the response body as a string
async fn get_response_body_string(response: Response<Body>) -> String {
    let body_bytes = hyper::body::to_bytes(response.into_body()).await.unwrap();
    String::from_utf8(body_bytes.to_vec()).unwrap()
}

// Calls the request handler with the given method, endpoint, and body
async fn send_request_to_path(
    method: Method,
    endpoint: &str,
    body: Body,
    prover_service_config: Option<Arc<ProverServiceConfig>>,
    training_wheels_key_pair: Option<TrainingWheelsKeyPair>,
    deployment_information: Option<DeploymentInformation>,
    jwk_cache: Option<JWKCache>,
) -> Response<Body> {
    // Get or create the prover service config
    let prover_service_config =
        prover_service_config.unwrap_or_else(|| Arc::new(ProverServiceConfig::default()));

    // Build the URI
    let uri = format!(
        "http://127.0.0.1:{}{}",
        prover_service_config.port, endpoint
    );

    // Build the request
    let request = Request::builder()
        .uri(uri)
        .method(method)
        .body(body)
        .unwrap();

    // Get or create a training wheels key pair
    let training_wheels_key_pair =
        training_wheels_key_pair.unwrap_or_else(TrainingWheelsKeyPair::new_for_testing);

    // Get or create deployment information
    let deployment_information = deployment_information.unwrap_or_default();

    // Get or create a JWK cache
    let jwk_cache = jwk_cache.unwrap_or_else(|| Arc::new(Mutex::new(HashMap::new())));

    // Create a federated JWKs object
    let federated_jwks = FederatedJWKs::new_empty();

    // Create the prover service state
    let prover_service_state = Arc::new(ProverServiceState::new_for_testing(
        training_wheels_key_pair,
        prover_service_config,
        deployment_information,
        jwk_cache,
        federated_jwks,
    ));

    // Serve the request
    handler::handle_request(request, prover_service_state)
        .await
        .unwrap()
}
