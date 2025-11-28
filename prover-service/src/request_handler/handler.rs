// Copyright (c) Aptos Foundation

use crate::external_resources::jwk_fetcher::JWKCache;
use crate::external_resources::prover_config::ProverServiceConfig;
use crate::request_handler::deployment_information::DeploymentInformation;
use crate::request_handler::prover_handler;
use crate::request_handler::prover_state::ProverServiceState;
use aptos_logger::error;
use hyper::header::{ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_ALLOW_ORIGIN, CONTENT_TYPE};
use hyper::http::response;
use hyper::{
    header::{ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS},
    Body, Method, Request, Response, StatusCode,
};
use std::{convert::Infallible, sync::Arc};

// The list of endpoints/paths offered by the Prover Service.
// Note: if you update these paths, please also update the "ALL_PATHS" array below.
pub const ABOUT_PATH: &str = "/about";
pub const CONFIG_PATH: &str = "/config";
pub const HEALTH_CHECK_PATH: &str = "/healthcheck";
pub const JWK_PATH: &str = "/cached/jwk";
pub const PROVE_PATH: &str = "/v0/prove";

// An array of all known endpoints/paths
pub const ALL_PATHS: [&str; 5] = [
    ABOUT_PATH,
    CONFIG_PATH,
    HEALTH_CHECK_PATH,
    JWK_PATH,
    PROVE_PATH,
];

// Content type constants
pub const CONTENT_TYPE_JSON: &str = "application/json";
pub const CONTENT_TYPE_TEXT: &str = "text/plain";

// Origin header constants
pub const MISSING_ORIGIN_STRING: &str = ""; // Default to empty string if origin header is missing
const ORIGIN_HEADER: &str = "origin";

// Useful message constants
const HEALTH_CHECK_OK_MESSAGE: &str = "OK";
const METHOD_NOT_ALLOWED_MESSAGE: &str =
    "The request method is not allowed for the requested path!";

// Unexpected error message constant
const UNEXPECTED_ERROR_MESSAGE: &str = "An unexpected error was encountered!";

/// Returns a response builder prepopulated with common headers
pub fn create_response_builder(origin: String, status_code: StatusCode) -> response::Builder {
    hyper::Response::builder()
        .status(status_code)
        .header(ACCESS_CONTROL_ALLOW_ORIGIN, origin)
        .header(ACCESS_CONTROL_ALLOW_CREDENTIALS, "true")
}

/// Generates a response for the about endpoint
fn generate_about_response(
    origin: String,
    deployment_information: &DeploymentInformation,
) -> Result<Response<Body>, Infallible> {
    // Serialize the deployment information
    let deployment_info_json = match serde_json::to_string_pretty(
        &deployment_information.get_deployment_information_map(),
    ) {
        Ok(json) => json,
        Err(error) => {
            error!(
                "Failed to serialize deployment information to JSON: {}",
                error
            );
            return generate_internal_server_error_response(origin);
        }
    };

    // Generate the response
    generate_json_response(origin, StatusCode::OK, deployment_info_json)
}

/// Generates a 400 response for bad requests
pub fn generate_bad_request_response(
    origin: String,
    json_error_string: String,
) -> Result<Response<Body>, Infallible> {
    generate_json_response(origin, StatusCode::BAD_REQUEST, json_error_string)
}

/// Generates a response for the config endpoint
fn generate_config_response(
    origin: String,
    prover_service_config: Arc<ProverServiceConfig>,
) -> Result<Response<Body>, Infallible> {
    // Serialize the configuration information
    let config_json = match serde_json::to_string_pretty(&prover_service_config) {
        Ok(json) => json,
        Err(error) => {
            error!("Failed to serialize configuration to JSON: {}", error);
            return generate_internal_server_error_response(origin);
        }
    };

    // Generate the response
    generate_json_response(origin, StatusCode::OK, config_json)
}

/// Generates a 200 response for health check requests. This
/// is useful for kubernetes liveness and readiness probes.
fn generate_health_check_response(origin: String) -> Result<Response<Body>, Infallible> {
    generate_text_response(origin, StatusCode::OK, HEALTH_CHECK_OK_MESSAGE.into())
}

/// Generates a 500 response for unexpected internal server errors
pub fn generate_internal_server_error_response(
    origin: String,
) -> Result<Response<Body>, Infallible> {
    generate_text_response(
        origin,
        StatusCode::INTERNAL_SERVER_ERROR,
        UNEXPECTED_ERROR_MESSAGE.into(),
    )
}

/// Generates a JSON response with the given status code and body string
pub fn generate_json_response(
    origin: String,
    status_code: StatusCode,
    body_str: String,
) -> Result<Response<Body>, Infallible> {
    let response = create_response_builder(origin, status_code)
        .header(CONTENT_TYPE, CONTENT_TYPE_JSON)
        .body(Body::from(body_str))
        .expect("Failed to build JSON response!");
    Ok(response)
}

/// Generates a response with the cached JWKs as JSON
fn generate_jwt_cache_response(
    origin: String,
    jwk_cache: JWKCache,
) -> Result<Response<Body>, Infallible> {
    let jwk_cache = jwk_cache.lock().clone();
    match serde_json::to_string_pretty(&jwk_cache) {
        Ok(response_body) => generate_json_response(origin, StatusCode::OK, response_body),
        Err(error) => {
            // Failed to serialize the JWK cache, return a server error
            error!("Failed to serialize to JSON response: {}", error);
            generate_internal_server_error_response(origin.clone())
        }
    }
}

/// Generates a 405 response for invalid methods on known paths
fn generate_method_not_allowed_response(origin: String) -> Result<Response<Body>, Infallible> {
    generate_text_response(
        origin,
        StatusCode::METHOD_NOT_ALLOWED,
        METHOD_NOT_ALLOWED_MESSAGE.into(),
    )
}

/// Generates a 404 response for invalid paths
fn generate_not_found_response(
    origin: String,
    request_method: &Method,
    request_path: &str,
) -> Result<Response<Body>, Infallible> {
    let response_message = format!(
        "The request for '{}' with method '{}' was not found!",
        request_path, request_method
    );
    generate_text_response(origin, StatusCode::NOT_FOUND, response_message)
}

/// Generates a response for options requests
fn generate_options_response(origin: String) -> Result<Response<Body>, Infallible> {
    let response = create_response_builder(origin, StatusCode::OK)
        .header(ACCESS_CONTROL_ALLOW_METHODS, "GET, POST, OPTIONS")
        .header(ACCESS_CONTROL_ALLOW_HEADERS, "*")
        .body(Body::empty())
        .expect("Failed to build options response!");
    Ok(response)
}

/// Generates a text response with the given status code and body string
pub fn generate_text_response(
    origin: String,
    status_code: StatusCode,
    body_str: String,
) -> Result<Response<Body>, Infallible> {
    let response = create_response_builder(origin, status_code)
        .header(CONTENT_TYPE, CONTENT_TYPE_TEXT)
        .body(Body::from(body_str))
        .expect("Failed to build text response!");
    Ok(response)
}

/// Extracts the origin header from the request
pub fn get_request_origin(request: &Request<Body>) -> String {
    request
        .headers()
        .get(ORIGIN_HEADER)
        .and_then(|header_value| header_value.to_str().ok())
        .unwrap_or(MISSING_ORIGIN_STRING)
        .to_owned()
}

/// Handles the given request and returns a response
pub async fn handle_request(
    request: Request<Body>,
    prover_service_state: Arc<ProverServiceState>,
) -> Result<Response<Body>, Infallible> {
    // Get the request origin
    let origin = get_request_origin(&request);

    // Handle any OPTIONS requests
    let request_method = request.method();
    if request_method == Method::OPTIONS {
        return generate_options_response(origin);
    }

    // Handle any GET requests
    let request_path = request.uri().path();
    if request_method == Method::GET {
        match request_path {
            ABOUT_PATH => {
                return generate_about_response(
                    origin,
                    prover_service_state.deployment_information(),
                )
            }
            CONFIG_PATH => {
                return generate_config_response(
                    origin,
                    prover_service_state.prover_service_config(),
                )
            }
            HEALTH_CHECK_PATH => return generate_health_check_response(origin),
            JWK_PATH => {
                return generate_jwt_cache_response(origin, prover_service_state.jwk_cache())
            }
            _ => { /* Continue below */ }
        };
    }

    // Handle any POST requests
    if request_method == Method::POST {
        match request_path {
            PROVE_PATH => {
                return prover_handler::hande_prove_request(origin, request, prover_service_state)
                    .await
            }
            _ => { /* Continue below */ }
        };
    }

    // If the request is to a known path but with an invalid method, return a method not allowed response
    if is_known_path(request_path) {
        return generate_method_not_allowed_response(origin);
    }

    // Otherwise, no matching route was found
    generate_not_found_response(origin, request_method, request_path)
}

/// Returns true if the given URI path is a known path/endpoint
pub fn is_known_path(uri_path: &str) -> bool {
    ALL_PATHS.contains(&uri_path)
}
