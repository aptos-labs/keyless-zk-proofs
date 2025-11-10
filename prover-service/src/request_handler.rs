// Copyright (c) Aptos Foundation

use crate::config::prover_config::ProverServiceConfig;
use crate::prover_state::ProverServiceState;
use crate::{deployment_information::DeploymentInformation, prover_handler, utils};
use aptos_logger::error;
use hyper::{
    header::{ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS},
    Body, Method, Request, Response, StatusCode,
};
use std::{convert::Infallible, sync::Arc};

// The list of endpoints/paths offered by the Prover Service.
// Note: if you update these paths, please also update the "ALL_PATHS" array below.
const ABOUT_PATH: &str = "/about";
const CONFIG_PATH: &str = "/config";
const HEALTH_CHECK_PATH: &str = "/healthcheck";
const PROVE_PATH: &str = "/v0/prove";

// An array of all known endpoints/paths
pub const ALL_PATHS: [&str; 4] = [ABOUT_PATH, CONFIG_PATH, HEALTH_CHECK_PATH, PROVE_PATH];

// Useful message constants
const HEALTH_CHECK_OK_MESSAGE: &str = "OK";
const METHOD_NOT_ALLOWED_MESSAGE: &str =
    "The request method is not allowed for the requested path!";

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
            return utils::generate_internal_server_error_response(origin);
        }
    };

    // Generate the response
    utils::generate_json_response(origin, StatusCode::OK, deployment_info_json)
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
            return utils::generate_internal_server_error_response(origin);
        }
    };

    // Generate the response
    utils::generate_json_response(origin, StatusCode::OK, config_json)
}

/// Generates a 200 response for health check requests. This
/// is useful for kubernetes liveness and readiness probes.
fn generate_health_check_response(origin: String) -> Result<Response<Body>, Infallible> {
    utils::generate_text_response(origin, StatusCode::OK, HEALTH_CHECK_OK_MESSAGE.into())
}

/// Generates a 405 response for invalid methods on known paths
fn generate_method_not_allowed_response(origin: String) -> Result<Response<Body>, Infallible> {
    utils::generate_text_response(
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
    utils::generate_text_response(origin, StatusCode::NOT_FOUND, response_message)
}

/// Generates a response for options requests
fn generate_options_response(origin: String) -> Result<Response<Body>, Infallible> {
    let response = utils::create_response_builder(origin, StatusCode::OK)
        .header(ACCESS_CONTROL_ALLOW_METHODS, "GET, POST, OPTIONS")
        .header(ACCESS_CONTROL_ALLOW_HEADERS, "*")
        .body(Body::empty())
        .expect("Failed to build options response!");
    Ok(response)
}

/// Handles the given request and returns a response
pub async fn handle_request(
    request: Request<Body>,
    prover_service_state: Arc<ProverServiceState>,
) -> Result<Response<Body>, Infallible> {
    // Get the request origin
    let origin = utils::get_request_origin(&request);

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
