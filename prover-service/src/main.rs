// Copyright (c) Aptos Foundation

use aptos_crypto::ed25519::Ed25519PrivateKey;
use aptos_crypto::ValidCryptoMaterialStringExt;
use aptos_logger::{error, info, warn};
use clap::Parser;
use hyper::service::{make_service_fn, service_fn};
use hyper::Server;
use prover_service::external_resources::prover_config::ProverServiceConfig;
use prover_service::external_resources::{jwk_fetcher, prover_config};
use prover_service::request_handler::prover_state::{ProverServiceState, TrainingWheelsKeyPair};
use prover_service::request_handler::{deployment_information, handler};
use prover_service::*;
use std::convert::Infallible;
use std::time::Instant;
use std::{net::SocketAddr, sync::Arc, time::Duration};

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// The prover service config file path
    #[arg(long)]
    config_file_path: String,

    /// The training wheels private key file path
    #[arg(long)]
    training_wheels_private_key_file_path: String,
}

#[tokio::main]
async fn main() {
    // Fetch the command line arguments
    let args = Args::parse();

    // Start the Aptos logger
    aptos_logger::Logger::new().init();
    info!("Starting the Prover service...");

    // Load the training wheels key pair
    let training_wheels_key_pair =
        load_training_wheels_key_pair(&args.training_wheels_private_key_file_path);

    // Load the prover service config
    let prover_service_config = prover_config::load_prover_service_config(&args.config_file_path);

    // Get the deployment information
    let deployment_information = deployment_information::get_deployment_information(
        training_wheels_key_pair.verification_key(),
    );

    // Start the JWK fetchers
    let (jwk_cache, federated_jwks) = jwk_fetcher::start_jwk_fetchers(
        prover_service_config.jwk_issuers.clone(),
        Duration::from_secs(prover_service_config.jwk_refresh_rate_secs),
    );

    // Create the prover service state
    let prover_service_state = Arc::new(ProverServiceState::init(
        training_wheels_key_pair,
        prover_service_config.clone(),
        deployment_information,
        jwk_cache,
        federated_jwks,
    ));

    // Load the verification key
    load_verification_key(prover_service_config.clone());

    // Start the metrics server
    metrics::start_metrics_server(prover_service_config.clone());

    // Start the prover service
    start_prover_service(prover_service_config.port, prover_service_state).await;
}

/// Loads and logs the verification key from the prover service config
fn load_verification_key(prover_service_config: Arc<ProverServiceConfig>) {
    let verification_key_file_path = prover_service_config.verification_key_file_path();
    let verification_key = utils::read_string_from_file_path(&verification_key_file_path);
    info!("Loaded default verifying Key: {}", verification_key);
}

/// Loads the training wheels key pair from the specified private key file path.
/// If the file cannot be read or the key cannot be parsed, this function will panic.
fn load_training_wheels_key_pair(
    training_wheels_private_key_file_path: &str,
) -> TrainingWheelsKeyPair {
    info!(
        "Loading the training wheels private key from the path: {}",
        training_wheels_private_key_file_path
    );

    // Read the private key file contents (hex encoded)
    let private_key_hex = utils::read_string_from_file_path(training_wheels_private_key_file_path);

    // Parse the private key from the hex string and create the key pair
    match Ed25519PrivateKey::from_encoded_string(&private_key_hex) {
        Ok(private_key) => {
            let training_wheels_key_pair = TrainingWheelsKeyPair::from_sk(private_key);
            info!(
                "Loaded the training wheels verification key: {:?}",
                training_wheels_key_pair.verification_key()
            );

            training_wheels_key_pair
        }
        Err(error) => panic!(
            "Failed to parse the training wheels private key from hex string: {}",
            error
        ),
    }
}

// Starts the prover service
async fn start_prover_service(
    prover_service_port: u16,
    prover_service_state: Arc<ProverServiceState>,
) {
    info!(
        "Starting the Prover service request handler on port {}...",
        prover_service_port
    );

    // Create the service function that handles the endpoint requests
    let make_service = make_service_fn(move |_conn| {
        // Clone the required state for the service function
        let prover_service_state = prover_service_state.clone();

        async move {
            Ok::<_, Infallible>(service_fn(move |request| {
                // Start the request timer
                let request_start_time = Instant::now();

                // Get the request origin, method and request path
                let request_origin = handler::get_request_origin(&request);
                let request_method = request.method().clone();
                let request_path = request.uri().path().to_owned();

                // Clone the required state for the request handler
                let prover_service_state = prover_service_state.clone();

                // Handle the request
                async move {
                    // Call the request handler
                    let result =
                        handler::handle_request(request, prover_service_state.clone()).await;

                    // Update the request handling metrics and logs
                    match &result {
                        Ok(response) => {
                            // Update the request handling metrics
                            metrics::update_request_handling_metrics(
                                &request_path,
                                request_method.clone(),
                                response.status(),
                                request_start_time,
                            );

                            // If the response was not successful, log the request details
                            if !response.status().is_success() {
                                warn!(
                                    "Handled request with non-successful response! Request origin: {:?}, \
                                    request path: {:?}, request method: {:?}, response status: {:?}",
                                    request_origin,
                                    request_path,
                                    request_method,
                                    response.status()
                                );
                            }
                        }
                        Err(error) => {
                            error!(
                                "Error occurred when handling request! Request origin: {:?}, \
                                request path: {:?}, request method: {:?}, Error: {:?}",
                                request_origin, request_path, request_method, error
                            );
                        }
                    }

                    result
                }
            }))
        }
    });

    // Bind the socket address, and start the server
    let socket_addr = SocketAddr::from(([0, 0, 0, 0], prover_service_port));
    let server = Server::bind(&socket_addr).serve(make_service);
    if let Err(error) = server.await {
        panic!("Prover service error! Error: {}", error);
    }
}
