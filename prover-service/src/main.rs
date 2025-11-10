// Copyright (c) Aptos Foundation

use aptos_crypto::ed25519::Ed25519PrivateKey;
use aptos_crypto::ValidCryptoMaterialStringExt;
use aptos_logger::info;
use axum::{
    routing::{get, post},
    Router,
};
use clap::Parser;
use http::Method;
use prover_service::config::prover_config;
use prover_service::config::prover_config::ProverServiceConfig;
use prover_service::{prover_state::*, *};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tower::ServiceBuilder;
use tower_http::cors::{Any, CorsLayer};

// The list of endpoints/paths offered by the Prover Service.
const ABOUT_PATH: &str = "/about";
const CONFIG_PATH: &str = "/config";
const HEALTH_CHECK_PATH: &str = "/healthcheck";
const PROVE_PATH: &str = "/v0/prove";

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
        &training_wheels_key_pair.verification_key,
    );

    // Create the prover service state
    let prover_service_state = Arc::new(ProverServiceState::init(
        training_wheels_key_pair,
        prover_service_config.clone(),
        deployment_information,
    ));

    // Load the test verification key
    load_test_verification_key(prover_service_config.clone());

    // init jwk fetching job; refresh every `config.jwk_refresh_rate_secs` seconds
    jwk_fetching::init_jwk_fetching(
        &prover_service_config.oidc_providers,
        Duration::from_secs(prover_service_config.jwk_refresh_rate_secs),
    )
    .await;

    // init axum and serve public routes
    let cors = CorsLayer::new()
        // allow `GET` and `POST` when accessing the resource
        .allow_methods([Method::GET, Method::POST])
        // allow requests from any origin
        .allow_origin(Any)
        // allow cross-origin requests
        .allow_headers(Any);
    let app = Router::new()
        .route(ABOUT_PATH, get(handlers::about_handler))
        .route(CONFIG_PATH, get(handlers::config_handler))
        .route(HEALTH_CHECK_PATH, get(handlers::health_check_handler))
        .route(
            PROVE_PATH,
            post(handlers::prove_handler).fallback(handlers::fallback_handler),
        )
        .fallback(handlers::fallback_handler)
        .with_state(prover_service_state.clone())
        .layer(ServiceBuilder::new().layer(cors));

    let addr = SocketAddr::from(([0, 0, 0, 0], prover_service_config.port));
    let app_handle = tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        axum::serve(listener, app).await.unwrap();
    });

    // Start the metrics server
    metrics::start_metrics_server(prover_service_config);

    // Wait for the application to end (it shouldn't, unless there's a fatal error)
    let res = tokio::try_join!(app_handle);
    panic!("The application task ended unexpectedly: {:?}", res);
}

/// Loads and logs the test verification key from the prover service config
fn load_test_verification_key(prover_service_config: Arc<ProverServiceConfig>) {
    // TODO: what does this actually do? Is it still useful?

    let test_verification_key_file_path = prover_service_config.test_verification_key_file_path();
    let test_verification_key = utils::read_string_from_file_path(&test_verification_key_file_path);
    info!("Loaded default verifying Key: {}", test_verification_key);
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
                training_wheels_key_pair.verification_key
            );

            training_wheels_key_pair
        }
        Err(error) => panic!(
            "Failed to parse the training wheels private key from hex string: {}",
            error
        ),
    }
}
