// Copyright (c) Aptos Foundation

use anyhow::Context;
use axum::{
    http::header,
    routing::{get, post},
    Router,
};
use axum_prometheus::{
    metrics_exporter_prometheus::{Matcher, PrometheusBuilder},
    utils::SECONDS_DURATION_BUCKETS,
    PrometheusMetricLayerBuilder, AXUM_HTTP_REQUESTS_DURATION_SECONDS,
};
use clap::Parser;
use http::{Method, StatusCode};
use log::info;
use prometheus::{Encoder, TextEncoder};
use prover_service::deployment_information::DeploymentInformation;
use prover_service::prover_config::ProverServiceConfig;
use prover_service::{state::*, *};
use std::{fs, net::SocketAddr, sync::Arc, time::Duration};
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
}

#[tokio::main]
async fn main() {
    // Fetch the command line arguments
    let args = Args::parse();

    // Start the Aptos logger
    aptos_logger::Logger::new().init();
    info!("Starting the Prover service...");

    // Get the deployment information
    let deployment_information = DeploymentInformation::new();

    // Load the prover service config
    let prover_service_config = load_prover_service_config(&args.config_file_path);

    // TODO: removing tracing and using aptos_logger only
    // init tracing
    //logging::init_tracing().expect("Couldn't init tracing.");

    // Create the prover service state
    let state = ProverServiceState::init(prover_service_config.clone(), deployment_information);
    let state = Arc::new(state);

    let vkey = fs::read_to_string(
        state
            .prover_service_config
            .test_verification_key_file_path(),
    )
    .expect("Unable to read default vkey file");
    info!("Default verifying Key: {}", vkey);

    // init jwk fetching job; refresh every `config.jwk_refresh_rate_secs` seconds
    jwk_fetching::init_jwk_fetching(
        &prover_service_config.oidc_providers,
        Duration::from_secs(prover_service_config.jwk_refresh_rate_secs),
    )
    .await;

    let (prometheus_layer, metric_handle) = PrometheusMetricLayerBuilder::new()
        .with_prefix("prover")
        .enable_response_body_size(true)
        .with_metrics_from_fn(|| {
            PrometheusBuilder::new()
                .set_buckets_for_metric(
                    Matcher::Full(AXUM_HTTP_REQUESTS_DURATION_SECONDS.to_string()),
                    SECONDS_DURATION_BUCKETS,
                )
                .unwrap()
                .install_recorder()
                .unwrap()
        })
        .build_pair();

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
        .with_state(state.clone())
        .layer(ServiceBuilder::new().layer(cors))
        .layer(prometheus_layer);

    let addr = SocketAddr::from(([0, 0, 0, 0], prover_service_config.port));
    let app_handle = tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        axum::serve(listener, app).await.unwrap();
    });

    // serve metrics on metrics_port; this is so that we don't have to expose metrics route publicly
    let app_metrics = Router::new()
        .route(
            "/metrics",
            get(|| async move {
                // TODO: will this pick up metrics from the `metric_handle`?
                let metrics = prometheus::gather();

                let mut encode_buffer = vec![];
                let encoder = TextEncoder::new();
                // If metrics encoding fails, we want to panic and crash the process.
                encoder
                    .encode(&metrics, &mut encode_buffer)
                    .context("Failed to encode metrics")
                    .unwrap();

                let res = metric_handle.render();
                encode_buffer.extend(b"\n\n");
                encode_buffer.extend(res.as_bytes());

                (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "text/plain")],
                    encode_buffer,
                )
            }),
        )
        .fallback(handlers::fallback_handler);

    let addr = SocketAddr::from(([0, 0, 0, 0], prover_service_config.metrics_port));
    let metrics_handle = tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        axum::serve(listener, app_metrics).await.unwrap();
    });

    // Wait for both serve jobs to finish indefinitely, or until one of them panics
    let res = tokio::try_join!(app_handle, metrics_handle);
    panic!(
        "One of the tasks that weren't meant to end ended unexpectedly: {:?}",
        res
    );
}

/// Loads the prover service config from the specified file path.
/// If the file cannot be read or parsed, this function will panic.
fn load_prover_service_config(config_file_path: &str) -> Arc<ProverServiceConfig> {
    info!(
        "Loading the prover service config file from path: {}",
        config_file_path
    );

    // Read the config file contents
    let config_file_contents = utils::read_string_from_file_path(config_file_path);

    // Parse the config file contents into the config struct
    let prover_service_config = match serde_yaml::from_str(&config_file_contents) {
        Ok(prover_service_config) => {
            info!(
                "Loaded the prover service config: {:?}",
                prover_service_config
            );
            prover_service_config
        }
        Err(error) => panic!(
            "Failed to parse prover service config yaml file: {}! Error: {}",
            config_file_path, error
        ),
    };

    Arc::new(prover_service_config)
}
