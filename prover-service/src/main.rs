// Copyright © Aptos Foundation

use axum::{
    http::header,
    routing::{get, post},
    Json, Router,
};
use http::{Method, StatusCode};
use log::info;
use prometheus::{Encoder, TextEncoder};
use prover_service::{state::*, *};

use anyhow::Context;
use axum_prometheus::{
    metrics_exporter_prometheus::{Matcher, PrometheusBuilder},
    utils::SECONDS_DURATION_BUCKETS,
    PrometheusMetricLayerBuilder, AXUM_HTTP_REQUESTS_DURATION_SECONDS,
};
use prover_service::config::CONFIG;
use std::{fs, net::SocketAddr, sync::Arc, time::Duration};
use tower::ServiceBuilder;
use tower_http::cors::{Any, CorsLayer};

#[tokio::main]
async fn main() {
    let cors = CorsLayer::new()
        // allow `GET` and `POST` when accessing the resource
        .allow_methods([Method::GET, Method::POST])
        // allow requests from any origin
        .allow_origin(Any)
        // allow cross-origin requests
        .allow_headers(Any);

    // init tracing
    logging::init_tracing().expect("Couldn't init tracing.");
    info!("CONFIG={:?}", CONFIG);
    let state = ProverServiceState::init();
    let state = Arc::new(state);

    let vkey = fs::read_to_string(state.config.verification_key_path())
        .expect("Unable to read default vkey file");
    info!("Default verifying Key: {}", vkey);

    // init jwk fetching job; refresh every `config.jwk_refresh_rate_secs` seconds
    jwk_fetching::init_jwk_fetching(
        &CONFIG.oidc_providers,
        Duration::from_secs(CONFIG.jwk_refresh_rate_secs),
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
    let app = Router::new()
        .route("/meta", get((StatusCode::OK, Json(CONFIG.clone()))))
        .route(
            "/v0/prove",
            post(handlers::prove_handler).fallback(handlers::fallback_handler),
        )
        .route("/healthcheck", get(handlers::healthcheck_handler))
        .fallback(handlers::fallback_handler)
        .with_state(state.clone())
        .layer(ServiceBuilder::new().layer(cors))
        .layer(prometheus_layer);

    let addr = SocketAddr::from(([0, 0, 0, 0], CONFIG.port));
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

    let addr = SocketAddr::from(([0, 0, 0, 0], CONFIG.metrics_port));
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
