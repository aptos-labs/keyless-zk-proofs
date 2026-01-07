// Copyright (c) Aptos Foundation

use crate::external_resources::prover_config::ProverServiceConfig;
use crate::request_handler::handler::is_known_path;
use crate::request_handler::types::VerifiedInput;
use aptos_logger::{error, info, warn};
use aptos_metrics_core::{
    exponential_buckets, register_histogram_vec, register_int_counter_vec, Encoder, HistogramVec,
    IntCounterVec, TextEncoder,
};
use hyper::header::CONTENT_TYPE;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Server, StatusCode};
use once_cell::sync::Lazy;
use prometheus::proto::MetricFamily;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

// Constants for the metrics endpoint and response type
const METRICS_ENDPOINT: &str = "/metrics";
const PLAIN_CONTENT_TYPE: &str = "text/plain";

// Useful metric labels for counting all metrics
const TOTAL_METRIC_BYTES_LABEL: &str = "total_bytes";
const TOTAL_METRIC_FAMILIES_OVER_2000_LABEL: &str = "families_over_2000";
const TOTAL_METRICS_LABEL: &str = "total";

// Useful metric labels for different phases of prove request handling
pub const DERIVE_CIRCUIT_INPUT_SIGNALS_LABEL: &str = "derive_circuit_input_signals";
pub const DESERIALIZE_PROVE_REQUEST_LABEL: &str = "deserialize_prove_request";
pub const PROOF_DESERIALIZATION_LABEL: &str = "proof_deserialization";
pub const PROOF_GENERATION_LABEL: &str = "proof_generation";
pub const PROOF_TW_SIGNATURE_LABEL: &str = "proof_tw_signature";
pub const PROOF_VERIFICATION_LABEL: &str = "proof_verification";
pub const PROVER_RESPONSE_GENERATION_LABEL: &str = "prover_response_generation";
pub const VALIDATE_PROVE_REQUEST_LABEL: &str = "validate_prove_request";
pub const WITNESS_GENERATION_LABEL: &str = "witness_generation";

// Useful metric labels for JWT attribute sizes
const JWT_HEADER_SIZE: &str = "jwt_header_size";
const JWT_PAYLOAD_SIZE: &str = "jwt_payload_size";
const JWT_SIGNATURE_SIZE: &str = "jwt_signature_size";
const JWT_ISS_SIZE: &str = "jwt_iss_size";
const JWT_NONCE_SIZE: &str = "jwt_nonce_size";
const JWT_SUB_SIZE: &str = "jwt_sub_size";
const JWT_EMAIL_SIZE: &str = "jwt_email_size";
const JWT_AUD_SIZE: &str = "jwt_aud_size";

// Invalid request path label
const INVALID_PATH: &str = "invalid-path";

// Histogram for tracking time taken to fetch JWKs by issuer and result
static JWK_FETCH_SECONDS: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "keyless_prover_service_jwk_fetch_seconds",
        "Time taken to fetch keyless prover service jwks",
        &["issuer", "succeeded"],
        LATENCY_BUCKETS.clone()
    )
    .unwrap()
});

// Buckets for tracking latencies
static LATENCY_BUCKETS: Lazy<Vec<f64>> = Lazy::new(|| {
    exponential_buckets(
        /*start=*/ 1e-6, /*factor=*/ 2.0, /*count=*/ 24,
    )
    .unwrap()
});

// Buckets for tracking sizes (1 byte to 256 KB)
static SIZE_BUCKETS: Lazy<Vec<f64>> = Lazy::new(|| {
    exponential_buckets(
        /*start=*/ 1.0, /*factor=*/ 2.0, /*count=*/ 19,
    )
    .unwrap()
});

// Counter for the number of prover metrics in various states
pub static NUM_TOTAL_METRICS: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "keyless_prover_service_num_metrics",
        "Number of keyless prover metrics in certain states",
        &["type"]
    )
    .unwrap()
});

// Histogram for tracking the internal breakdown of prove request handling
static PROVE_REQUEST_BREAKDOWN_SECONDS: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "keyless_prover_service_prove_request_breakdown_seconds",
        "Time taken to handle various phases of the prove request.",
        &["phase"],
        LATENCY_BUCKETS.clone()
    )
    .unwrap()
});

// Histogram for tracking time taken to handle prover service requests
static REQUEST_HANDLING_SECONDS: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "keyless_prover_service_request_handling_seconds",
        "Seconds taken to process prover requests by scheme and result.",
        &["request_endpoint", "request_method", "response_code"],
        LATENCY_BUCKETS.clone()
    )
    .unwrap()
});

// Histogram for tracking the attribute sizes of JWT requests
static REQUEST_JWT_ATTRIBUTE_SIZES: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "keyless_prover_service_request_jwt_attribute_sizes",
        "Sizes of request JWT attributes",
        &["attribute"],
        SIZE_BUCKETS.clone()
    )
    .unwrap()
});

/// Handles incoming HTTP requests for the metrics server
async fn handle_metrics_request(
    request: hyper::Request<Body>,
) -> Result<hyper::Response<Body>, Infallible> {
    let response = match (request.method(), request.uri().path()) {
        (&Method::GET, METRICS_ENDPOINT) => {
            let buffer = get_encoded_metrics(TextEncoder::new());
            hyper::Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, PLAIN_CONTENT_TYPE)
                .body(Body::from(buffer))
                .expect("The metric response failed to build!")
        }
        _ => {
            let mut response = hyper::Response::new(Body::empty());
            *response.status_mut() = StatusCode::NOT_FOUND;
            response
        }
    };
    Ok(response)
}

/// A simple utility function that encodes the metrics using the given encoder
fn get_encoded_metrics(encoder: impl Encoder) -> Vec<u8> {
    // Gather and encode the metrics
    let metric_families = get_metric_families();
    let mut encoded_buffer = vec![];
    if let Err(error) = encoder.encode(&metric_families, &mut encoded_buffer) {
        error!("Failed to encode metrics! Error: {}", error);
        return vec![];
    }

    // Update the total metric bytes counter
    NUM_TOTAL_METRICS
        .with_label_values(&[TOTAL_METRIC_BYTES_LABEL])
        .inc_by(encoded_buffer.len() as u64);

    encoded_buffer
}

/// A simple utility function that returns all metric families
fn get_metric_families() -> Vec<MetricFamily> {
    let metric_families = aptos_metrics_core::gather();
    let mut total: u64 = 0;
    let mut families_over_2000: u64 = 0;

    // Take metrics of metric gathering so we know possible overhead of this process
    for metric_family in &metric_families {
        let family_count = metric_family.get_metric().len();
        if family_count > 2000 {
            families_over_2000 = families_over_2000.saturating_add(1);
            let name = metric_family.get_name();
            warn!(
                count = family_count,
                metric_family = name,
                "Metric Family '{}' over 2000 dimensions '{}'",
                name,
                family_count
            );
        }
        total = total.saturating_add(family_count as u64);
    }

    // These metrics will be reported on the next pull, rather than create a new family
    NUM_TOTAL_METRICS
        .with_label_values(&[TOTAL_METRICS_LABEL])
        .inc_by(total);
    NUM_TOTAL_METRICS
        .with_label_values(&[TOTAL_METRIC_FAMILIES_OVER_2000_LABEL])
        .inc_by(families_over_2000);

    metric_families
}

// Starts a simple metrics server
pub fn start_metrics_server(prover_service_config: Arc<ProverServiceConfig>) {
    let _handle = tokio::spawn(async move {
        info!("Starting metrics server request handler...");

        // Create a service function that handles the metrics requests
        let make_service = make_service_fn(|_conn| async {
            Ok::<_, Infallible>(service_fn(handle_metrics_request))
        });

        // Bind the socket address, and start the server
        let socket_addr = SocketAddr::from(([0, 0, 0, 0], prover_service_config.metrics_port));
        let server = Server::bind(&socket_addr).serve(make_service);
        if let Err(error) = server.await {
            panic!("Metrics server error! Error: {}", error);
        }
    });
}

/// Updates the JWK fetch metrics with the given data
pub fn update_jwk_fetch_metrics(issuer: &str, succeeded: bool, elapsed: Duration) {
    JWK_FETCH_SECONDS
        .with_label_values(&[issuer, &succeeded.to_string()])
        .observe(elapsed.as_secs_f64());
}

/// Updates the prove request breakdown metrics with the given data
pub fn update_prove_request_breakdown_metrics(phase: &str, elapsed: Duration) {
    PROVE_REQUEST_BREAKDOWN_SECONDS
        .with_label_values(&[phase])
        .observe(elapsed.as_secs_f64());
}

/// Updates the request handling metrics with the given data
pub fn update_request_handling_metrics(
    request_endpoint: &str,
    request_method: Method,
    response_code: StatusCode,
    request_start_time: Instant,
) {
    // Calculate the elapsed time
    let elapsed = request_start_time.elapsed();

    // Determine the request endpoint to use in the metrics (i.e., replace
    // invalid paths with a fixed label to avoid high cardinality).
    let request_endpoint = if is_known_path(request_endpoint) {
        request_endpoint
    } else {
        INVALID_PATH
    };

    // Update the metrics
    REQUEST_HANDLING_SECONDS
        .with_label_values(&[
            request_endpoint,
            request_method.as_str(),
            &response_code.to_string(),
        ])
        .observe(elapsed.as_secs_f64());
}

/// Updates the JWT attribute size metrics for the given attribute and size
fn update_jwt_attribute_size_metrics(attribute: &str, size_bytes: usize) {
    REQUEST_JWT_ATTRIBUTE_SIZES
        .with_label_values(&[attribute])
        .observe(size_bytes as f64);
}

/// Updates the JWT attribute metrics based on the verified input
pub fn update_jwt_attribute_metrics(verified_input: &VerifiedInput) {
    // Update the JWT parts metrics
    let jwt_parts = &verified_input.jwt_parts;
    update_jwt_attribute_size_metrics(JWT_HEADER_SIZE, jwt_parts.header_undecoded().len());
    update_jwt_attribute_size_metrics(JWT_PAYLOAD_SIZE, jwt_parts.payload_undecoded().len());
    update_jwt_attribute_size_metrics(JWT_SIGNATURE_SIZE, jwt_parts.signature_undecoded().len());

    // Update the JWT field metrics
    let jwt_payload = &verified_input.jwt.payload;
    update_jwt_attribute_size_metrics(JWT_ISS_SIZE, jwt_payload.iss.len());
    update_jwt_attribute_size_metrics(JWT_NONCE_SIZE, jwt_payload.nonce.len());
    if let Some(sub) = &jwt_payload.sub {
        update_jwt_attribute_size_metrics(JWT_SUB_SIZE, sub.len());
    }
    if let Some(email) = &jwt_payload.email {
        update_jwt_attribute_size_metrics(JWT_EMAIL_SIZE, email.len());
    }
    update_jwt_attribute_size_metrics(JWT_AUD_SIZE, jwt_payload.aud.len());
}
