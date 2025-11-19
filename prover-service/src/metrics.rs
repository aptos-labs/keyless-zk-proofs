// Copyright (c) Aptos Foundation

use crate::config::prover_config::ProverServiceConfig;
use crate::request_handler::handler::is_known_path;
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
use std::time::Instant;

// TODO: sanity check and expand these metrics!

// Constants for the metrics endpoint and response type
const METRICS_ENDPOINT: &str = "/metrics";
const PLAIN_CONTENT_TYPE: &str = "text/plain";

// Useful metric labels for counting all metrics
const TOTAL_METRIC_BYTES_LABEL: &str = "total_bytes";
const TOTAL_METRIC_FAMILIES_OVER_2000_LABEL: &str = "families_over_2000";
const TOTAL_METRICS_LABEL: &str = "total";

// Invalid request path label
const INVALID_PATH: &str = "invalid-path";

// Buckets for tracking latencies
static LATENCY_BUCKETS: Lazy<Vec<f64>> = Lazy::new(|| {
    exponential_buckets(
        /*start=*/ 1e-6, /*factor=*/ 2.0, /*count=*/ 24,
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
