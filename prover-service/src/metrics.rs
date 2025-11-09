// Copyright (c) Aptos Foundation

use aptos_logger::{error, warn};
use aptos_metrics_core::{
    register_histogram, register_int_counter_vec, Histogram, IntCounterVec, TextEncoder,
};
use hyper::header::CONTENT_TYPE;
use hyper::{Body, Method, StatusCode};
use once_cell::sync::Lazy;
use prometheus::{proto::MetricFamily, Encoder};
use std::convert::Infallible;

// TODO: sanity check and expand these metrics!

pub static GROTH16_TIME_SECS: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "prover_groth16_time_secs",
        "Time to run Groth16 in seconds",
        vec![1.0, 2.0, 3.0, 4.0, 5.0, 10.0, 20.0]
    )
    .unwrap()
});

pub static REQUEST_QUEUE_TIME_SECS: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "prover_request_queue_time_secs",
        "Time in seconds between the point when a request is received and the point when the prover starts processing the request",
        vec![0.5, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0, 20.0, 30.0, 40.0, 50.0, 60.0]
    )
    .unwrap()
});

/// Counter for the number of metrics in various states
pub static NUM_METRICS: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "aptos_metrics",
        "Number of metrics in certain states",
        &["type"]
    )
    .unwrap()
});

/// Handles incoming HTTP requests for the metrics server
pub async fn handle_metrics_request(
    request: hyper::Request<Body>,
) -> Result<hyper::Response<Body>, Infallible> {
    let response = match (request.method(), request.uri().path()) {
        (&Method::GET, "/metrics") => {
            let buffer = get_encoded_metrics(TextEncoder::new());
            hyper::Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "text/plain")
                .body(Body::from(buffer))
                .expect("Metric response should build")
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
    NUM_METRICS
        .with_label_values(&["total_bytes"])
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
    NUM_METRICS.with_label_values(&["total"]).inc_by(total);
    NUM_METRICS
        .with_label_values(&["families_over_2000"])
        .inc_by(families_over_2000);

    metric_families
}
