// Copyright © Aptos Foundation

use once_cell::sync::Lazy;
use prometheus::{register_histogram, Histogram};

pub static PROVER_TIME_SECS: Lazy<Histogram> =
    Lazy::new(|| register_histogram!("prover_time_secs", "Prover time in seconds",).unwrap());

pub static GROTH16_TIME_SECS: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "prover_groth16_time_secs",
        "Time to run Groth16 in seconds",
        vec![1.0, 2.0, 3.0, 4.0, 5.0, 10.0, 20.0]
    )
    .unwrap()
});

pub static WITNESS_TIME_SECS: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "prover_witness_generation_time_secs",
        "Witness generation time in seconds",
        vec![0.25, 0.5, 0.75, 1.0, 2.0]
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
