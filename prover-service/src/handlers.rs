// Copyright © Aptos Foundation

use crate::{
    api::{ProverServiceResponse, RequestInput},
    error::{self, ErrorWithCode, ThrowCodeOnError},
    input_processing::derive_circuit_input_signals,
    metrics,
    state::ProverServiceState,
    training_wheels,
    witness_gen::witness_gen,
};
use anyhow::Result;
use aptos_types::{
    keyless::{G1Bytes, G2Bytes, Groth16Proof},
    transaction::authenticator::EphemeralSignature,
};
use axum::{extract::State, http::StatusCode, Json};
use axum_extra::extract::WithRejection;

use crate::proving::prove;
use aptos_crypto::hash::CryptoHash;
use aptos_keyless_common::logging;
use aptos_keyless_common::logging::HasLoggableError;
use maplit2::hashmap;
use serde::Deserialize;
use std::{sync::Arc, time::Instant};
use uuid::Uuid;

pub async fn prove_handler(
    State(state): State<Arc<ProverServiceState>>,
    WithRejection(Json(body), _): WithRejection<Json<RequestInput>, error::ApiError>,
) -> Result<Json<ProverServiceResponse>, ErrorWithCode> {
    let start_time: Instant = Instant::now();
    metrics::REQUEST_QUEUE_TIME_SECS.observe(start_time.elapsed().as_secs_f64());

    logging::run_with_empty_logger_context(async {
        let _span = logging::new_span_extra_attrs(
            "HandleRequest",
            hashmap! {
                "session_id" => Uuid::new_v4().to_string()[0..8].to_string(),
                "req_hash" => CryptoHash::hash(&body).to_hex(),
            },
        );

        let input = training_wheels::preprocess_and_validate_request(state.as_ref(), &body)
            .await
            .log_err()
            .with_status(StatusCode::BAD_REQUEST)?;

        let (circuit_input_signals, public_inputs_hash) =
            derive_circuit_input_signals(input, state.circuit_config()).log_err()?;

        let witness_file = witness_gen(&state.config, &circuit_input_signals).log_err()?;

        let proof = prove(state.as_ref(), witness_file, public_inputs_hash)
            .await
            .log_err()?;

        // We should've signed the VK too but, unfortunately, we realized this too late.
        // As a result, whenever the VK changes on-chain, the TW PK must change too.
        // Otherwise, an old proof computed for an old VK will pass the TW signature check, even though this proof will not verify under the new VK.
        let training_wheels_signature = EphemeralSignature::ed25519(
            training_wheels::sign(&state.tw_keys.signing_key, proof, public_inputs_hash)
                .map_err(anyhow::Error::from)
                .log_err()?,
        );

        let response = ProverServiceResponse::Success {
            proof,
            public_inputs_hash,
            training_wheels_signature: bcs::to_bytes(&training_wheels_signature).unwrap(),
        };

        if state.config.enable_debug_checks {
            assert!(training_wheels::verify(&response, &state.tw_keys.verification_key).is_ok());
        }

        Ok(Json(response))
    })
    .await
}

/// Added on request by Christian: Kubernetes apparently needs a GET route to check whether
/// this service is ready for requests.
pub async fn healthcheck_handler() -> (StatusCode, &'static str) {
    // TODO: CHECK FOR A REAL STATUS OF PROVER HERE?
    (StatusCode::OK, "OK")
}

/// On all unrecognized routes, return 404.
pub async fn fallback_handler() -> (StatusCode, &'static str) {
    (StatusCode::NOT_FOUND, "Invalid route")
}

#[derive(Deserialize)]
pub struct RapidsnarkProofResponse {
    pi_a: [String; 3],
    pi_b: [[String; 2]; 3],
    pi_c: [String; 3],
}

impl RapidsnarkProofResponse {
    fn pi_b_str(&self) -> [[&str; 2]; 3] {
        [
            [&self.pi_b[0][0], &self.pi_b[0][1]],
            [&self.pi_b[1][0], &self.pi_b[1][1]],
            [&self.pi_b[2][0], &self.pi_b[2][1]],
        ]
    }
}

pub fn encode_proof(proof: &RapidsnarkProofResponse) -> Result<Groth16Proof> {
    let new_pi_a = G1Bytes::new_unchecked(&proof.pi_a[0], &proof.pi_a[1])?;
    let new_pi_b = G2Bytes::new_unchecked(proof.pi_b_str()[0], proof.pi_b_str()[1])?;
    let new_pi_c = G1Bytes::new_unchecked(&proof.pi_c[0], &proof.pi_c[1])?;

    Ok(Groth16Proof::new(new_pi_a, new_pi_b, new_pi_c))
}
