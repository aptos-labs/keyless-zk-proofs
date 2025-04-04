// Copyright © Aptos Foundation

use crate::{
    api::{ProverServiceResponse, RequestInput},
    error::{self, ErrorWithCode, ThrowCodeOnError},
    input_processing::{derive_circuit_input_signals, preprocess},
    jwk_fetching::{get_federated_jwk, get_jwk},
    load_vk::prepared_vk,
    metrics,
    state::ProverServiceState,
    training_wheels,
    witness_gen::{witness_gen, PathStr},
};
use anyhow::Result;
use aptos_types::{
    jwks::rsa::RSA_JWK,
    keyless::{G1Bytes, G2Bytes, Groth16Proof},
    transaction::authenticator::EphemeralSignature,
};
use ark_ff::PrimeField;
use axum::{extract::State, http::StatusCode, Json};
use axum_extra::extract::WithRejection;

use crate::groth16_vk::{OnChainGroth16VerificationKey, ON_CHAIN_GROTH16_VK};
use crate::prover_key::{OnChainKeylessConfiguration, ON_CHAIN_KEYLESS_CONFIG};
use aptos_crypto::hash::CryptoHash;
use serde::Deserialize;
use std::{fs, sync::Arc, time::Instant};
use tracing::{info, info_span, warn};

pub async fn prove_handler(
    State(state): State<Arc<ProverServiceState>>,
    WithRejection(Json(body), _): WithRejection<Json<RequestInput>, error::ApiError>,
) -> Result<Json<ProverServiceResponse>, ErrorWithCode> {
    let start_time: Instant = Instant::now();
    let span = info_span!("prove_handler", req_hash = CryptoHash::hash(&body).to_hex());
    let _enter = span.enter();

    // TODO: add validation somewhere and nice error for override_aud_value must match aud in jwt (?)

    metrics::REQUEST_QUEUE_TIME_SECS.observe(start_time.elapsed().as_secs_f64());

    let mut jwk_override: Option<RSA_JWK> = None;
    if state.config.enable_federated_jwks {
        jwk_override = get_federated_jwk(&body)
            .await
            .ok()
            .map(|arc| (*arc).clone());
        if let Some(ref federated_jwk) = jwk_override {
            info!("Using federated jwk {:?}", federated_jwk);
        }
    }
    if state.config.use_insecure_jwk_for_test && body.use_insecure_test_jwk {
        info!("Using insecure test jwk");
        jwk_override = get_jwk(&body.jwt_b64, "https://github.com/aptos-labs/aptos-core/raw/main/types/src/jwks/rsa/insecure_test_jwk.json").await.ok().map(|arc| (*arc).clone());
    }

    training_wheels::validate_jwt_sig_and_dates(&body, jwk_override.as_ref(), &state.config)
        .with_status(StatusCode::BAD_REQUEST)?;

    let input = preprocess::decode_and_add_jwk(body, jwk_override.as_ref())
        .with_status(StatusCode::BAD_REQUEST)?;

    let on_chain_groth16_vk = {
        // Minimizing the lock acquisition time.
        ON_CHAIN_GROTH16_VK.read().unwrap().as_ref().cloned()
    };
    let local_new_groth16_vk = state.new_setup.as_ref().map(|c| &c.groth16_vk);
    #[allow(clippy::match_like_matches_macro)]
    let use_new_setup = match (on_chain_groth16_vk.as_ref(), local_new_groth16_vk) {
        (Some(on_chain), Some(local)) if on_chain == local => true,
        _ => false,
    };

    info!("Setup selected, on_chain_groth16_vk={:?}, local_new_groth16_vk={:?}, local_default_groth16_vk={:?}, use_new_setup={}", on_chain_groth16_vk, local_new_groth16_vk, state.default_setup.groth16_vk, use_new_setup);

    let circuit_config = state.circuit_config(use_new_setup);

    training_wheels::check_nonce_consistency(&input, circuit_config)
        .with_status(StatusCode::BAD_REQUEST)?;

    training_wheels::validate_jwt_payload_parsing(&input).with_status(StatusCode::BAD_REQUEST)?;

    // TODO seems not super clean to output public_inputs_hash here
    let (circuit_input_signals, public_inputs_hash) =
        derive_circuit_input_signals(input, circuit_config)
            .with_status(StatusCode::INTERNAL_SERVER_ERROR)?;

    let formatted_input_str = serde_json::to_string(&circuit_input_signals.to_json_value())
        .map_err(anyhow::Error::new)
        .with_status(StatusCode::INTERNAL_SERVER_ERROR)?;

    // Only sensitive values to disk.
    if state.config.enable_dangerous_logging {
        fs::write("formatted_input.json", &formatted_input_str).unwrap();
    }

    let witness_file = witness_gen(&state.config, use_new_setup, &formatted_input_str)
        .with_status(StatusCode::INTERNAL_SERVER_ERROR)?;

    // Prove!
    let prover_unlocked = if use_new_setup {
        state.new_setup.as_ref().unwrap().full_prover.lock().await
    } else {
        state.default_setup.full_prover.lock().await
    };

    let g16vk = prepared_vk(&state.config.verification_key_path(use_new_setup));
    let max_retries = 3;
    let mut retries = 0;
    let (proof, _proof_json, internal_metrics) = loop {
        let (proof_json, internal_metrics) = prover_unlocked
            .prove(witness_file.path_str()?)
            .map_err(error::handle_prover_lib_error)?;
        // TODO constructing the response struct should be its own func, so that I can test it
        let proof = encode_proof(
            &serde_json::from_str(proof_json)
                .map_err(anyhow::Error::from)
                .with_status(StatusCode::INTERNAL_SERVER_ERROR)?,
        )
        .with_status(StatusCode::INTERNAL_SERVER_ERROR)?;

        let verify_result = proof
            .verify_proof(
                ark_bn254::Fr::from_le_bytes_mod_order(&public_inputs_hash),
                &g16vk,
            )
            .with_status(StatusCode::INTERNAL_SERVER_ERROR);

        match verify_result {
            Ok(_) => {
                break (proof, proof_json, internal_metrics);
            }
            Err(e) => {
                warn!("Generated an invalid proof");
                warn!("Proof: {:?}", proof);
                warn!("Public inputs hash: {:?}", hex::encode(public_inputs_hash));
                retries += 1;
                if retries >= max_retries {
                    warn!("Reached max retries. Exiting.");
                    return Err(e);
                }
            }
        }
    };

    let onchain_twpk = {
        // Minimize lock acquisition time.
        ON_CHAIN_KEYLESS_CONFIG
            .read()
            .unwrap()
            .as_ref()
            .map(|c| &c.data.training_wheels_pubkey)
            .cloned()
    };

    let local_new_twpk = state
        .new_setup
        .as_ref()
        .map(|s| &s.tw_keys.on_chain_repr.data.training_wheels_pubkey);
    let (using_new_tw_keys, actual_tw_sk, actual_tw_pk) =
        match (onchain_twpk.as_ref(), local_new_twpk) {
            (Some(on_chain), Some(local)) if on_chain == local => {
                let new_tw_keys = &state.new_setup.as_ref().unwrap().tw_keys;
                (
                    true,
                    &new_tw_keys.signing_key,
                    &new_tw_keys.verification_key,
                )
            }
            _ => (
                false,
                &state.default_setup.tw_keys.signing_key,
                &state.default_setup.tw_keys.verification_key,
            ),
        };

    info!(
        "TW keys selected, onchain_twpk={:?}, local_new_twpk={:?}, local_default_twpk={:?}, use_new_twpk={}",
        onchain_twpk,
        local_new_twpk,
        state.default_setup.tw_keys.on_chain_repr.data.training_wheels_pubkey,
        using_new_tw_keys
    );

    let training_wheels_signature = EphemeralSignature::ed25519(
        training_wheels::sign(actual_tw_sk, proof, public_inputs_hash)
            .map_err(anyhow::Error::from)
            .with_status(StatusCode::INTERNAL_SERVER_ERROR)?,
    );

    let response = ProverServiceResponse::Success {
        proof,
        public_inputs_hash,
        training_wheels_signature: bcs::to_bytes(&training_wheels_signature)
            .expect("Only unhandleable errors happen here."),
    };

    if state.config.enable_debug_checks {
        assert!(training_wheels::verify(&response, actual_tw_pk).is_ok());
    }

    metrics::GROTH16_TIME_SECS.observe((f64::from(internal_metrics.prover_time)) / 1000.0);

    Ok(Json(response))
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

pub async fn cached_groth16_vk_handler() -> (StatusCode, Json<Option<OnChainGroth16VerificationKey>>)
{
    let cached = { ON_CHAIN_GROTH16_VK.read().unwrap().as_ref().cloned() };
    if let Some(val) = cached {
        (StatusCode::OK, Json(Some(val)))
    } else {
        (StatusCode::NOT_FOUND, Json(None))
    }
}

pub async fn cached_keyless_config() -> (StatusCode, Json<Option<OnChainKeylessConfiguration>>) {
    let cached = { ON_CHAIN_KEYLESS_CONFIG.read().unwrap().as_ref().cloned() };
    if let Some(val) = cached {
        (StatusCode::OK, Json(Some(val)))
    } else {
        (StatusCode::NOT_FOUND, Json(None))
    }
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
