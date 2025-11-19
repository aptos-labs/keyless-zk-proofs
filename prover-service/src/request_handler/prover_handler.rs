// Copyright (c) Aptos Foundation

use crate::error::ProverServiceError;
use crate::request_handler::witness_gen::PathStr;
use crate::request_handler::{handler, witness_gen};
use crate::{
    input_processing,
    request_handler::prover_state::ProverServiceState,
    training_wheels,
    types::api::{ProverServiceResponse, RequestInput},
    utils,
};
use anyhow::Result;
use aptos_keyless_common::PoseidonHash;
use aptos_logger::{error, warn};
use aptos_types::keyless::{g1_projective_str_to_affine, g2_projective_str_to_affine};
use aptos_types::{
    keyless::{G1Bytes, G2Bytes, Groth16Proof},
    transaction::authenticator::EphemeralSignature,
};
use ark_bn254::Bn254;
use ark_ff::PrimeField;
use ark_groth16::{PreparedVerifyingKey, VerifyingKey};
use hyper::{Body, Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::sync::Arc;
use tempfile::NamedTempFile;

/// Handles a prove request
pub async fn hande_prove_request(
    origin: String,
    request: Request<Body>,
    prover_service_state: Arc<ProverServiceState>,
) -> Result<Response<Body>, Infallible> {
    // Get the request body bytes
    let request_body = request.into_body();
    let request_bytes = match hyper::body::to_bytes(request_body).await {
        Ok(request_bytes) => request_bytes,
        Err(error) => {
            error!("Failed to get request body bytes! Error: {}", error);
            return handler::generate_internal_server_error_response(origin);
        }
    };

    // Extract the request input from the request bytes
    let request_input: RequestInput = match serde_json::from_slice(&request_bytes) {
        Ok(request_input) => request_input,
        Err(error) => {
            let error_string = format!("Failed to deserialize request body JSON! Error: {}", error);
            warn!("{}", error_string);
            return handler::generate_bad_request_response(origin, error_string);
        }
    };

    // Validate the input request
    let verified_input = match training_wheels::preprocess_and_validate_request(
        &prover_service_state,
        &request_input,
    )
    .await
    {
        Ok(verified_input) => verified_input,
        Err(error) => {
            warn!("Failed to validate request! Error: {}", error);

            // Don't return the exact error (to avoid leaking any sensitive info)
            return handler::generate_bad_request_response(
                origin,
                "Failed to validate request!".into(),
            );
        }
    };

    // Derive the circuit input signals from the verified input
    let circuit_config = prover_service_state.circuit_config();
    let (circuit_input_signals, public_inputs_hash) =
        match input_processing::derive_circuit_input_signals(verified_input, circuit_config) {
            Ok((input_signals, input_hash)) => (input_signals, input_hash),
            Err(error) => {
                warn!("Failed to derive circuit input signals! Error: {}", error);

                // Don't return the exact error (to avoid leaking any sensitive info)
                return handler::generate_bad_request_response(
                    origin,
                    "Failed to derive circuit input signals!".into(),
                );
            }
        };

    // Generate the witness file
    let prover_service_config = prover_service_state.prover_service_config();
    let witness_file = match witness_gen::witness_gen(prover_service_config, &circuit_input_signals)
    {
        Ok(witness_file) => witness_file,
        Err(error) => {
            warn!("Failed to generate witness file! Error: {}", error);

            // Don't return the exact error (to avoid leaking any sensitive info)
            return handler::generate_internal_server_error_response(origin);
        }
    };

    // Generate the groth16 proof
    let groth16_proof =
        match generate_groth16_proof(&prover_service_state, witness_file, public_inputs_hash).await
        {
            Ok(groth16_proof) => groth16_proof,
            Err(error) => {
                warn!("Failed to generate proof! Error: {}", error);

                // Don't return the exact error (to avoid leaking any sensitive info)
                return handler::generate_bad_request_response(
                    origin,
                    "Failed to generate proof!".into(),
                );
            }
        };

    // Sign the proof using the training wheels (TW) key.
    // Note: we should've signed the VK too but, unfortunately, we realized this too late.
    // As a result, whenever the VK changes on-chain, the TW PK must change too.
    // Otherwise, an old proof computed for an old VK will pass the TW signature check,
    // even though this proof will not verify under the new VK.
    let training_wheels_signing_key = prover_service_state
        .training_wheels_key_pair()
        .signing_key();
    let training_wheels_signature = match training_wheels::sign(
        training_wheels_signing_key,
        groth16_proof,
        public_inputs_hash,
    ) {
        Ok(signature) => signature,
        Err(error) => {
            error!(
                "Failed to sign the proof with the training wheels key! Error: {}",
                error
            );
            return handler::generate_internal_server_error_response(origin);
        }
    };

    // Serialize the training wheels signature
    let ephemeral_signature = EphemeralSignature::ed25519(training_wheels_signature);
    let training_wheels_signature = match bcs::to_bytes(&ephemeral_signature) {
        Ok(signature_bytes) => signature_bytes,
        Err(error) => {
            error!(
                "Failed to serialize the training wheels signature! Error: {}",
                error
            );
            return handler::generate_internal_server_error_response(origin);
        }
    };

    // Generate the prover service response
    let prover_service_response = ProverServiceResponse::Success {
        proof: groth16_proof,
        public_inputs_hash,
        training_wheels_signature,
    };

    // Verify the training wheels signature. This is necessary to ensure that
    // only valid signatures are returned, and avoids certain classes of bugs
    // and attacks (e.g., fault-based side-channels).
    // fault-based side-channels).
    let verification_key = prover_service_state
        .training_wheels_key_pair()
        .verification_key();
    assert!(training_wheels::verify(&prover_service_response, verification_key,).is_ok());

    // Serialize the response to JSON and generate the HTTP response
    let response_string = match serde_json::to_string(&prover_service_response) {
        Ok(response_string) => response_string,
        Err(error) => {
            error!(
                "Failed to serialize prover service response to JSON! Error: {}",
                error
            );
            return handler::generate_internal_server_error_response(origin);
        }
    };
    handler::generate_json_response(origin, StatusCode::OK, response_string)
}

/// Generates a groth16 proof using the provided witness file and public inputs hash
async fn generate_groth16_proof(
    prover_service_state: &ProverServiceState,
    witness_file: NamedTempFile,
    public_inputs_hash: PoseidonHash,
) -> Result<Groth16Proof, ProverServiceError> {
    // Get the witness file path
    let witness_file_path = match witness_file.path_str() {
        Ok(path_str) => path_str,
        Err(error) => {
            return Err(ProverServiceError::UnexpectedError(format!(
                "Failed to get witness file path! Error: {}",
                error
            )));
        }
    };

    // Generate the JSON proof
    let full_prover = prover_service_state.full_prover();
    let full_prover_locked = full_prover.lock().await;
    let (proof_json, _internal_metrics) = match full_prover_locked.prove(witness_file_path) {
        Ok((proof_json, metrics)) => (proof_json.to_string(), metrics),
        Err(error) => {
            return Err(ProverServiceError::UnexpectedError(format!(
                "Failed to generate rapidsnark proof! Error: {:?}",
                error
            )));
        }
    };

    // Deserialize the JSON proof into a rapidsnark proof
    let rapidsnark_proof_response = match serde_json::from_str(&proof_json) {
        Ok(proof) => proof,
        Err(error) => {
            return Err(ProverServiceError::UnexpectedError(format!(
                "Failed to deserialize rapidsnark proof JSON! Error: {}",
                error
            )));
        }
    };

    // Encode the rapidsnark proof into a groth16 proof
    let groth16_proof = match encode_proof(&rapidsnark_proof_response) {
        Ok(proof) => proof,
        Err(error) => {
            return Err(ProverServiceError::UnexpectedError(format!(
                "Failed to encode rapidsnark proof! Error: {}",
                error
            )));
        }
    };

    // Prepare the groth16 verification key
    let verification_key_file_path = prover_service_state
        .prover_service_config()
        .verification_key_file_path();
    let groth16_prepare_verifying_key = prepared_vk(&verification_key_file_path)?;

    // Verify the proof. This is necessary to ensure that only valid proofs
    // are returned, and avoids certain classes of bugs and attacks (e.g.,
    // fault-based side-channels).
    groth16_proof.verify_proof(
        ark_bn254::Fr::from_le_bytes_mod_order(&public_inputs_hash),
        &groth16_prepare_verifying_key,
    )?;

    Ok(groth16_proof)
}

// TODO: should we rename RawVK?

/// A raw VK as outputted by circom in YAML format
#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
struct RawVK {
    vk_alpha_1: Vec<String>,
    vk_beta_2: Vec<Vec<String>>,
    vk_gamma_2: Vec<Vec<String>>,
    vk_delta_2: Vec<Vec<String>>,
    IC: Vec<Vec<String>>,
}

/// This function uses the decimal uncompressed point serialization which is outputted by circom
pub fn prepared_vk(vk_file_path: &str) -> Result<PreparedVerifyingKey<Bn254>, ProverServiceError> {
    // Fetch the raw VK from the file
    let raw_vk_yaml = utils::read_string_from_file_path(vk_file_path);
    let raw_vk: RawVK = match serde_yaml::from_str(&raw_vk_yaml) {
        Ok(raw_vk) => raw_vk,
        Err(error) => {
            return Err(ProverServiceError::UnexpectedError(format!(
                "Failed to parse VK YAML file: {}! Error: {}",
                vk_file_path, error
            )));
        }
    };

    // Construct alpha_g1
    let alpha_g1 =
        g1_projective_str_to_affine(&raw_vk.vk_alpha_1[0], &raw_vk.vk_alpha_1[1]).unwrap();

    // Construct beta_g2
    let beta_g2 = g2_projective_str_to_affine(
        [&raw_vk.vk_beta_2[0][0], &raw_vk.vk_beta_2[0][1]],
        [&raw_vk.vk_beta_2[1][0], &raw_vk.vk_beta_2[1][1]],
    )
    .unwrap();

    // Construct gamma_g2
    let gamma_g2 = g2_projective_str_to_affine(
        [&raw_vk.vk_gamma_2[0][0], &raw_vk.vk_gamma_2[0][1]],
        [&raw_vk.vk_gamma_2[1][0], &raw_vk.vk_gamma_2[1][1]],
    )
    .unwrap();

    // Construct delta_g2
    let delta_g2 = g2_projective_str_to_affine(
        [&raw_vk.vk_delta_2[0][0], &raw_vk.vk_delta_2[0][1]],
        [&raw_vk.vk_delta_2[1][0], &raw_vk.vk_delta_2[1][1]],
    )
    .unwrap();

    // Construct gamma_abc_g1
    let mut gamma_abc_g1 = Vec::new();
    for p in raw_vk.IC {
        gamma_abc_g1.push(g1_projective_str_to_affine(&p[0], &p[1]).unwrap());
    }

    // Create and return the prepared verifying key
    let vk = VerifyingKey {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        gamma_abc_g1,
    };
    Ok(PreparedVerifyingKey::from(vk))
}

/// A rapidsnark proof response
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

/// Encodes a Rapidsnark proof response into a Groth16 proof
pub fn encode_proof(rapidsnark_proof_response: &RapidsnarkProofResponse) -> Result<Groth16Proof> {
    let new_pi_a = G1Bytes::new_unchecked(
        &rapidsnark_proof_response.pi_a[0],
        &rapidsnark_proof_response.pi_a[1],
    )?;
    let new_pi_b = G2Bytes::new_unchecked(
        rapidsnark_proof_response.pi_b_str()[0],
        rapidsnark_proof_response.pi_b_str()[1],
    )?;
    let new_pi_c = G1Bytes::new_unchecked(
        &rapidsnark_proof_response.pi_c[0],
        &rapidsnark_proof_response.pi_c[1],
    )?;

    Ok(Groth16Proof::new(new_pi_a, new_pi_b, new_pi_c))
}
