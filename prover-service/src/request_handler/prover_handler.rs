// Copyright (c) Aptos Foundation

use crate::error::ProverServiceError;
use crate::external_resources::prover_config::ProverServiceConfig;
use crate::input_processing::input_signals;
use crate::metrics::{
    DERIVE_CIRCUIT_INPUT_SIGNALS_LABEL, DESERIALIZE_PROVE_REQUEST_LABEL,
    PROOF_DESERIALIZATION_LABEL, PROOF_GENERATION_LABEL, PROOF_TW_SIGNATURE_LABEL,
    PROOF_VERIFICATION_LABEL, PROVER_RESPONSE_GENERATION_LABEL, VALIDATE_PROVE_REQUEST_LABEL,
    WITNESS_GENERATION_LABEL,
};
use crate::request_handler::types::{ProverServiceResponse, RequestInput, VerifiedInput};
use crate::request_handler::{handler, training_wheels, types};
use crate::{metrics, request_handler::prover_state::ProverServiceState, utils};
use aptos_keyless_common::input_processing::circuit_input_signals::{CircuitInputSignals, Padded};
use aptos_keyless_common::types::PoseidonHash;
use aptos_logger::{error, warn};
use aptos_types::keyless::Groth16Proof;
use aptos_types::transaction::authenticator::EphemeralSignature;
use ark_ff::PrimeField;
use hyper::{Body, Request, Response, StatusCode};
use std::convert::Infallible;
use std::fs;
use std::process::Command;
use std::sync::Arc;
use std::time::Instant;
use tempfile::NamedTempFile;

/// Handles a prove request
pub async fn hande_prove_request(
    origin: String,
    request: Request<Body>,
    prover_service_state: Arc<ProverServiceState>,
) -> Result<Response<Body>, Infallible> {
    // Extract the prove request input
    let prove_request_input = match extract_prove_request_input(request).await {
        Ok(prove_request_input) => prove_request_input,
        Err(error) => {
            let error_string = format!("Failed to extract prove request input! Error: {}", error);
            warn!("{}", error_string);

            return handler::generate_bad_request_response(origin, error_string);
        }
    };

    // Validate the input request
    let verified_input =
        match validate_prove_request_input(&prover_service_state, &prove_request_input).await {
            Ok(verified_input) => verified_input,
            Err(error) => {
                let error_string =
                    format!("Failed to validate prove request input! Error: {}", error);
                warn!("{}", error_string);

                return handler::generate_bad_request_response(origin, error_string);
            }
        };

    // Generate the witness file for the proof
    let (generated_witness_file, public_inputs_hash) =
        match generate_witness_file_for_proof(&prover_service_state, verified_input).await {
            Ok(generated_witness_file) => generated_witness_file,
            Err(error) => {
                error!(
                    "Failed to generate witness file for proof! Error: {}",
                    error
                );
                return handler::generate_internal_server_error_response(origin);
            }
        };

    // Generate the groth16 proof
    let generated_groth16_proof = match generate_groth16_proof(
        &prover_service_state,
        generated_witness_file,
        public_inputs_hash,
    )
    .await
    {
        Ok(generated_groth16_proof) => generated_groth16_proof,
        Err(error) => {
            error!("Failed to generate groth16 proof! Error: {}", error);
            return handler::generate_internal_server_error_response(origin);
        }
    };

    // Sign the proof using the training wheels key
    let training_wheels_signature = match sign_groth16_proof_with_tw_key(
        &prover_service_state,
        generated_groth16_proof,
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

    // Generate and verify the prover service response
    match generate_and_verify_proof_response(
        &prover_service_state,
        generated_groth16_proof,
        public_inputs_hash,
        training_wheels_signature,
    ) {
        Ok(response_string) => {
            handler::generate_json_response(origin, StatusCode::OK, response_string)
        }
        Err(error) => {
            error!(
                "Failed to generate and verify the prover service response! Error: {}",
                error
            );
            handler::generate_internal_server_error_response(origin)
        }
    }
}

/// Extracts the request input from the given HTTP request
async fn extract_prove_request_input(
    request: Request<Body>,
) -> Result<RequestInput, ProverServiceError> {
    // Start the deserialization timer
    let deserialization_timer = Instant::now();

    // Get the request body bytes
    let request_body = request.into_body();
    let request_bytes = match hyper::body::to_bytes(request_body).await {
        Ok(request_bytes) => request_bytes,
        Err(error) => {
            return Err(ProverServiceError::BadRequest(format!(
                "Failed to read request body bytes! Error: {}",
                error
            )));
        }
    };

    // Extract the request input from the request bytes
    let request_input = match serde_json::from_slice(&request_bytes) {
        Ok(request_input) => request_input,
        Err(error) => {
            return Err(ProverServiceError::BadRequest(format!(
                "Failed to deserialize request body JSON! Error: {}",
                error
            )));
        }
    };

    // Update the deserialization metrics
    metrics::update_prove_request_breakdown_metrics(
        DESERIALIZE_PROVE_REQUEST_LABEL,
        deserialization_timer.elapsed(),
    );

    Ok(request_input)
}

/// Generates and verifies the prover service response
fn generate_and_verify_proof_response(
    prover_service_state: &ProverServiceState,
    groth16_proof: Groth16Proof,
    public_inputs_hash: PoseidonHash,
    training_wheels_signature: Vec<u8>,
) -> Result<String, ProverServiceError> {
    // Start the prover response generation timer
    let prover_response_generation_timer = Instant::now();

    // Generate the prover service response
    let prover_service_response = ProverServiceResponse::Success {
        proof: groth16_proof,
        public_inputs_hash,
        training_wheels_signature,
    };

    // Verify the training wheels signature. This is necessary to ensure that
    // only valid signatures are returned, and avoids certain classes of bugs
    // and attacks (e.g., fault-based side-channels).
    let verification_key = prover_service_state
        .training_wheels_key_pair()
        .verification_key();
    if let Err(error) = training_wheels::verify(&prover_service_response, verification_key) {
        return Err(ProverServiceError::UnexpectedError(format!(
            "Failed to verify training wheels signature on prover service response! Error: {}",
            error
        )));
    }

    // Serialize the response to JSON and generate the HTTP response
    let response_string = match serde_json::to_string(&prover_service_response) {
        Ok(response_string) => response_string,
        Err(error) => {
            return Err(ProverServiceError::UnexpectedError(format!(
                "Failed to serialize prover service response to JSON! Error: {}",
                error
            )));
        }
    };

    // Update the prover response generation metrics
    metrics::update_prove_request_breakdown_metrics(
        PROVER_RESPONSE_GENERATION_LABEL,
        prover_response_generation_timer.elapsed(),
    );

    Ok(response_string)
}

/// Generates a groth16 proof using the provided witness file and public inputs hash
async fn generate_groth16_proof(
    prover_service_state: &ProverServiceState,
    witness_file: NamedTempFile,
    public_inputs_hash: PoseidonHash,
) -> Result<Groth16Proof, ProverServiceError> {
    // Start the proof generation timer
    let proof_generation_timer = Instant::now();

    // Get the witness file path
    let witness_file_path = match witness_file.path().to_str() {
        Some(path_str) => path_str,
        None => {
            return Err(ProverServiceError::UnexpectedError(format!(
                "Failed to get witness file path as string: {:?}",
                witness_file.path()
            )));
        }
    };

    // Generate the JSON proof
    let full_prover = prover_service_state.full_prover();
    let full_prover_locked = full_prover.lock().await;
    let (proof_json, _internal_metrics) = match full_prover_locked.as_ref() {
        Some(full_prover_locked) => match full_prover_locked.prove(witness_file_path) {
            Ok((proof_json, metrics)) => (proof_json.to_string(), metrics),
            Err(error) => {
                return Err(ProverServiceError::UnexpectedError(format!(
                    "Failed to generate rapidsnark proof! Error: {:?}",
                    error
                )));
            }
        },
        None => {
            return Err(ProverServiceError::UnexpectedError(
                "The full prover was not initialized correctly!".into(),
            ));
        }
    };

    // Update the proof generation metrics
    metrics::update_prove_request_breakdown_metrics(
        PROOF_GENERATION_LABEL,
        proof_generation_timer.elapsed(),
    );

    // Deserialize the JSON proof into a rapidsnark proof
    let proof_deserialization_timer = Instant::now();
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
    let groth16_proof = match types::encode_proof(&rapidsnark_proof_response) {
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
    let groth16_prepare_verifying_key = types::prepared_vk(&verification_key_file_path)?;

    // Update the proof deserialization metrics
    metrics::update_prove_request_breakdown_metrics(
        PROOF_DESERIALIZATION_LABEL,
        proof_deserialization_timer.elapsed(),
    );

    // Verify the proof. This is necessary to ensure that only valid proofs
    // are returned, and avoids certain classes of bugs and attacks (e.g.,
    // fault-based side-channels).
    let proof_verification_timer = Instant::now();
    groth16_proof.verify_proof(
        ark_bn254::Fr::from_le_bytes_mod_order(&public_inputs_hash),
        &groth16_prepare_verifying_key,
    )?;

    // Update the proof verification metrics
    metrics::update_prove_request_breakdown_metrics(
        PROOF_VERIFICATION_LABEL,
        proof_verification_timer.elapsed(),
    );

    Ok(groth16_proof)
}

/// Generates the witness file for the proof using the verified input
async fn generate_witness_file_for_proof(
    prover_service_state: &ProverServiceState,
    verified_input: VerifiedInput,
) -> Result<(NamedTempFile, PoseidonHash), ProverServiceError> {
    // Derive the circuit input signals from the verified input
    let circuit_input_signals_timer = Instant::now();
    let prover_service_config = prover_service_state.prover_service_config();
    let circuit_config = prover_service_state.circuit_config();
    let (circuit_input_signals, public_inputs_hash) =
        match input_signals::derive_circuit_input_signals(
            prover_service_config,
            circuit_config,
            verified_input,
        ) {
            Ok((input_signals, input_hash)) => (input_signals, input_hash),
            Err(error) => {
                return Err(ProverServiceError::UnexpectedError(format!(
                    "Failed to derive circuit input signals! Error: {}",
                    error
                )));
            }
        };

    // Update the metrics for deriving circuit input signals
    metrics::update_prove_request_breakdown_metrics(
        DERIVE_CIRCUIT_INPUT_SIGNALS_LABEL,
        circuit_input_signals_timer.elapsed(),
    );

    // Generate the witness file
    let witness_generation_timer = Instant::now();
    let prover_service_config = prover_service_state.prover_service_config();
    let generated_witness_file = match generate_witness_file_using_signal_inputs(
        prover_service_config,
        &circuit_input_signals,
    ) {
        Ok(witness_file) => witness_file,
        Err(error) => {
            return Err(ProverServiceError::UnexpectedError(format!(
                "Failed to generate witness file! Error: {}",
                error
            )));
        }
    };

    // Update the witness generation metrics
    metrics::update_prove_request_breakdown_metrics(
        WITNESS_GENERATION_LABEL,
        witness_generation_timer.elapsed(),
    );

    Ok((generated_witness_file, public_inputs_hash))
}

/// Signs the given groth16 proof with the training wheels signing key.
/// Note: we should've signed the VK too but, unfortunately, we realized this too late.
/// As a result, whenever the VK changes on-chain, the TW PK must change too.
/// Otherwise, an old proof computed for an old VK will pass the TW signature check,
/// even though this proof will not verify under the new VK.
fn sign_groth16_proof_with_tw_key(
    prover_service_state: &ProverServiceState,
    groth16_proof: Groth16Proof,
    public_inputs_hash: PoseidonHash,
) -> Result<Vec<u8>, ProverServiceError> {
    // Start the signature generation timer
    let signature_generation_timer = Instant::now();

    // Sign the proof using the training wheels signing key
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
            return Err(ProverServiceError::UnexpectedError(format!(
                "Failed to sign groth16 proof with training wheels key! Error: {}",
                error
            )));
        }
    };

    // Serialize the training wheels signature
    let ephemeral_signature = EphemeralSignature::ed25519(training_wheels_signature);
    let training_wheels_signature = match bcs::to_bytes(&ephemeral_signature) {
        Ok(signature_bytes) => signature_bytes,
        Err(error) => {
            return Err(ProverServiceError::UnexpectedError(format!(
                "Failed to serialize training wheels signature to bytes! Error: {}",
                error
            )));
        }
    };

    // Update the signature generation metrics
    metrics::update_prove_request_breakdown_metrics(
        PROOF_TW_SIGNATURE_LABEL,
        signature_generation_timer.elapsed(),
    );

    Ok(training_wheels_signature)
}

/// Validates the given prove request input
async fn validate_prove_request_input(
    prover_service_state: &ProverServiceState,
    prove_request_input: &RequestInput,
) -> Result<VerifiedInput, ProverServiceError> {
    // Start the validation timer
    let validation_timer = Instant::now();

    // Validate the prove request input
    let verified_input = match training_wheels::preprocess_and_validate_request(
        prover_service_state,
        prove_request_input,
        prover_service_state.jwk_cache(),
    )
    .await
    {
        Ok(verified_input) => verified_input,
        Err(error) => {
            return Err(ProverServiceError::BadRequest(format!(
                "Prove request input validation failed! Error: {}",
                error
            )));
        }
    };

    // Update the validation metrics
    metrics::update_prove_request_breakdown_metrics(
        VALIDATE_PROVE_REQUEST_LABEL,
        validation_timer.elapsed(),
    );

    Ok(verified_input)
}

/// Generates the witness file using the given prover config and circuit input signals
pub fn generate_witness_file_using_signal_inputs(
    prover_service_config: Arc<ProverServiceConfig>,
    circuit_input_signals: &CircuitInputSignals<Padded>,
) -> Result<NamedTempFile, ProverServiceError> {
    // Write the circuit input signals to a temporary file
    let circuit_input_signals_string =
        serde_json::to_string(&circuit_input_signals.to_json_value()).map_err(|error| {
            ProverServiceError::UnexpectedError(format!(
                "Failed to serialize circuit input signals to JSON! Error: {}",
                error
            ))
        })?;
    let input_file = utils::create_named_temp_file()?;
    fs::write(input_file.path(), circuit_input_signals_string.as_bytes()).map_err(|error| {
        ProverServiceError::UnexpectedError(format!(
            "Failed to write circuit input signals to temporary file! Error: {}",
            error
        ))
    })?;

    // Get the input and witness file paths
    let generated_witness_file = utils::create_named_temp_file()?;
    let input_file_path = utils::get_file_path_string(input_file.path())?;
    let generated_witness_file_path = utils::get_file_path_string(generated_witness_file.path())?;

    // Run the witness generation command
    let output = get_witness_generation_command(
        &prover_service_config,
        &input_file_path,
        &generated_witness_file_path,
    )
    .output()
    .map_err(|error| {
        ProverServiceError::UnexpectedError(format!(
            "Failed to execute witness generation command! Error: {}",
            error
        ))
    })?;

    // Check if the command executed successfully
    if output.status.success() {
        Ok(generated_witness_file)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(ProverServiceError::UnexpectedError(format!(
            "Witness generation command failed! Error: {}",
            stderr
        )))
    }
}

// Returns the command to generate the witness file (non-x86_64 uses node + wasm)
#[cfg(not(target_arch = "x86_64"))]
fn get_witness_generation_command(
    config: &ProverServiceConfig,
    input_file_path: &str,
    witness_file_path: &str,
) -> Command {
    // Create the command to run the witness generator
    let mut command = Command::new("node");
    command.args(&[
        config.witness_gen_js_file_path(),
        config.witness_gen_wasm_file_path(),
        String::from(input_file_path),
        String::from(witness_file_path),
    ]);

    command
}

// Returns the command to generate the witness file (x86_64 uses the native binary)
#[cfg(target_arch = "x86_64")]
fn get_witness_generation_command(
    config: &ProverServiceConfig,
    input_file_path: &str,
    witness_file_path: &str,
) -> Command {
    // Create the command to run the witness generator
    let mut command = Command::new(config.witness_gen_binary_file_path());
    command.args([input_file_path, witness_file_path]);

    command
}
