use crate::error::ErrorWithCode;
use crate::handlers::encode_proof;
use crate::load_vk::prepared_vk;
use crate::state::ProverServiceState;
use crate::witness_gen::PathStr;
use crate::{error, metrics};
use anyhow::Result;
use aptos_keyless_common::logging::HasLoggableError;
use aptos_keyless_common::{logging, PoseidonHash};
use aptos_types::keyless::Groth16Proof;
use ark_ff::PrimeField;
use tempfile::NamedTempFile;

pub async fn prove(
    state: &ProverServiceState,
    witness_file: NamedTempFile,
    public_inputs_hash: PoseidonHash,
) -> Result<Groth16Proof, ErrorWithCode> {
    let _span = logging::new_span("GenerateProofWithRetry");
    let prover_unlocked = state.full_prover.lock().await;
    let witness_file_path = witness_file.path_str().log_err()?;
    let (proof_json, internal_metrics) = prover_unlocked
        .prove(witness_file_path)
        .map_err(error::handle_prover_lib_error)
        .log_err()?;
    metrics::GROTH16_TIME_SECS.observe((f64::from(internal_metrics.prover_time)) / 1000.0);

    let rapidsnark_proof = serde_json::from_str(proof_json).map_err(anyhow::Error::from)?;
    let proof = encode_proof(&rapidsnark_proof)?;

    let g16vk = {
        let _span = logging::new_span("PrepareVK");
        prepared_vk(&state.config.verification_key_path())
    };

    proof.verify_proof(
        ark_bn254::Fr::from_le_bytes_mod_order(&public_inputs_hash),
        &g16vk,
    )?;

    Ok(proof)
}
