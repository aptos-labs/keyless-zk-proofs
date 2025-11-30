// Copyright (c) Aptos Foundation

use crate::error::ProverServiceError;
use crate::external_resources::jwk_fetcher;
use crate::external_resources::jwk_fetcher::get_federated_jwk;
use crate::external_resources::jwk_types::{FederatedJWKIssuer, FederatedJWKs, JWKCache};
use crate::external_resources::prover_config::ProverServiceConfig;
use crate::request_handler::prover_state::ProverServiceState;
use crate::request_handler::types::{ProverServiceResponse, RequestInput, VerifiedInput};
use anyhow::{anyhow, bail, ensure};
use aptos_crypto::{
    ed25519::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature},
    poseidon_bn254, CryptoMaterialError, SigningKey,
};
use aptos_keyless_common::input_processing::circuit_config::CircuitConfig;
use aptos_keyless_common::input_processing::encoding::AsFr;
use aptos_keyless_common::input_processing::jwt::DecodedJWT;
use aptos_keyless_common::types::PoseidonHash;
use aptos_types::jwks::rsa::RSA_JWK;
use aptos_types::keyless::Claims;
use aptos_types::{
    keyless::{Groth16Proof, Groth16ProofAndStatement},
    transaction::authenticator::{EphemeralPublicKey, EphemeralSignature},
};
use ark_bn254::Fr;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Computes the nonce scalar for the given inputs
pub fn compute_nonce(
    expiration_date: u64,
    ephemeral_public_key: &EphemeralPublicKey,
    epk_blinder: Fr,
    circuit_config: &CircuitConfig,
) -> anyhow::Result<Fr> {
    // Pack the ephemeral public key bytes, expiration date, and blinder into scalars
    let max_length_epk = circuit_config.get_max_length("epk")?;
    let mut frs = poseidon_bn254::keyless::pad_and_pack_bytes_to_scalars_with_len(
        ephemeral_public_key.to_bytes().as_slice(),
        max_length_epk * poseidon_bn254::keyless::BYTES_PACKED_PER_SCALAR,
    )?;
    frs.push(Fr::from(expiration_date));
    frs.push(epk_blinder);

    // Compute the nonce as the Poseidon hash of the packed scalars
    let nonce_fr = poseidon_bn254::hash_scalars(frs)?;
    Ok(nonce_fr)
}

/// Retrieves the JWK for the given JWT, either directly from the cache or from federated JWKs
async fn get_jwk(
    prover_service_config: &ProverServiceConfig,
    jwt: &DecodedJWT,
    jwk_cache: JWKCache,
    federated_jwks: FederatedJWKs<FederatedJWKIssuer>,
) -> anyhow::Result<Arc<RSA_JWK>> {
    // Fetch the JWK from cache first
    let cached_jwk =
        jwk_fetcher::get_cached_jwk_as_rsa(&jwt.payload.iss, &jwt.header.kid, jwk_cache);
    if cached_jwk.is_ok() {
        return cached_jwk;
    }

    // Otherwise, fetch the JWK from the federated JWKs (if enabled)
    if prover_service_config.enable_federated_jwks {
        get_federated_jwk(jwt, federated_jwks).await
    } else {
        bail!(
            "JWK not found in cache, and federated JWKs are disabled! Iss: {}, Kid: {}",
            jwt.payload.iss,
            jwt.header.kid
        );
    }
}

/// Pre-processes and validates a prover service request under training-wheels mode.
/// All training-wheel checks go here, and if a request passes this successfully, we
/// should be convinced that the *public statement* to be proved is correct.
pub async fn preprocess_and_validate_request(
    prover_service_state: &ProverServiceState,
    request_input: &RequestInput,
    jwk_cache: JWKCache,
    federated_jwks: FederatedJWKs<FederatedJWKIssuer>,
) -> anyhow::Result<VerifiedInput> {
    // Get the decoded JWT and the JWK
    let jwt = DecodedJWT::from_b64(&request_input.jwt_b64)?;
    let jwk = get_jwk(
        &prover_service_state.prover_service_config(),
        &jwt,
        jwk_cache,
        federated_jwks,
    )
    .await?;

    // Validate the JWT signature.
    // Keyless relation condition 10 captured: https://github.com/aptos-foundation/AIPs/blob/f133e29d999adf31c4f41ce36ae1a808339af71e/aips/aip-108.md?plain=1#L95
    validate_jwt_signature(jwk.as_ref(), &request_input.jwt_b64)?;

    // Ensure the expiration date is within the allowed horizon.
    // Keyless relation condition 8 captured: https://github.com/aptos-foundation/AIPs/blob/f133e29d999adf31c4f41ce36ae1a808339af71e/aips/aip-108.md?plain=1#L92
    ensure!(
        (request_input.exp_date_secs as u128)
            < (jwt.payload.iat as u128) + (request_input.exp_horizon_secs as u128)
    );

    // Verify that iat is not in the future
    let now_unix_secs = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    ensure!(
        jwt.payload.iat <= now_unix_secs,
        "jwt which was issued in the future"
    );

    // Verify the computed nonce matches the one in the JWT.
    // Keyless relation condition 7 captured: https://github.com/aptos-foundation/AIPs/blob/f133e29d999adf31c4f41ce36ae1a808339af71e/aips/aip-108.md?plain=1#L90
    let computed_nonce = compute_nonce(
        request_input.exp_date_secs,
        &request_input.epk,
        request_input.epk_blinder.as_fr(),
        prover_service_state.circuit_config(),
    )?;
    ensure!(jwt.payload.nonce == computed_nonce.to_string());

    // Get the UID value from the JWT
    let uid_val = match request_input.uid_key.as_str() {
        "email" => {
            // Verify that the email is verified.
            // Keyless relation condition 3 captured: https://github.com/aptos-foundation/AIPs/blob/f133e29d999adf31c4f41ce36ae1a808339af71e/aips/aip-108.md?plain=1#L74
            ensure!(Some(true) == jwt.payload.email_verified);

            // Use the email
            jwt.payload
                .email
                .clone()
                .ok_or_else(|| anyhow!("Missing email in JWT payload!"))?
        }
        "sub" => {
            // Use the subject
            jwt.payload
                .sub
                .clone()
                .ok_or_else(|| anyhow!("Missing sub in JWT payload"))?
        }
        _ => bail!(
            "Unrecognized uid_key in request input: {}",
            request_input.uid_key
        ),
    };

    // Return the verified input
    VerifiedInput::new(request_input, jwk, jwt, uid_val)
}

/// Signs the given Groth16 proof and public inputs hash using the provided private key
pub fn sign(
    private_key: &Ed25519PrivateKey,
    proof: Groth16Proof,
    public_inputs_hash: PoseidonHash,
) -> Result<Ed25519Signature, CryptoMaterialError> {
    // Create the message to sign
    let message_to_sign: Groth16ProofAndStatement = Groth16ProofAndStatement {
        proof,
        public_inputs_hash,
    };

    // Sign and return the signature
    private_key.sign(&message_to_sign)
}

/// Validates the signature of the given JWT using the provided JWK
pub fn validate_jwt_signature(jwk: &RSA_JWK, jwt: &str) -> anyhow::Result<()> {
    let validation = Validation::new(Algorithm::RS256);
    let decoding_key = &DecodingKey::from_rsa_components(&jwk.n, &jwk.e)?;
    let _claims = jsonwebtoken::decode::<Claims>(jwt, decoding_key, &validation)?;

    Ok(())
}

/// Verifies the signature in the given prover service response (using the provided public key)
pub fn verify(
    prover_service_response: &ProverServiceResponse,
    public_key: &Ed25519PublicKey,
) -> Result<(), ProverServiceError> {
    match prover_service_response {
        ProverServiceResponse::Success {
            proof,
            public_inputs_hash,
            training_wheels_signature,
        } => {
            // Get the ephemeral signature to check
            let ephemeral_signature = EphemeralSignature::try_from(
                training_wheels_signature.as_slice(),
            )
            .map_err(|error| {
                ProverServiceError::UnexpectedError(format!(
                    "Failed to parse ephemeral signature from bytes: {}",
                    error
                ))
            })?;

            // Verify the ephemeral signature
            ephemeral_signature
                .verify(
                    &Groth16ProofAndStatement {
                        proof: *proof,
                        public_inputs_hash: *public_inputs_hash,
                    },
                    &EphemeralPublicKey::ed25519(public_key.clone()),
                )
                .map_err(|error| {
                    ProverServiceError::BadRequest(format!(
                        "Failed to verify ephemeral signature: {}",
                        error
                    ))
                })
        }
        ProverServiceResponse::Error { message } => Err(ProverServiceError::UnexpectedError(
            format!("Cannot verify an error response! Error: {}!", message),
        )),
    }
}
