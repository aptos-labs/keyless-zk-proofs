// Copyright (c) Aptos Foundation

use crate::error::ProverServiceError;
use crate::utils;
use aptos_crypto_derive::{BCSCryptoHash, CryptoHasher};
use aptos_keyless_common::input_processing::encoding::{AsFr, FromB64};
use aptos_keyless_common::input_processing::jwt::{DecodedJWT, JwtParts};
use aptos_keyless_common::types::PoseidonHash;
use aptos_types::jwks::rsa::RSA_JWK;
use aptos_types::keyless::{
    g1_projective_str_to_affine, g2_projective_str_to_affine, G1Bytes, G2Bytes, Groth16Proof,
    Pepper,
};
use aptos_types::transaction::authenticator::EphemeralPublicKey;
use ark_bn254::{Bn254, Fr};
use ark_groth16::{PreparedVerifyingKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

// A simple type alias for the blinder used in ephemeral public keys
pub type EphemeralPublicKeyBlinder = Vec<u8>;

/// The input request structure for prove requests
#[derive(Debug, Serialize, Deserialize, BCSCryptoHash, CryptoHasher)]
pub struct RequestInput {
    pub jwt_b64: String,
    pub epk: EphemeralPublicKey,
    #[serde(with = "hex")]
    pub epk_blinder: EphemeralPublicKeyBlinder,
    pub exp_date_secs: u64,
    pub exp_horizon_secs: u64,
    pub pepper: Pepper,
    pub uid_key: String,
    pub extra_field: Option<String>,
    pub idc_aud: Option<String>,
    #[serde(default)]
    pub use_insecure_test_jwk: bool,
    #[serde(default)]
    pub skip_aud_checks: bool,
}

/// The response structure for prover service responses
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum ProverServiceResponse {
    Success {
        proof: Groth16Proof,
        #[serde(with = "hex")]
        public_inputs_hash: PoseidonHash,
        #[serde(with = "hex")]
        training_wheels_signature: Vec<u8>,
    },
    Error {
        message: String,
    },
}

/// A prover request that has passed training wheel checks and been pre-processed.
/// Output of prover request handling step `preprocess_and_validate_request()`.
/// Input of prover request handling step `derive_circuit_input_signals()`.
///
/// TODO: avoid storing derived data like `uid_val` and ensure only `preprocess_and_validate_request` can construct it?
#[derive(Debug)]
pub struct VerifiedInput {
    pub jwt: DecodedJWT,
    pub jwt_parts: JwtParts,
    pub jwk: Arc<RSA_JWK>,
    pub epk: EphemeralPublicKey,
    pub epk_blinder_fr: Fr,
    pub exp_date_secs: u64,
    pub pepper_fr: Fr,
    pub uid_key: String,
    pub uid_val: String,
    pub extra_field: Option<String>,
    pub exp_horizon_secs: u64,
    pub idc_aud: Option<String>,
    pub skip_aud_checks: bool,
}

impl VerifiedInput {
    pub fn new(
        rqi: &RequestInput,
        jwk: Arc<RSA_JWK>,
        jwt: DecodedJWT,
        uid_val: String,
    ) -> anyhow::Result<Self> {
        let jwt_parts = JwtParts::from_b64(&rqi.jwt_b64)?;
        Ok(Self {
            jwt,
            jwt_parts,
            jwk,
            epk: rqi.epk.clone(),
            epk_blinder_fr: rqi.epk_blinder.as_fr(),
            exp_date_secs: rqi.exp_date_secs,
            pepper_fr: rqi.pepper.as_fr(),
            uid_key: rqi.uid_key.clone(),
            uid_val,
            extra_field: rqi.extra_field.clone(),
            exp_horizon_secs: rqi.exp_horizon_secs,
            idc_aud: rqi.idc_aud.clone(),
            skip_aud_checks: rqi.skip_aud_checks,
        })
    }

    pub fn use_extra_field(&self) -> bool {
        self.extra_field.is_some()
    }
}

/// A raw VK as outputted by circom in YAML format
#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
pub struct RawVK {
    vk_alpha_1: Vec<String>,
    vk_beta_2: Vec<Vec<String>>,
    vk_gamma_2: Vec<Vec<String>>,
    vk_delta_2: Vec<Vec<String>>,
    IC: Vec<Vec<String>>,
}

/// A rapidsnark proof response
#[derive(Deserialize)]
pub struct RapidsnarkProofResponse {
    pi_a: [String; 3],
    pi_b: [[String; 2]; 3],
    pi_c: [String; 3],
}

impl RapidsnarkProofResponse {
    pub fn pi_b_str(&self) -> [[&str; 2]; 3] {
        [
            [&self.pi_b[0][0], &self.pi_b[0][1]],
            [&self.pi_b[1][0], &self.pi_b[1][1]],
            [&self.pi_b[2][0], &self.pi_b[2][1]],
        ]
    }
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

/// Encodes a Rapidsnark proof response into a Groth16 proof
pub fn encode_proof(
    rapidsnark_proof_response: &RapidsnarkProofResponse,
) -> Result<Groth16Proof, ProverServiceError> {
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
