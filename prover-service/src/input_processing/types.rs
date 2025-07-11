// Copyright © Aptos Foundation

use aptos_keyless_common::input_processing::encoding::{AsFr, DecodedJWT, FromB64, JwtParts};

use crate::api::RequestInput;
use anyhow::Result;
use aptos_types::{jwks::rsa::RSA_JWK, transaction::authenticator::EphemeralPublicKey};
use ark_bn254::Fr;
use std::sync::Arc;

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
    ) -> Result<Self> {
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
