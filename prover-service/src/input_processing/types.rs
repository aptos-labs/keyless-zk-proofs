// Copyright © Aptos Foundation

use keyless_common::input_processing::encoding::JwtParts;

use aptos_types::{jwks::rsa::RSA_JWK, transaction::authenticator::EphemeralPublicKey};
use ark_bn254::Fr;
use std::sync::Arc;

#[derive(Debug)]
pub struct Input {
    pub jwt_parts: JwtParts,
    pub jwk: Arc<RSA_JWK>,
    pub epk: EphemeralPublicKey,
    pub epk_blinder_fr: Fr,
    pub exp_date_secs: u64,
    pub pepper_fr: Fr,
    pub uid_key: String,
    pub extra_field: Option<String>,
    pub exp_horizon_secs: u64,
    pub idc_aud: Option<String>,
    pub skip_aud_checks: bool,
}

impl Input {
    pub fn use_extra_field(&self) -> bool {
        self.extra_field.is_some()
    }
}
