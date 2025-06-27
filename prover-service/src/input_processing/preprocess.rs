// Copyright © Aptos Foundation

use super::{types::Input, JwtHeader, JwtPayload};
use crate::{api::RequestInput, jwk_fetching};
use anyhow::Context;
use aptos_keyless_common::input_processing::encoding::{AsFr as _, FromB64 as _, JwtParts};
use aptos_keyless_common::logging;
use aptos_types::jwks::rsa::RSA_JWK;
use std::sync::Arc;

pub fn decode_and_add_jwk(
    rqi: RequestInput,
    maybe_jwk: Option<&RSA_JWK>,
) -> Result<Input, anyhow::Error> {
    let jwt_parts = JwtParts::from_b64(&rqi.jwt_b64)?;

    let header_decoded = jwt_parts.header_decoded()?;
    let header_struct: JwtHeader = serde_json::from_str(&header_decoded)?;

    let payload_decoded = jwt_parts.payload_decoded()?;
    let payload_struct: JwtPayload = serde_json::from_str(&payload_decoded)?;

    logging::info(format!("header decoded: {:?}", header_decoded));
    logging::info(format!("payload decoded: {}", payload_decoded));

    let jwk = match maybe_jwk {
        Some(x) => Arc::new(x.clone()),
        None => jwk_fetching::cached_decoding_key(&payload_struct.iss, &header_struct.kid)
            .context("Request has a JWT with an unrecognized JWK")?,
    };

    Ok(Input {
        jwt_parts,
        jwk,
        epk: rqi.epk,
        epk_blinder_fr: rqi.epk_blinder.as_fr(),
        exp_date_secs: rqi.exp_date_secs,
        pepper_fr: rqi.pepper.as_fr(),
        uid_key: rqi.uid_key,
        extra_field: rqi.extra_field,
        exp_horizon_secs: rqi.exp_horizon_secs,
        idc_aud: rqi.idc_aud,
        skip_aud_checks: rqi.skip_aud_checks,
    })
}
