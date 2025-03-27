use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use aptos_crypto::poseidon_bn254;
use aptos_types::{
    jwks::rsa::RSA_JWK, keyless::Claims, transaction::authenticator::EphemeralPublicKey,
};
use ark_bn254::Fr;
use http::StatusCode;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use keyless_common::input_processing::{
    config::CircuitConfig,
    encoding::{FromB64, JwtHeader, JwtParts, JwtPayload},
};

use crate::{
    api::RequestInput,
    config::ProverServiceConfig,
    error::{ErrorWithCode, ThrowCodeOnError},
    input_processing::{field_parser::FieldParser, types::Input},
    jwk_fetching,
};
use anyhow::{bail, Context, Result};

pub fn check_nonce_consistency(input: &Input, circuit_config: &CircuitConfig) -> Result<()> {
    let payload_decoded = input.jwt_parts.payload_decoded()?;
    let payload_struct: JwtPayload = serde_json::from_str(&payload_decoded)?;
    let computed_nonce = compute_nonce(
        input.exp_date_secs,
        &input.epk,
        input.epk_blinder_fr,
        circuit_config,
    )?;

    if computed_nonce.to_string() == payload_struct.nonce {
        Ok(())
    } else {
        bail!("Nonce in JWT is inconsistent with epk, epk_blinder, or expiration date")
    }
}

pub fn validate_jwt_sig_and_dates(
    rqi: &RequestInput,
    maybe_jwk: Option<&RSA_JWK>,
    config: &ProverServiceConfig,
) -> Result<(), ErrorWithCode> {
    let jwt_parts = JwtParts::from_b64(&rqi.jwt_b64)?;

    let header_decoded = jwt_parts.header_decoded()?;
    let header_struct: JwtHeader = serde_json::from_str(&header_decoded)?;

    let payload_decoded = jwt_parts.payload_decoded()?;
    let payload_struct: JwtPayload = serde_json::from_str(&payload_decoded)?;

    let jwk = match maybe_jwk {
        Some(x) => Arc::new(x.clone()),
        None => jwk_fetching::cached_decoding_key(&payload_struct.iss, &header_struct.kid)
            .context(format!(
                "Request has a JWT with an unrecognized JWK: {}",
                payload_struct.iss
            ))?,
    };

    // Check the signature verifies.
    let mut validation = Validation::new(Algorithm::RS256);
    if !config.enable_jwt_exp_not_in_the_past_check {
        validation.validate_exp = false;
    }
    let key = &DecodingKey::from_rsa_components(&jwk.n, &jwk.e)?;

    let _claims = jsonwebtoken::decode::<Claims>(&rqi.jwt_b64, key, &validation)?;

    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .map_err(anyhow::Error::from)
        .context("Went back in time")
        .with_status(StatusCode::INTERNAL_SERVER_ERROR)?;

    if config.enable_jwt_iat_not_in_future_check && payload_struct.iat > since_the_epoch.as_secs() {
        crate::bail!("Submitted a request jwt which was issued in the future")
    } else {
        Ok(())
    }
}

pub fn validate_jwt_payload_parsing(input: &Input) -> Result<(), ErrorWithCode> {
    let payload_decoded = input.jwt_parts.payload_decoded()?;
    let payload_struct: JwtPayload = serde_json::from_str(&payload_decoded)?;
    let uid_key = &input.uid_key;

    let parsed_uid = FieldParser::find_and_parse_field(&payload_decoded, uid_key)?;

    match uid_key.as_str() {
        "email" => {
            if Some(parsed_uid.value) != payload_struct.email {
                crate::bail!("Circuit is parsing the \"email\" field incorrectly")
            }
        }
        "sub" => {
            if Some(parsed_uid.value) != payload_struct.sub {
                crate::bail!("Circuit is parsing the \"sub\" field incorrectly")
            }
        }
        _ => {
            crate::bail!("unrecognized uid key")
        }
    }

    let parsed_aud = FieldParser::find_and_parse_field(&payload_decoded, "aud")?;
    if Some(parsed_aud.value) != payload_struct.aud {
        crate::bail!("Circuit is parsing the \"aud\" field incorrectly")
    }

    Ok(())
}

pub fn compute_nonce(
    exp_date: u64,
    epk: &EphemeralPublicKey,
    epk_blinder: Fr,
    config: &CircuitConfig,
) -> Result<Fr> {
    let mut frs = poseidon_bn254::keyless::pad_and_pack_bytes_to_scalars_with_len(
        epk.to_bytes().as_slice(),
        config.max_lengths["temp_pubkey"] * poseidon_bn254::keyless::BYTES_PACKED_PER_SCALAR,
    )?;

    frs.push(Fr::from(exp_date));
    frs.push(epk_blinder);

    let nonce_fr = poseidon_bn254::hash_scalars(frs)?;
    Ok(nonce_fr)
}
