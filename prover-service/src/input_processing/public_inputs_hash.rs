// Copyright (c) Aptos Foundation

use super::field_check_input;
use crate::external_resources::prover_config::ProverServiceConfig;
use crate::request_handler::types::VerifiedInput;
use anyhow::{anyhow, Result};
use aptos_crypto::poseidon_bn254;
use aptos_keyless_common::input_processing::circuit_config::CircuitConfig;
use aptos_types::keyless::IdCommitment;
use ark_bn254::Fr;
use std::sync::Arc;

// Length of the ephemeral public key FRS (this is always expected to be 3)
const EPHEMERAL_PUBKEY_FRS_LEN: usize = 3;

/// Computes the identity commitment hash from the verified input
fn compute_idc_hash(
    circuit_config: &CircuitConfig,
    verified_input: &VerifiedInput,
    pepper_fr: Fr,
) -> Result<Fr> {
    // Add the pepper to the hash
    let mut frs: Vec<Fr> = Vec::new();
    frs.push(pepper_fr);

    // Add the aud to the hash
    let max_aud_bytes = get_max_bytes_from_config(circuit_config, "private_aud_value")?;
    let aud_hash_fr = poseidon_bn254::pad_and_hash_string(
        &field_check_input::private_aud_value(verified_input)?,
        max_aud_bytes,
    )?;
    frs.push(aud_hash_fr);

    // Add the uid val to the hash
    let max_uid_val_bytes = get_max_bytes_from_config(circuit_config, "uid_value")?;
    let uid_val_hash_fr =
        poseidon_bn254::pad_and_hash_string(&verified_input.uid_val, max_uid_val_bytes)?;
    frs.push(uid_val_hash_fr);

    // Add the uid key to the hash
    let max_uid_key_bytes = get_max_bytes_from_config(circuit_config, "uid_name")?;
    let uid_key_hash_fr =
        poseidon_bn254::pad_and_hash_string(&verified_input.uid_key, max_uid_key_bytes)?;
    frs.push(uid_key_hash_fr);

    // Compute and return the final hash
    poseidon_bn254::hash_scalars(frs)
}

/// Computes the ephemeral public key FRS and length from the verified input
pub fn compute_ephemeral_pubkey_frs(
    prover_service_config: Arc<ProverServiceConfig>,
    verified_input: &VerifiedInput,
) -> Result<([Fr; 3], Fr)> {
    let max_committed_epk_bytes = prover_service_config.max_committed_epk_bytes;
    let ephemeral_pubkey_frs_with_len =
        poseidon_bn254::keyless::pad_and_pack_bytes_to_scalars_with_len(
            verified_input.epk.to_bytes().as_slice(),
            max_committed_epk_bytes,
        )?;

    Ok((
        ephemeral_pubkey_frs_with_len[..EPHEMERAL_PUBKEY_FRS_LEN]
            .try_into()
            .unwrap_or_else(|error| {
                panic!(
                    "Length here should always be {}. Error: {:?}",
                    EPHEMERAL_PUBKEY_FRS_LEN, error
                )
            }),
        ephemeral_pubkey_frs_with_len[EPHEMERAL_PUBKEY_FRS_LEN],
    ))
}

/// Computes the public inputs hash from the verified input
pub fn compute_public_inputs_hash(
    prover_service_config: Arc<ProverServiceConfig>,
    circuit_config: &CircuitConfig,
    verified_input: &VerifiedInput,
) -> Result<Fr> {
    // Compute the ephemeral public key FRS and length
    let (temp_pubkey_frs, temp_pubkey_len) =
        compute_ephemeral_pubkey_frs(prover_service_config, verified_input)?;

    // Parse the extra field
    let extra_field = field_check_input::parsed_extra_field_or_default(verified_input)?;

    // Add the epk as padded and packed scalars
    let mut frs = Vec::from(temp_pubkey_frs);
    frs.push(temp_pubkey_len);

    // Add the id_commitment as a scalar
    let addr_idc_fr = compute_idc_hash(circuit_config, verified_input, verified_input.pepper_fr)?;
    frs.push(addr_idc_fr);

    // Add the exp_timestamp_secs as a scalar
    frs.push(Fr::from(verified_input.exp_date_secs));

    // Add the epk lifespan as a scalar
    frs.push(Fr::from(verified_input.exp_horizon_secs));

    // Add the iss value hash
    let max_iss_bytes = get_max_bytes_from_config(circuit_config, "iss_value")?;
    let iss_val_hash =
        poseidon_bn254::pad_and_hash_string(&verified_input.jwt.payload.iss, max_iss_bytes)?;
    frs.push(iss_val_hash);

    // Add the extra field info
    let use_extra_field_fr = Fr::from(verified_input.use_extra_field() as u64);
    frs.push(use_extra_field_fr);

    // Add the extra field hash
    let max_extra_field_bytes = get_max_bytes_from_config(circuit_config, "extra_field")?;
    let extra_field_hash =
        poseidon_bn254::pad_and_hash_string(&extra_field.whole_field, max_extra_field_bytes)?;
    frs.push(extra_field_hash);

    // Add the hash of the jwt_header with the "." separator appended
    let jwt_header_str = verified_input.jwt_parts.header_undecoded_with_dot();
    let jwt_header_hash = poseidon_bn254::pad_and_hash_string(
        &jwt_header_str,
        circuit_config.max_lengths["b64u_jwt_header_w_dot"],
    )?;
    frs.push(jwt_header_hash);

    // Add the public key hash
    let pubkey_hash_fr = verified_input.jwk.to_poseidon_scalar()?;
    frs.push(pubkey_hash_fr);

    // Add the override aud value hash
    let override_aud_val_hashed = poseidon_bn254::pad_and_hash_string(
        &field_check_input::override_aud_value(verified_input),
        IdCommitment::MAX_AUD_VAL_BYTES,
    )?;
    frs.push(override_aud_val_hashed);

    // Add the use override aud flag
    let use_override_aud = if verified_input.idc_aud.is_some() {
        ark_bn254::Fr::from(1)
    } else {
        ark_bn254::Fr::from(0)
    };
    frs.push(use_override_aud);

    // Compute and return the final hash
    let result = poseidon_bn254::hash_scalars(frs)?;
    Ok(result)
}

/// Retrieves the maximum byte length for a given key from the circuit config
fn get_max_bytes_from_config(circuit_config: &CircuitConfig, key: &str) -> Result<usize> {
    let max_lengths = &circuit_config.max_lengths;
    let max_bytes = max_lengths
        .get(key)
        .ok_or_else(|| anyhow!("Can't find key {} in circuit config", key))?;
    Ok(*max_bytes)
}

#[cfg(test)]
mod tests {
    use super::compute_public_inputs_hash;
    use crate::external_resources::prover_config::ProverServiceConfig;
    use crate::request_handler::types::VerifiedInput;
    use aptos_crypto::{
        ed25519::{Ed25519PrivateKey, Ed25519PublicKey},
        encoding_type::EncodingType,
    };
    use aptos_keyless_common::input_processing::encoding::DecodedJWT;
    use aptos_keyless_common::input_processing::{
        circuit_config::CircuitConfig,
        encoding::{FromB64, JwtParts},
    };
    use aptos_types::{jwks::rsa::RSA_JWK, transaction::authenticator::EphemeralPublicKey};
    use ark_bn254::Fr;
    use std::{fs, str::FromStr, sync::Arc};

    #[test]
    fn test_hashing() {
        // Create the RSA JWK
        let pk_mod_str: &'static str =      "6S7asUuzq5Q_3U9rbs-PkDVIdjgmtgWreG5qWPsC9xXZKiMV1AiV9LXyqQsAYpCqEDM3XbfmZqGb48yLhb_XqZaKgSYaC_h2DjM7lgrIQAp9902Rr8fUmLN2ivr5tnLxUUOnMOc2SQtr9dgzTONYW5Zu3PwyvAWk5D6ueIUhLtYzpcB-etoNdL3Ir2746KIy_VUsDwAM7dhrqSK8U2xFCGlau4ikOTtvzDownAMHMrfE7q1B6WZQDAQlBmxRQsyKln5DIsKv6xauNsHRgBAKctUxZG8M4QJIx3S6Aughd3RZC4Ca5Ae9fd8L8mlNYBCrQhOZ7dS0f4at4arlLcajtw";
        let pk_kid_str: &'static str = "test-rsa";
        let jwk = RSA_JWK::new_256_aqab(pk_kid_str, pk_mod_str);

        // Create the JWT
        let jwt_b64 = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3RfandrIiwidHlwIjoiSldUIn0.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI0MDc0MDg3MTgxOTIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI0MDc0MDg3MTgxOTIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTM5OTAzMDcwODI4OTk3MTg3NzUiLCJoZCI6ImFwdG9zbGFicy5jb20iLCJlbWFpbCI6Im1pY2hhZWxAYXB0b3NsYWJzLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJhdF9oYXNoIjoiYnhJRVN1STU5SW9aYjVhbENBU3FCZyIsIm5hbWUiOiJNaWNoYWVsIFN0cmFrYSIsInBpY3R1cmUiOiJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vYS9BQ2c4b2NKdlk0a1ZVQlJ0THhlMUlxS1dMNWk3dEJESnpGcDlZdVdWWE16d1BwYnM9czk2LWMiLCJnaXZlbl9uYW1lIjoiTWljaGFlbCIsImZhbWlseV9uYW1lIjoiU3RyYWthIiwibG9jYWxlIjoiZW4iLCJpYXQiOjE3MDAyNTU5NDQsImV4cCI6MjcwMDI1OTU0NCwibm9uY2UiOiI5Mzc5OTY2MjUyMjQ4MzE1NTY1NTA5NzkwNjEzNDM5OTAyMDA1MTU4ODcxODE1NzA4ODczNjMyNDMxNjk4MTkzNDIxNzk1MDMzNDk4In0.Ejdu3RLnqe0qyS4qJrT7z58HwQISbHoqG1bNcM2JvQDF9h-SAm4X9R6oGfD_wSD8dvs9vaLbZCUhOB8pL-bmXXF25ZkDk1-PU1lWDnuZ77cYQKOrT259LdfPtscdn2DBClfQ5Faepzq-OdPZcfbNegpdclZyIn_jT_EJgO8BTRLP5QHpcPe5f9EsgP7ISw2UNIEB6mDn0hqVnB6MvAPmmYEY6VGgwqwKs1ntih8TEnL3bfJ3511MwhYJvnpAQ1l-c_htAGaVm98tC-rWD5QQKGAf1ONXG3_Rfq6JsTdBBq_p_3zxNUbD2WiEOSBRptZDNcGCbtI2SuPCY5o00NE6aQ";

        // Create the ephemeral private and public keys
        let ed25519_private_key: Ed25519PrivateKey = EncodingType::Hex
            .decode_key(
                "test ephemeral private key",
                "0x76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7"
                    .as_bytes()
                    .to_vec(),
            )
            .unwrap();
        let ed25519_public_key: Ed25519PublicKey = Ed25519PublicKey::from(&ed25519_private_key);
        let ephemeral_public_key = EphemeralPublicKey::ed25519(ed25519_public_key);

        // Create the verified input from the above components
        let jwt = DecodedJWT::from_b64(jwt_b64).unwrap();
        let uid_val = jwt.payload.sub.clone().unwrap();
        let input = VerifiedInput {
            jwt,
            jwt_parts: JwtParts::from_b64(jwt_b64).unwrap(),
            jwk: Arc::new(jwk),
            epk: ephemeral_public_key,
            epk_blinder_fr: Fr::from_str("42").unwrap(),
            exp_date_secs: 1900255944,
            exp_horizon_secs: 100255944,
            pepper_fr: Fr::from_str("76").unwrap(),
            uid_key: String::from("sub"),
            uid_val,
            extra_field: Some(String::from("family_name")),
            idc_aud: None,
            skip_aud_checks: false,
        };

        // Load the prover service config and circuit config
        let prover_service_config = Arc::new(ProverServiceConfig::default());
        let config: CircuitConfig = serde_yaml::from_str(
            &fs::read_to_string("circuit_config.yml").expect("Unable to read file"),
        )
        .expect("should parse correctly");

        // Compute the public inputs hash
        let public_inputs_hash =
            compute_public_inputs_hash(prover_service_config, &config, &input).unwrap();

        // Verify the public inputs hash
        assert_eq!(
            public_inputs_hash.to_string(),
            "18884813797014402005012488165063359209340898803829594097564044767682806702965"
        );
    }
}
