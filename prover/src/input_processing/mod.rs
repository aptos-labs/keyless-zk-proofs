// Copyright © Aptos Foundation

pub mod config;
pub mod encoding;
pub mod field_check_input;
pub mod field_parser;
pub mod preprocess;
pub mod public_inputs_hash;
pub mod rsa;
pub mod sha;
pub mod types;

use aptos_keyless_common::input_processing::circuit_input_signals::{CircuitInputSignals, Padded};
use aptos_keyless_common::input_processing::config::CircuitPaddingConfig;
use self::{
    field_check_input::field_check_input_signals,
    public_inputs_hash::compute_public_inputs_hash,
};
use crate::{
    api::PoseidonHash,
    input_processing::{encoding::*, types::Input},
};
use anyhow::Result;
use ark_bn254::Fr;
use ark_ff::PrimeField;
use sha::{compute_sha_padding_without_len, jwt_bit_len_binary, with_sha_padding_bytes};
use std::time::Instant;
use tracing::info_span;

// TODO this works when I have it here, but doesn't when I move it to encoding.rs. Why?
impl FromHex for Fr {
    fn from_hex(s: &str) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(Fr::from_le_bytes_mod_order(&hex::decode(s)?))
    }
}

pub fn derive_circuit_input_signals(
    input: Input,
    config: &CircuitPaddingConfig,
) -> Result<(CircuitInputSignals<Padded>, PoseidonHash), anyhow::Error> {
    // TODO add metrics instead of just printing out elapsed time
    let _start_time = Instant::now();
    let _span = info_span!("Deriving circuit input signals");

    let jwt_parts = &input.jwt_parts;
    let epk_blinder_fr = input.epk_blinder_fr;
    let unsigned_jwt_with_padding = with_sha_padding_bytes(&input.jwt_parts.unsigned_undecoded());
    let signature = jwt_parts.signature()?;
    let (temp_pubkey_frs, temp_pubkey_len) = public_inputs_hash::compute_temp_pubkey_frs(&input)?;
    let public_inputs_hash = compute_public_inputs_hash(&input, config)?;

    let circuit_input_signals = CircuitInputSignals::new()
        // "global" inputs
        .bytes_input("jwt", &unsigned_jwt_with_padding)
        .str_input(
            "jwt_header_with_separator",
            &jwt_parts.header_undecoded_with_dot(),
        )
        .bytes_input(
            "jwt_payload",
            &UnsignedJwtPartsWithPadding::from_b64_bytes_with_padding(&unsigned_jwt_with_padding)
                .payload_with_padding()?,
        )
        .str_input(
            "jwt_payload_without_sha_padding",
            &jwt_parts.payload_undecoded(),
        )
        .usize_input(
            "header_len_with_separator",
            jwt_parts.header_undecoded_with_dot().len(),
        )
        .usize_input("b64_payload_len", jwt_parts.payload_undecoded().len())
        .usize_input(
            "jwt_num_sha2_blocks",
            unsigned_jwt_with_padding.len() * 8 / 512,
        )
        .bytes_input(
            "jwt_len_bit_encoded",
            &jwt_bit_len_binary(&jwt_parts.unsigned_undecoded()).as_bytes()?,
        )
        .bytes_input(
            "padding_without_len",
            &compute_sha_padding_without_len(&jwt_parts.unsigned_undecoded()).as_bytes()?,
        )
        .limbs_input("signature", &signature.as_64bit_limbs())
        .limbs_input("pubkey_modulus", &input.jwk.as_64bit_limbs())
        .u64_input("exp_date", input.exp_date_secs)
        .u64_input("exp_delta", input.exp_horizon_secs)
        .frs_input("temp_pubkey", &temp_pubkey_frs)
        .fr_input("temp_pubkey_len", temp_pubkey_len)
        .fr_input("jwt_randomness", epk_blinder_fr)
        .fr_input("pepper", input.pepper_fr)
        .bool_input("use_extra_field", input.use_extra_field())
        .fr_input("public_inputs_hash", public_inputs_hash)
        .merge(field_check_input_signals(&input)?)?
        // add padding for global inputs
        .pad(config)?;
    // "field check" input signals

    Ok((
        circuit_input_signals,
        PoseidonHash::try_from_fr(&public_inputs_hash)?,
    ))
}

#[cfg(test)]
mod tests {

    use aptos_crypto::{
        ed25519::{Ed25519PrivateKey, Ed25519PublicKey},
        encoding_type::EncodingType,
        poseidon_bn254,
    };

    use aptos_types::keyless::Configuration;
    use aptos_types::transaction::authenticator::EphemeralPublicKey;
    use std::str::FromStr;

    #[test]
    fn test_epk_packing() {
        let ephemeral_private_key: Ed25519PrivateKey = EncodingType::Hex
            .decode_key(
                "zkid test ephemeral private key",
                "0x76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7"
                    .as_bytes()
                    .to_vec(),
            )
            .unwrap();
        let epk_unwrapped = Ed25519PublicKey::from(&ephemeral_private_key);
        println!("{}", epk_unwrapped);
        let ephemeral_public_key: EphemeralPublicKey = EphemeralPublicKey::ed25519(epk_unwrapped);

        let temp_pubkey_frs_with_len =
            poseidon_bn254::keyless::pad_and_pack_bytes_to_scalars_with_len(
                ephemeral_public_key.to_bytes().as_slice(),
                Configuration::new_for_testing().max_commited_epk_bytes as usize, // TODO should use my own thing here
            )
            .unwrap();

        let temp_pubkey_frs = &temp_pubkey_frs_with_len[0..3];

        let temp_pubkey_0 =
            "242984842061174104272170180221318235913385474778206477109637294427650138112";
        let temp_pubkey_1 = "4497911";
        let temp_pubkey_2 = "0";
        let _temp_pubkey_len = "34";

        println!(
            "pubkey frs: {} {} {}",
            temp_pubkey_frs[0], temp_pubkey_frs[1], temp_pubkey_frs[2]
        );
        assert_eq!(
            temp_pubkey_frs[0],
            ark_bn254::Fr::from_str(temp_pubkey_0).unwrap()
        );
        assert_eq!(
            temp_pubkey_frs[1],
            ark_bn254::Fr::from_str(temp_pubkey_1).unwrap()
        );
        assert_eq!(
            temp_pubkey_frs[2],
            ark_bn254::Fr::from_str(temp_pubkey_2).unwrap()
        );
    }
}
