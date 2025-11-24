// Copyright (c) Aptos Foundation

use crate::external_resources::prover_config::ProverServiceConfig;
use crate::input_processing::field_check_input::field_check_input_signals;
use crate::input_processing::public_inputs_hash;
use crate::input_processing::public_inputs_hash::compute_public_inputs_hash;
use crate::input_processing::types::VerifiedInput;
use aptos_keyless_common::input_processing::circuit_input_signals::{CircuitInputSignals, Padded};
use aptos_keyless_common::input_processing::config::CircuitConfig;
use aptos_keyless_common::input_processing::encoding::{
    As64BitLimbs, TryFromFr, UnsignedJwtPartsWithPadding,
};
use aptos_keyless_common::input_processing::sha::{
    compute_sha_padding_without_len, jwt_bit_len_binary, with_sha_padding_bytes,
};
use aptos_keyless_common::PoseidonHash;
use std::sync::Arc;

/// Derives the circuit input signals and public inputs hash from the verified input
pub fn derive_circuit_input_signals(
    prover_service_config: Arc<ProverServiceConfig>,
    circuit_config: &CircuitConfig,
    verified_input: VerifiedInput,
) -> Result<(CircuitInputSignals<Padded>, PoseidonHash), anyhow::Error> {
    // Compute the ephemeral pubkey FRS and length
    let (ephemeral_pubkey_frs, ephemeral_pubkey_len) =
        public_inputs_hash::compute_ephemeral_pubkey_frs(
            prover_service_config.clone(),
            &verified_input,
        )?;

    // Compute the public inputs hash
    let public_inputs_hash =
        compute_public_inputs_hash(prover_service_config, circuit_config, &verified_input)?;

    // Get the unsigned JWT with SHA padding
    let unsigned_jwt_with_padding =
        with_sha_padding_bytes(verified_input.jwt_parts.unsigned_undecoded().as_bytes());

    // Derive the circuit input signals
    let jwt_parts = &verified_input.jwt_parts;
    let mut circuit_input_signals = CircuitInputSignals::new()
        // "global" inputs
        .bytes_input("b64u_jwt_no_sig_sha2_padded", &unsigned_jwt_with_padding)
        .str_input(
            "b64u_jwt_header_w_dot",
            &jwt_parts.header_undecoded_with_dot(),
        )
        .bytes_input(
            "b64u_jwt_payload_sha2_padded",
            &UnsignedJwtPartsWithPadding::from_b64_bytes_with_padding(&unsigned_jwt_with_padding)
                .payload_with_padding()?,
        )
        .str_input("b64u_jwt_payload", &jwt_parts.payload_undecoded())
        .usize_input(
            "b64u_jwt_header_w_dot_len",
            jwt_parts.header_undecoded_with_dot().len(),
        )
        .usize_input(
            "b64u_jwt_payload_sha2_padded_len",
            jwt_parts.payload_undecoded().len(),
        )
        .usize_input("sha2_num_blocks", unsigned_jwt_with_padding.len() * 8 / 512)
        .bytes_input(
            "sha2_num_bits",
            &jwt_bit_len_binary(jwt_parts.unsigned_undecoded().as_bytes()).as_bytes()?,
        )
        .bytes_input(
            "sha2_padding",
            &compute_sha_padding_without_len(jwt_parts.unsigned_undecoded().as_bytes())
                .as_bytes()?,
        )
        .limbs_input("signature", &verified_input.jwt.signature.as_64bit_limbs())
        .limbs_input("pubkey_modulus", &verified_input.jwk.as_64bit_limbs())
        .u64_input("exp_date", verified_input.exp_date_secs)
        .u64_input("exp_horizon", verified_input.exp_horizon_secs)
        .frs_input("epk", &ephemeral_pubkey_frs)
        .fr_input("epk_len", ephemeral_pubkey_len)
        .fr_input("epk_blinder", verified_input.epk_blinder_fr)
        .fr_input("pepper", verified_input.pepper_fr)
        .bool_input("use_extra_field", verified_input.use_extra_field());

    // Add skip_aud_checks (if required)
    if circuit_config.has_input_skip_aud_checks {
        circuit_input_signals =
            circuit_input_signals.bool_input("skip_aud_checks", verified_input.skip_aud_checks);
    }

    // Add the public inputs hash and field check input signals
    circuit_input_signals = circuit_input_signals
        .fr_input("public_inputs_hash", public_inputs_hash)
        .merge(field_check_input_signals(&verified_input)?)?;

    // Return the padded input signals and the Poseidon hash of the public inputs hash
    let padded = circuit_input_signals.pad(circuit_config)?;
    Ok((padded, PoseidonHash::try_from_fr(&public_inputs_hash)?))
}

#[cfg(test)]
mod tests {
    use crate::external_resources::prover_config::ProverServiceConfig;
    use aptos_crypto::{
        ed25519::{Ed25519PrivateKey, Ed25519PublicKey},
        encoding_type::EncodingType,
        poseidon_bn254,
    };
    use aptos_types::transaction::authenticator::EphemeralPublicKey;
    use std::str::FromStr;

    #[test]
    fn test_epk_packing() {
        // Create an Ed25519 ephemeral private key
        let ed25519_private_key: Ed25519PrivateKey = EncodingType::Hex
            .decode_key(
                "ephemeral private key",
                "0x76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7"
                    .as_bytes()
                    .to_vec(),
            )
            .unwrap();

        // Derive the corresponding ephemeral public key
        let ed25519_public_key = Ed25519PublicKey::from(&ed25519_private_key);
        let ephemeral_public_key: EphemeralPublicKey =
            EphemeralPublicKey::ed25519(ed25519_public_key);

        // Pack the ephemeral public key into FRS with length
        let epk_frs_with_len = poseidon_bn254::keyless::pad_and_pack_bytes_to_scalars_with_len(
            ephemeral_public_key.to_bytes().as_slice(),
            ProverServiceConfig::default().max_committed_epk_bytes,
        )
        .unwrap();

        // Verify the ephemeral public key FRS
        let epk_frs = &epk_frs_with_len[0..3];
        assert_eq!(
            epk_frs[0],
            ark_bn254::Fr::from_str(
                "242984842061174104272170180221318235913385474778206477109637294427650138112"
            )
            .unwrap()
        );
        assert_eq!(epk_frs[1], ark_bn254::Fr::from_str("4497911").unwrap());
        assert_eq!(epk_frs[2], ark_bn254::Fr::from_str("0").unwrap());
    }
}
