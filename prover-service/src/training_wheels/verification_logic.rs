use aptos_crypto::poseidon_bn254;
use aptos_keyless_common::input_processing::config::CircuitConfig;
use aptos_types::{
    jwks::rsa::RSA_JWK, keyless::Claims, transaction::authenticator::EphemeralPublicKey,
};
use ark_bn254::Fr;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};

use crate::config::ProverServiceConfig;
use anyhow::Result;

pub fn validate_jwt_sig(jwk: &RSA_JWK, jwt: &str, config: &ProverServiceConfig) -> Result<()> {
    let mut validation = Validation::new(Algorithm::RS256);
    if !config.enable_jwt_exp_not_in_the_past_check {
        //TODO: should it be always enabled?
        validation.validate_exp = false;
    }
    let key = &DecodingKey::from_rsa_components(&jwk.n, &jwk.e)?;

    let _claims = jsonwebtoken::decode::<Claims>(jwt, key, &validation)?;
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
        config.max_lengths["epk"] * poseidon_bn254::keyless::BYTES_PACKED_PER_SCALAR,
    )?;

    frs.push(Fr::from(exp_date));
    frs.push(epk_blinder);

    let nonce_fr = poseidon_bn254::hash_scalars(frs)?;
    Ok(nonce_fr)
}
