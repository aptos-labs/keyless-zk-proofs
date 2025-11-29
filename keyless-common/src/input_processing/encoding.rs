// Copyright (c) Aptos Foundation

use anyhow::Result;
use aptos_types::{
    jwks::rsa::RSA_JWK, keyless::Pepper, transaction::authenticator::EphemeralPublicKey,
};
use ark_bn254::Fr;
use ark_ff::PrimeField;
use num_bigint::BigUint;

/// A marker type for unpadding
#[derive(Debug)]
pub struct Unpadded;

/// A marker type for padding
#[derive(Debug)]
pub struct Padded;

/// Trait which signals that this type allows conversion into 64-bit limbs.
/// Used for JWT signature and JWK modulus.
pub trait As64BitLimbs {
    fn as_64bit_limbs(&self) -> Vec<u64>;
}

/// Trait for converting to a field element Fr
pub trait AsFr {
    fn as_fr(&self) -> Fr;
}

/// Trait for converting from a field element Fr
pub trait FromFr {
    fn from_fr(fr: &Fr) -> Self;
}

/// Trait for trying to convert from a field element Fr
pub trait TryFromFr: Sized {
    fn try_from_fr(fr: &Fr) -> Result<Self>;
}

/// Trait for converting from base64
pub trait FromB64 {
    fn from_b64(s: &str) -> Result<Self>
    where
        Self: Sized;
}

/// Trait for converting from hexadecimal
pub trait FromHex {
    fn from_hex(s: &str) -> Result<Self>
    where
        Self: Sized;
}

impl As64BitLimbs for RSA_JWK {
    fn as_64bit_limbs(&self) -> Vec<u64> {
        let modulus_bytes = base64::decode_config(&self.n, base64::URL_SAFE_NO_PAD)
            .expect("JWK should always have a properly-encoded modulus");
        // JWKs encode modulus in big-endian order
        let modulus_biguint: BigUint = BigUint::from_bytes_be(&modulus_bytes);
        modulus_biguint.to_u64_digits()
    }
}

impl AsFr for Pepper {
    fn as_fr(&self) -> Fr {
        Fr::from_le_bytes_mod_order(self.to_bytes())
    }
}

impl FromHex for EphemeralPublicKey {
    fn from_hex(s: &str) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(EphemeralPublicKey::try_from(hex::decode(s)?.as_slice())?)
    }
}

impl FromHex for Fr {
    fn from_hex(s: &str) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(Fr::from_le_bytes_mod_order(&hex::decode(s)?))
    }
}
