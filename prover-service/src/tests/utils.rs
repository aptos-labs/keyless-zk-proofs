// Copyright (c) Aptos Foundation

use crate::tests::types::{DefaultTestJWKKeyPair, TestJWKKeyPair};
use num_bigint::BigUint;
use rsa::pkcs1::{EncodeRsaPrivateKey, LineEnding};
use rsa::rand_core;
use rsa::traits::PublicKeyParts;
use std::str::FromStr;

/// A simple RSA public key representation (for testing)
#[derive(Debug, PartialEq, Eq)]
pub struct RsaPublicKey {
    modulus: BigUint,
}

impl RsaPublicKey {
    /// Returns the modulus as a base64 string
    pub fn as_mod_b64(&self) -> String {
        base64::encode_config(self.modulus.to_bytes_be(), base64::URL_SAFE_NO_PAD)
    }
}

/// A simple RSA private key representation (for testing)
pub struct RsaPrivateKey {
    internal_private_key: rsa::RsaPrivateKey,
}

impl RsaPrivateKey {
    /// Generates a new RSA private key with the given bit size and public exponent
    pub fn new_with_exp<R>(
        rng: &mut R,
        bit_size: usize,
        exp: &BigUint,
    ) -> anyhow::Result<Self, anyhow::Error>
    where
        R: rand_core::CryptoRngCore + ?Sized,
    {
        let exp_rsa_type = rsa::BigUint::from_bytes_be(&exp.to_bytes_be());
        let internal_private_key = rsa::RsaPrivateKey::new_with_exp(rng, bit_size, &exp_rsa_type)?;
        Ok(Self {
            internal_private_key,
        })
    }

    /// Returns the encoding key for this private key (for JWT signing)
    pub fn as_encoding_key(&self) -> jsonwebtoken::EncodingKey {
        let pkcs1_pem = self
            .internal_private_key
            .to_pkcs1_pem(LineEnding::LF)
            .unwrap();
        jsonwebtoken::EncodingKey::from_rsa_pem(pkcs1_pem.as_bytes()).unwrap()
    }
}

impl From<&RsaPrivateKey> for RsaPublicKey {
    fn from(value: &RsaPrivateKey) -> Self {
        RsaPublicKey {
            modulus: BigUint::from_bytes_be(&value.internal_private_key.n().to_bytes_be()),
        }
    }
}

/// Generates a test JWK keypair
pub fn generate_test_jwk_keypair() -> impl TestJWKKeyPair {
    generate_test_jwk_keypair_with_kid("test-rsa")
}

/// Generates a test JWK keypair with the given KID
pub fn generate_test_jwk_keypair_with_kid(kid: &str) -> impl TestJWKKeyPair {
    let exp = BigUint::from_str("65537").unwrap();
    let mut rng = rand_core::OsRng;

    DefaultTestJWKKeyPair::new_with_kid_and_exp(&mut rng, kid, exp).unwrap()
}
