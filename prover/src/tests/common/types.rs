// Copyright © Aptos Foundation

use std::time::{SystemTime, UNIX_EPOCH};

use super::{gen_test_ephemeral_pk, gen_test_ephemeral_pk_blinder, get_test_pepper};
use aptos_keyless_common::input_processing::{config::CircuitPaddingConfig, encoding::FromFr};
use crate::{
    api::{EphemeralPublicKeyBlinder, RequestInput},
    input_processing::rsa::RsaPrivateKey,
    training_wheels::verification_logic::compute_nonce,
};
use aptos_types::{
    jwks::rsa::RSA_JWK, keyless::Pepper, transaction::authenticator::EphemeralPublicKey,
};
use ark_ff::{BigInteger, PrimeField};
use jsonwebtoken::{Algorithm, Header};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct TestJWTPayload {
    pub azp: String,
    pub aud: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    pub hd: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    pub at_hash: String,
    pub name: String,
    pub picture: String,
    pub given_name: String,
    pub family_name: String,
    pub locale: String,
    pub iss: String,
    pub iat: u64,
    pub exp: u64,
    pub nonce: String,
}

pub trait WithNonce {
    fn with_nonce(&self, nonce: &str) -> Self;
}

impl WithNonce for TestJWTPayload {
    fn with_nonce(&self, nonce: &str) -> Self {
        Self {
            nonce: String::from(nonce),
            ..self.clone()
        }
    }
}

impl Default for TestJWTPayload {
    fn default() -> Self {
        let start = SystemTime::now();
        let since_the_epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");

        TestJWTPayload {
        azp: String::from("407408718192.apps.googleusercontent.com"),
        aud: String::from("407408718192.apps.googleusercontent.com"),
        sub: Some(String::from("113990307082899718775")),
        email: Some(String::from("michael@aptoslabs.com")),
        hd: String::from("aptoslabs.com"),
        email_verified: Some(true),
        at_hash: String::from("bxIESuI59IoZb5alCASqBg"),
        name: String::from("Michael Straka"),
        picture: String::from("https://lh3.googleusercontent.com/a/ACg8ocJvY4kVUBRtLxe1IqKWL5i7tBDJzFp9YuWVXMzwPpbs=s96-c"),
        given_name: String::from("Michael"),
        family_name: String::from("Straka"),
        locale: String::from("en"),
        iss: String::from("test.oidc.provider"),
        iat: 0,
        exp: since_the_epoch.as_secs() + 100,
        nonce: String::from(""),
    }
    }
}

// JWK keypair trait/struct

pub trait TestJWKKeyPair {
    fn pubkey_mod_b64(&self) -> String;
    fn kid(&self) -> &str;
    fn sign(&self, payload: &impl Serialize) -> String;
    #[allow(clippy::all)]
    fn into_rsa_jwk(&self) -> RSA_JWK;
}

pub struct DefaultTestJWKKeyPair {
    kid: String,
    private_key: crate::input_processing::rsa::RsaPrivateKey,
}

impl DefaultTestJWKKeyPair {
    pub fn new_with_kid_and_exp<R>(
        rng: &mut R,
        kid: &str,
        exp: num_bigint::BigUint,
    ) -> Result<Self, anyhow::Error>
    where
        R: rsa::rand_core::CryptoRngCore + Sized,
    {
        Ok(Self {
            kid: String::from(kid),
            private_key: RsaPrivateKey::new_with_exp(rng, 2048, &exp)?,
        })
    }
}

impl TestJWKKeyPair for DefaultTestJWKKeyPair {
    fn pubkey_mod_b64(&self) -> String {
        crate::input_processing::rsa::RsaPublicKey::from(&self.private_key).as_mod_b64()
    }

    fn kid(&self) -> &str {
        &self.kid
    }

    #[allow(clippy::all)]
    fn sign(&self, payload: &impl Serialize) -> String {
        let mut header = Header::default();
        header.alg = Algorithm::RS256;
        header.kid = Some(self.kid.clone());

        let jwt =
            jsonwebtoken::encode(&header, &payload, &self.private_key.as_encoding_key()).unwrap();

        let jwk = RSA_JWK::new_256_aqab(self.kid.as_str(), &self.pubkey_mod_b64());
        assert!(jwk.verify_signature_without_exp_check(&jwt).is_ok());

        jwt
    }

    fn into_rsa_jwk(&self) -> RSA_JWK {
        RSA_JWK::new_256_aqab(&self.kid, &self.pubkey_mod_b64())
    }
}

#[derive(Clone)]
pub struct ProofTestCase<T: Serialize + WithNonce + Clone> {
    pub jwt_payload: T,
    pub epk: EphemeralPublicKey,
    pub epk_blinder_fr: ark_bn254::Fr,
    pub pepper: Pepper,
    pub epk_expiry_time_secs: u64,
    pub epk_expiry_horizon_secs: u64,
    pub extra_field: Option<String>,
    pub uid_key: String,
    pub idc_aud: Option<String>,
}

impl<T: Serialize + WithNonce + Clone> ProofTestCase<T> {
    #[allow(clippy::all)]
    #[allow(dead_code)]
    pub fn new_with_test_epk_and_blinder(
        jwt_payload: T,
        pepper: Pepper,
        exp_date: u64,
        exp_horizon: u64,
        extra_field: Option<String>,
        uid_key: String,
        idc_aud: Option<String>,
        config: &CircuitPaddingConfig,
    ) -> Self {
        let epk = gen_test_ephemeral_pk();
        let epk_blinder = gen_test_ephemeral_pk_blinder();

        let nonce = compute_nonce(exp_date, &epk, epk_blinder, config).unwrap();
        let payload_with_nonce = jwt_payload.with_nonce(&nonce.to_string());

        Self {
            jwt_payload: payload_with_nonce as T,
            epk,
            epk_blinder_fr: epk_blinder,
            pepper,
            epk_expiry_time_secs: exp_date,
            epk_expiry_horizon_secs: exp_horizon,
            extra_field,
            uid_key,
            idc_aud: idc_aud,
        }
    }

    pub fn default_with_payload(jwt_payload: T) -> Self {
        let epk = gen_test_ephemeral_pk();
        let epk_blinder = gen_test_ephemeral_pk_blinder();
        let pepper = get_test_pepper();

        Self {
            jwt_payload,
            epk,
            epk_blinder_fr: epk_blinder,
            pepper,
            epk_expiry_time_secs: 0,
            epk_expiry_horizon_secs: 100,
            extra_field: Some(String::from("name")),
            uid_key: String::from("email"),
            idc_aud: None,
        }
    }

    pub fn compute_nonce(self, config: &CircuitPaddingConfig) -> Self {
        let nonce = compute_nonce(
            self.epk_expiry_time_secs,
            &self.epk,
            self.epk_blinder_fr,
            config,
        )
        .unwrap();
        let payload_with_nonce = self.jwt_payload.with_nonce(&nonce.to_string());

        Self {
            jwt_payload: payload_with_nonce,
            ..self
        }
    }

    pub fn convert_to_prover_request(&self, jwk_keypair: &impl TestJWKKeyPair) -> RequestInput {
        let _epk_blinder_hex_string = hex::encode(self.epk_blinder_fr.into_bigint().to_bytes_le());

        RequestInput {
            jwt_b64: jwk_keypair.sign(&self.jwt_payload),
            epk: self.epk.clone(),
            epk_blinder: EphemeralPublicKeyBlinder::from_fr(&self.epk_blinder_fr),
            exp_date_secs: self.epk_expiry_time_secs,
            exp_horizon_secs: self.epk_expiry_horizon_secs,
            pepper: self.pepper.clone(),
            uid_key: self.uid_key.clone(),
            extra_field: self.extra_field.clone(),
            idc_aud: self.idc_aud.clone(),
            use_insecure_test_jwk: false,
        }
    }
}
