mod sign;
pub mod verification_logic;

use crate::api::RequestInput;
use crate::config::ProverServiceConfig;
use crate::input_processing::types::VerifiedInput;
use crate::jwk_fetching;
use crate::jwk_fetching::get_federated_jwk;
use crate::state::ProverServiceState;
use crate::training_wheels::verification_logic::compute_nonce;
use anyhow::{anyhow, bail, ensure};
use aptos_keyless_common::input_processing::encoding::{AsFr, DecodedJWT};
use aptos_keyless_common::logging;
use aptos_keyless_common::logging::HasLoggableError;
use aptos_types::jwks::rsa::RSA_JWK;
pub use sign::sign;
pub use sign::verify;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
pub use verification_logic::validate_jwt_sig;

/// All training-wheel checks go here.
/// If a request passes this, we should be convinced that this is the *public statement* to be proved is correct.
pub async fn preprocess_and_validate_request(
    prover: &ProverServiceState,
    req: &RequestInput,
) -> anyhow::Result<VerifiedInput> {
    let _span = logging::new_span("TrainingWheelChecks");
    let jwt = DecodedJWT::from_b64(&req.jwt_b64).log_err()?;
    let jwk = finalize_jwk(&prover.config, &jwt).await.log_err()?;

    {
        let _span = logging::new_span("VerifyJWTSignature");
        validate_jwt_sig(jwk.as_ref(), &req.jwt_b64, &prover.config).log_err()?;
    }

    if prover.config.enable_jwt_iat_not_in_future_check {
        let _span = logging::new_span("CheckIatNotInFuture");
        let now_unix_secs = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        ensure!(
            jwt.payload.iat <= now_unix_secs,
            "jwt which was issued in the future"
        );
    }

    {
        let _span = logging::new_span("CheckNonceConsistency");
        let computed_nonce = compute_nonce(
            req.exp_date_secs,
            &req.epk,
            req.epk_blinder.as_fr(),
            prover.circuit_config(),
        )
        .log_err()?;
        ensure!(jwt.payload.nonce == computed_nonce.to_string());
    }

    let uid_val = {
        let _span = logging::new_span("EnsureUidKeyNotNull");
        match req.uid_key.as_str() {
            "email" => jwt
                .payload
                .email
                .clone()
                .ok_or_else(|| anyhow!("Missing email in jwt payload"))?,
            "sub" => jwt
                .payload
                .sub
                .clone()
                .ok_or_else(|| anyhow!("Missing sub in jwt payload"))?,
            _ => bail!("Unrecognized uid_key: {}", req.uid_key),
        }
    };

    VerifiedInput::new(req, jwk, jwt, uid_val).log_err()
}

async fn finalize_jwk(
    prover_config: &ProverServiceConfig,
    jwt: &DecodedJWT,
) -> anyhow::Result<Arc<RSA_JWK>> {
    let _span = logging::new_span("FinalizeJWK");
    let default_jwk = jwk_fetching::cached_decoding_key(&jwt.payload.iss, &jwt.header.kid);
    if default_jwk.is_ok() {
        return default_jwk;
    }
    ensure!(prover_config.enable_federated_jwks);
    get_federated_jwk(jwt).await
}
