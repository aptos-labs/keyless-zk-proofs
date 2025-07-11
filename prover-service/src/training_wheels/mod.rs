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
    let jwk = get_jwk(&prover.config, &jwt).await.log_err()?;

    {
        // Keyless relation condition 10 captured: https://github.com/aptos-foundation/AIPs/blob/f133e29d999adf31c4f41ce36ae1a808339af71e/aips/aip-108.md?plain=1#L95
        let _span = logging::new_span("VerifyJWTSignature");
        validate_jwt_sig(jwk.as_ref(), &req.jwt_b64, &prover.config).log_err()?;
    }

    {
        // Keyless relation condition 8 captured: https://github.com/aptos-foundation/AIPs/blob/f133e29d999adf31c4f41ce36ae1a808339af71e/aips/aip-108.md?plain=1#L92
        let _span = logging::new_span("EnsureEpkNotExpired");
        ensure!(
            (req.exp_date_secs as u128)
                < (jwt.payload.iat as u128) + (req.exp_horizon_secs as u128)
        );
    }

    if prover.config.enable_jwt_iat_not_in_future_check {
        //TODO: should it be always enabled?
        let _span = logging::new_span("CheckIatNotInFuture");
        let now_unix_secs = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        ensure!(
            jwt.payload.iat <= now_unix_secs,
            "jwt which was issued in the future"
        );
    }

    {
        // Keyless relation condition 7 captured: https://github.com/aptos-foundation/AIPs/blob/f133e29d999adf31c4f41ce36ae1a808339af71e/aips/aip-108.md?plain=1#L90
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
            "email" => {
                // Keyless relation condition 3 captured: https://github.com/aptos-foundation/AIPs/blob/f133e29d999adf31c4f41ce36ae1a808339af71e/aips/aip-108.md?plain=1#L74
                ensure!(Some(true) == jwt.payload.email_verified);
                jwt.payload
                    .email
                    .clone()
                    .ok_or_else(|| anyhow!("Missing email in jwt payload"))?
            }
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

/// This function returns the same JWK that the Aptos validators would expect for this JWT.
/// Specifically, it first checks if there is a "global" JWK for that `iss` "installed" by JWK consensus
/// (as per AIP-96 https://github.com/aptos-foundation/AIPs/blob/main/aips/aip-96.md#high-level-overview).
/// If there is no "global" JWK installed, it manually fetches the JWK from the JWK URL endpoint associated with the `iss`.
async fn get_jwk(
    prover_config: &ProverServiceConfig,
    jwt: &DecodedJWT,
) -> anyhow::Result<Arc<RSA_JWK>> {
    let _span = logging::new_span("GetJWK");
    let default_jwk = jwk_fetching::cached_decoding_key(&jwt.payload.iss, &jwt.header.kid);
    if default_jwk.is_ok() {
        return default_jwk;
    }
    ensure!(prover_config.enable_federated_jwks);
    get_federated_jwk(jwt).await
}
