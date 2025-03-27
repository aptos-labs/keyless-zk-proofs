// Copyright © Aptos Foundation

use crate::{api::RequestInput, config::OidcProvider};
use anyhow::{anyhow, Result};
use aptos_types::jwks::rsa::RSA_JWK;
use dashmap::DashMap;
use keyless_common::input_processing::encoding::{FromB64, JwtHeader, JwtParts, JwtPayload};
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::Value;
use std::{sync::Arc, time::Duration};
use tracing::{error, info, warn};

pub type Issuer = String;
pub type KeyID = String;

// TODO: this is a duplicate of the jwk fetching in the pepper service, with changes b/c the
// DecodingKey type that the pepper service uses is too opaque to use here. We should unify.

static AUTH_0_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^https://[a-zA-Z0-9-_]+\.us\.auth0\.com/$").unwrap());

static COGNITO_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^https://cognito-idp\.[a-zA-Z0-9-_]+\.amazonaws\.com/[a-zA-Z0-9-_]+$").unwrap()
});

/// The JWK in-mem cache.
pub static DECODING_KEY_CACHE: Lazy<DashMap<Issuer, DashMap<KeyID, Arc<RSA_JWK>>>> =
    Lazy::new(DashMap::new);

pub async fn get_federated_jwk(rqi: &RequestInput) -> Result<Arc<RSA_JWK>> {
    let jwt_parts = JwtParts::from_b64(&rqi.jwt_b64)?;

    let header_decoded = jwt_parts.header_decoded()?;
    let header_struct: JwtHeader = serde_json::from_str(&header_decoded)?;

    let payload_decoded = jwt_parts.payload_decoded()?;
    let payload_struct: JwtPayload = serde_json::from_str(&payload_decoded)?;

    let jwk_url = if AUTH_0_REGEX.is_match(&payload_struct.iss) {
        format!("{}.well-known/jwks.json", payload_struct.iss)
    } else if COGNITO_REGEX.is_match(&payload_struct.iss) {
        format!("{}/.well-known/jwks.json", payload_struct.iss)
    } else {
        return Err(anyhow!("not a federated iss"));
    };

    let keys = fetch_jwks(&jwk_url).await?;

    let key = keys
        .get(&header_struct.kid)
        .ok_or_else(|| anyhow!("unknown kid: {}", header_struct.kid))?;
    Ok(key.clone())
}

pub async fn get_jwk(jwt: &str, jwk_url: &str) -> Result<Arc<RSA_JWK>> {
    let jwt_parts = JwtParts::from_b64(jwt)?;
    let header_decoded = jwt_parts.header_decoded()?;
    let header_struct: JwtHeader = serde_json::from_str(&header_decoded)?;
    let keys = fetch_jwks(jwk_url).await?;

    let key = keys
        .get(&header_struct.kid)
        .ok_or_else(|| anyhow!("unknown kid: {}", header_struct.kid))?;
    Ok(key.clone())
}

/// Send a request to a JWK endpoint and return its JWK map.
pub async fn fetch_jwks(jwk_url: &str) -> Result<DashMap<KeyID, Arc<RSA_JWK>>> {
    let response = reqwest::get(jwk_url)
        .await
        .map_err(|e| anyhow!("jwk fetch error: {}", e))?;
    let text = response
        .text()
        .await
        .map_err(|e| anyhow!("error while getting response as text: {}", e))?;
    let endpoint_response_val = serde_json::from_str::<Value>(text.as_str())
        .map_err(|e| anyhow!("error while parsing json: {}", e))?;

    let keys: &Vec<Value> = endpoint_response_val
        .get("keys")
        .ok_or_else(|| anyhow!("Error while parsing jwk json: \"keys\" not found"))?
        .as_array()
        .ok_or_else(|| anyhow!("Error while parsing jwk json: \"keys\" not array"))?;
    let key_map: DashMap<KeyID, Arc<RSA_JWK>> = keys
        .iter()
        .filter_map(|jwk_val| match RSA_JWK::try_from(jwk_val) {
            Ok(jwk) => {
                if jwk.e == "AQAB" {
                    Some((jwk.kid.clone(), Arc::new(jwk)))
                } else {
                    warn!("Unsupported RSA modulus for jwk: {}", jwk_val);
                    None
                }
            }
            Err(e) => {
                warn!("error while parsing jwk {}: {e}", jwk_val);
                None
            }
        })
        .collect();
    Ok(key_map)
}

pub async fn populate_jwk_cache(issuer: &str, jwk_url: &str) {
    fetch_and_cache_jwk(issuer, jwk_url).await;
}

pub fn start_jwk_refresh_loop(issuer: &str, jwk_url: &str, refresh_interval: Duration) {
    let issuer = issuer.to_string();
    let jwk_url = jwk_url.to_string();
    let _handle = tokio::spawn(async move {
        loop {
            fetch_and_cache_jwk(&issuer, &jwk_url).await;
            tokio::time::sleep(refresh_interval).await;
        }
    });
}

async fn fetch_and_cache_jwk(issuer: &str, jwk_url: &str) {
    match fetch_jwks(jwk_url).await {
        Ok(key_set) => {
            let num_keys = key_set.len();
            info!(num_keys, issuer, "Updated key set",);
            DECODING_KEY_CACHE.insert(issuer.to_string(), key_set);
        }
        Err(msg) => {
            error!("{}", msg);
        }
    }
}

pub fn cached_decoding_key(issuer: &str, kid: &str) -> Result<Arc<RSA_JWK>> {
    let key_set = DECODING_KEY_CACHE
        .get(issuer)
        .ok_or_else(|| anyhow!("unknown issuer: {}", issuer))?;
    let key = key_set
        .get(kid)
        .ok_or_else(|| anyhow!("unknown kid: {}", kid))?;
    Ok(key.clone())
}

pub async fn init_jwk_fetching(oidc_providers: &Vec<OidcProvider>, jwk_refresh_rate: Duration) {
    info!("current cache: {:?}", DECODING_KEY_CACHE);

    for provider in oidc_providers {
        // Do initial jwk cache population non-async, so that we don't handle requests before this is
        // populated
        populate_jwk_cache(&provider.iss, &provider.endpoint_url).await;

        // init jwk polling job for this provider
        start_jwk_refresh_loop(&provider.iss, &provider.endpoint_url, jwk_refresh_rate);
    }
}
