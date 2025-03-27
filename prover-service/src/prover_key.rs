// Copyright © Aptos Foundation

// Import AsyncWriteExt for async writing

use crate::config::ProverServiceConfig;
use crate::watcher::ExternalResource;
use aptos_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
use aptos_crypto::ValidCryptoMaterialStringExt;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::sync::{Arc, RwLock};

pub async fn cached_prover_key(config: &ProverServiceConfig) -> String {
    String::from(&config.resources_dir) + &config.zkey_filename
}

pub async fn cached_verification_key(config: &ProverServiceConfig) -> String {
    String::from(&config.resources_dir) + &config.test_verification_key_filename
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct OnChainKeylessConfiguration {
    /// Some type info returned by node API.
    pub r#type: String,
    pub data: ConfigData,
}

impl OnChainKeylessConfiguration {
    pub fn from_tw_pk(tw_pk: Option<Ed25519PublicKey>) -> Self {
        let vec = if let Some(pk) = tw_pk {
            vec![pk.to_encoded_string().unwrap()]
        } else {
            vec![]
        };

        Self {
            r#type: "0x1::keyless_account::Configuration".to_string(),
            data: ConfigData {
                max_commited_epk_bytes: 93,
                max_exp_horizon_secs: "10000000".to_string(),
                max_extra_field_bytes: 350,
                max_iss_val_bytes: 120,
                max_jwt_header_b64_bytes: 300,
                max_signatures_per_txn: 3,
                override_aud_vals: vec![],
                training_wheels_pubkey: TrainingWheelsPubKey { vec },
            },
        }
    }
}

impl ExternalResource for OnChainKeylessConfiguration {
    fn resource_name() -> String {
        "OnChainTrainingWheelVerificationKey".to_string()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ConfigData {
    pub max_commited_epk_bytes: u16,
    pub max_exp_horizon_secs: String,
    pub max_extra_field_bytes: u16,
    pub max_iss_val_bytes: u16,
    pub max_jwt_header_b64_bytes: u32,
    pub max_signatures_per_txn: u16,
    pub override_aud_vals: Vec<String>,
    pub training_wheels_pubkey: TrainingWheelsPubKey,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TrainingWheelsPubKey {
    vec: Vec<String>,
}

#[derive(Debug)]
pub struct TrainingWheelsKeyPair {
    pub signing_key: Ed25519PrivateKey,
    pub verification_key: Ed25519PublicKey,
    pub on_chain_repr: OnChainKeylessConfiguration,
}

impl TrainingWheelsKeyPair {
    pub fn from_sk(sk: Ed25519PrivateKey) -> Self {
        let verification_key = Ed25519PublicKey::from(&sk);
        let on_chain_repr = OnChainKeylessConfiguration::from_tw_pk(Some(verification_key.clone()));
        Self {
            signing_key: sk,
            verification_key,
            on_chain_repr,
        }
    }
}

pub static ON_CHAIN_KEYLESS_CONFIG: Lazy<Arc<RwLock<Option<OnChainKeylessConfiguration>>>> =
    Lazy::new(|| Arc::new(RwLock::new(None)));

/// This is not a UT, but a tool to convert a .vkey to its on-chain representation and save in a file.
#[test]
fn tw_vk_rewriter() {
    if let (Ok(path_in), Ok(path_out)) = (
        std::env::var("LOCAL_TW_VK_IN"),
        std::env::var("ONCHAIN_KEYLESS_CONFIG_OUT"),
    ) {
        let local_tw_sk_encoded = std::fs::read_to_string(&path_in).unwrap();
        let local_tw_sk =
            Ed25519PrivateKey::from_encoded_string(local_tw_sk_encoded.as_str()).unwrap();
        let local_tw_keypair = TrainingWheelsKeyPair::from_sk(local_tw_sk);
        write_tw_on_chain_repr_json(&local_tw_keypair, &path_out);
    }
}

pub fn write_tw_on_chain_repr_json(tw_keypair: &TrainingWheelsKeyPair, path_out: &str) {
    let json_out = serde_json::to_string_pretty(&tw_keypair.on_chain_repr).unwrap();
    std::fs::File::create(path_out)
        .unwrap()
        .write_all(json_out.as_bytes())
        .unwrap();
}
