// Copyright (c) Aptos Foundation

use aptos_crypto::ed25519::Ed25519PublicKey;
use aptos_crypto::ValidCryptoMaterialStringExt;
use serde::{Deserialize, Serialize};

// TODO: merge this with the same struct used by the pepper service

/// This struct is a representation of an OnChainKeylessConfiguration resource as found on-chain.
/// See, for example:
/// https://fullnode.testnet.aptoslabs.com/v1/accounts/0x1/resource/0x1::keyless_account::Configuration
///
/// Example JSON:
/// {
///  "type": "0x1::keyless_account::Configuration",
///  "data": {
///    "max_commited_epk_bytes": 93,
///    "max_exp_horizon_secs": "10000000",
///    "max_extra_field_bytes": 350,
///    "max_iss_val_bytes": 120,
///    "max_jwt_header_b64_bytes": 300,
///    "max_signatures_per_txn": 3,
///     "override_aud_vals": [],
///     "training_wheels_pubkey": {
///       "vec": [
///         "0x1388de358cf4701696bd58ed4b96e9d670cbbb914b888be1ceda6374a3098ed4"
///       ]
///     }
///   }
/// }
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct OnChainKeylessConfiguration {
    pub r#type: String, // Note: "type" is a reserved keyword, so we use raw identifier syntax
    pub data: KeylessConfigurationData,
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
            data: KeylessConfigurationData {
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

/// The data fields of the OnChainKeylessConfiguration resource
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct KeylessConfigurationData {
    pub max_commited_epk_bytes: u16,
    pub max_exp_horizon_secs: String,
    pub max_extra_field_bytes: u16,
    pub max_iss_val_bytes: u16,
    pub max_jwt_header_b64_bytes: u32,
    pub max_signatures_per_txn: u16,
    pub override_aud_vals: Vec<String>,
    pub training_wheels_pubkey: TrainingWheelsPubKey,
}

/// The training wheels public key of the OnChainKeylessConfiguration resource
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TrainingWheelsPubKey {
    vec: Vec<String>,
}
