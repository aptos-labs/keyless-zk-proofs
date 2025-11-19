// Copyright (c) Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use aptos_build_info::build_information;
use aptos_crypto::ed25519::Ed25519PublicKey;
use aptos_infallible::Mutex;
use std::{collections::BTreeMap, sync::Arc};

// The key used to store the training wheels verification key in the deployment information
const TRAINING_WHEELS_VERIFICATION_KEY: &str = "training_wheels_verification_key";

/// A simple struct to hold deployment information as key-value pairs
#[derive(Clone, Debug)]
pub struct DeploymentInformation {
    deployment_information_map: Arc<Mutex<BTreeMap<String, String>>>,
}

impl DeploymentInformation {
    pub fn new() -> Self {
        // Collect the build information and initialize the map
        let build_information = build_information!();
        let deployment_information_map = Arc::new(Mutex::new(build_information));

        Self {
            deployment_information_map,
        }
    }

    /// Adds a new key-value pair to the deployment information map
    pub fn extend_deployment_information(&mut self, key: String, value: String) {
        self.deployment_information_map.lock().insert(key, value);
    }

    /// Returns a copy of the deployment information map
    pub fn get_deployment_information_map(&self) -> BTreeMap<String, String> {
        self.deployment_information_map.lock().clone()
    }
}

impl Default for DeploymentInformation {
    fn default() -> Self {
        Self::new()
    }
}

/// Creates and returns the deployment information for the prover service
pub fn get_deployment_information(
    training_wheels_verification_key: &Ed25519PublicKey,
) -> DeploymentInformation {
    // Create the deployment information
    let mut deployment_information = DeploymentInformation::new();

    // Insert the training wheels verification key into the deployment information.
    // This is useful for runtime verification (e.g., to ensure the correct key is being used).
    deployment_information.extend_deployment_information(
        TRAINING_WHEELS_VERIFICATION_KEY.into(),
        training_wheels_verification_key.to_string(),
    );

    deployment_information
}
