// Copyright (c) Aptos Foundation

use aptos_logger::{error, warn};
use http::StatusCode;
use serde::Serialize;
use std::fmt::Debug;
use std::fs;
use std::io::Write;

/// Reads the value of a given environment variable. If
/// the variable is not set, an error will be logged, and
/// the function will return None.
pub fn read_environment_variable(variable_name: &str) -> Option<String> {
    match std::env::var(variable_name) {
        Ok(value) => Some(value),
        Err(error) => {
            warn!(
                "Failed to read environment variable: {}! Error: {}",
                variable_name, error
            );
            None
        }
    }
}

/// Reads the entire contents of a given file path into a string.
/// If the file cannot be read, the function will panic.
pub fn read_string_from_file_path(file_path: &str) -> String {
    match fs::read_to_string(file_path) {
        Ok(content) => content,
        Err(error) => panic!("Failed to read file: {}! Error: {}", file_path, error),
    }
}

/// Serializes the given data to a pretty JSON string, and returns an appropriate HTTP status code
pub fn to_json_string_pretty<T: Debug + Serialize>(data: &T) -> (StatusCode, String) {
    match serde_json::to_string_pretty(&data) {
        Ok(string) => (StatusCode::OK, string),
        Err(error) => {
            // Log and return the error
            let error_string = format!(
                "Failed to serialize data to JSON: {:?}. Error: {}",
                data, error
            );
            error!("{}", error_string);

            (StatusCode::INTERNAL_SERVER_ERROR, error_string)
        }
    }
}

/// Writes the given string to a new file at the specified path (as bytes).
/// If the file cannot be created or written to, the function will panic.
pub fn write_string_to_new_file(file_path: &str, content: &str) {
    // Create the new file
    let mut output_file = fs::File::create(file_path).unwrap_or_else({
        |error| {
            panic!("Failed to create file: {}! Error: {}", file_path, error);
        }
    });

    // Write the content to the file as bytes
    output_file
        .write_all(content.as_bytes())
        .unwrap_or_else(|error| {
            panic!("Failed to write to file: {}! Error: {}", file_path, error);
        });
}

#[cfg(test)]
mod test {
    use crate::config::keyless_config::OnChainKeylessConfiguration;
    use crate::utils;
    use aptos_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
    use aptos_crypto::ValidCryptoMaterialStringExt;

    /// Note: this is not a unit test, but a tool to convert a .vkey file
    /// to its on-chain representation and save in a file.
    #[test]
    fn tw_vk_rewriter() {
        // TODO: move this into a utility CLI? Feels odd here.

        if let (Ok(input_file_path), Ok(output_file_path)) = (
            std::env::var("LOCAL_TW_VK_IN"),
            std::env::var("ONCHAIN_KEYLESS_CONFIG_OUT"),
        ) {
            // Load the local training wheels private key
            let local_tw_sk_encoded = utils::read_string_from_file_path(&input_file_path);

            // Parse the private key, derive the public key and extract the on-chain representation
            let local_tw_sk = Ed25519PrivateKey::from_encoded_string(&local_tw_sk_encoded)
                .expect("Failed to parse TW SK from encoded string!");
            let local_tw_pk = Ed25519PublicKey::from(&local_tw_sk);
            let onchain_keyless_config = OnChainKeylessConfiguration::from_tw_pk(Some(local_tw_pk));

            // Save the on-chain representation to file
            let json_out = serde_json::to_string_pretty(&onchain_keyless_config)
                .expect("Failed to serialize OnChainKeylessConfiguration!");

            // Write the output file
            utils::write_string_to_new_file(&output_file_path, &json_out);
        }
    }
}
