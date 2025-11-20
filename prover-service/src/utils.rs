// Copyright (c) Aptos Foundation

use aptos_logger::{error, warn};
use http::StatusCode;
use reqwest::Client;
use serde::Serialize;
use std::fmt::Debug;
use std::fs;
use std::io::Write;
use std::time::Duration;

// Timeout for client requests
const CLIENT_REQUEST_TIMEOUT_SECS: u64 = 15;

/// Creates and returns a reqwest HTTP client with a timeout
pub fn create_request_client() -> Client {
    Client::builder()
        .timeout(Duration::from_secs(CLIENT_REQUEST_TIMEOUT_SECS))
        .build()
        .expect("Failed to build the request client!")
}

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
