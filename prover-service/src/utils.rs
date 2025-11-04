// Copyright (c) Aptos Foundation

use aptos_logger::{error, warn};
use http::StatusCode;
use serde::Serialize;
use std::fmt::Debug;
use std::fs;

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
