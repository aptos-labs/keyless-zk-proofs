// Copyright © Aptos Foundation

use aptos_logger::warn;
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
