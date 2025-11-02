// Copyright (c) Aptos Foundation

use aptos_logger::error;
use http::StatusCode;
use serde::Serialize;
use std::fmt::Debug;

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
