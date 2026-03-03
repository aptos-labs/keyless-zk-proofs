// Copyright (c) Aptos Foundation

use aptos_logger::error;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A prover service error (e.g., for bad API requests, internal errors, etc.)
#[derive(Clone, Debug, Deserialize, Error, PartialEq, Eq, Serialize)]
pub enum ProverServiceError {
    #[error("Bad request error: {0}")]
    BadRequest(String),
    #[error("Internal service error: {0}")]
    InternalError(String),
    #[error("Unexpected error: {0}")]
    UnexpectedError(String),
}

impl From<anyhow::Error> for ProverServiceError {
    fn from(error: anyhow::Error) -> Self {
        ProverServiceError::UnexpectedError(error.to_string())
    }
}
