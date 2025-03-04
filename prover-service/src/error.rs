// Copyright © Aptos Foundation

use crate::{api::ProverServiceResponse, logging};
use axum::{extract::rejection::JsonRejection, http::StatusCode, response::IntoResponse, Json};
use rust_rapidsnark::ProverError;
use tracing::{error, warn};

// We derive `thiserror::Error`
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    // The `#[from]` attribute generates `From<JsonRejection> for ApiError`
    // implementation. See `thiserror` docs for more information
    #[error(transparent)]
    JsonExtractorRejection(#[from] JsonRejection),
}

// We implement `IntoResponse` so ApiError can be used as a response
impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self {
            ApiError::JsonExtractorRejection(json_rejection) => {
                (json_rejection.status(), json_rejection.body_text())
            }
        };

        let payload = make_error(anyhow::anyhow!("API Error"), status, &message);

        payload.into_response()
    }
}

/// The point of this struct is to have an error which knows which HTTP code to return.
#[derive(Debug)]
pub struct ErrorWithCode {
    pub error: anyhow::Error,
    pub code: Option<StatusCode>,
}

impl ErrorWithCode {
    pub fn context(self, s: &str) -> ErrorWithCode {
        Self {
            error: self.error.context(String::from(s)),
            code: self.code,
        }
    }

    pub fn code(&self) -> StatusCode {
        self.code.unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
    }
}

impl<T> From<T> for ErrorWithCode
where
    T: Into<anyhow::Error>,
{
    fn from(error: T) -> Self {
        Self {
            error: error.into(),
            code: None,
        }
    }
}

pub fn bad_request(error: anyhow::Error) -> ErrorWithCode {
    ErrorWithCode {
        error,
        code: Some(StatusCode::BAD_REQUEST),
    }
}

pub fn server_error(error: anyhow::Error) -> ErrorWithCode {
    ErrorWithCode {
        error,
        code: Some(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

pub fn service_unavailable(error: anyhow::Error) -> ErrorWithCode {
    ErrorWithCode {
        error,
        code: Some(StatusCode::SERVICE_UNAVAILABLE),
    }
}

/// Trait to easily convert results into results that know a code to return.
/// If the wrapped error type already knows its code, do not override.
pub trait ThrowCodeOnError<T> {
    fn with_status(self, code: StatusCode) -> Result<T, ErrorWithCode>;
}

impl<T> ThrowCodeOnError<T> for Result<T, anyhow::Error> {
    fn with_status(self, code: StatusCode) -> Result<T, ErrorWithCode> {
        self.map_err(|error| ErrorWithCode {
            error,
            code: Some(code),
        })
    }
}

// TODO: is this trait necessary?
impl<T> ThrowCodeOnError<T> for Result<T, ErrorWithCode> {
    fn with_status(self, _code: StatusCode) -> Result<T, ErrorWithCode> {
        self
    }
}

impl IntoResponse for ErrorWithCode {
    fn into_response(self) -> axum::response::Response {
        if self.code() == StatusCode::BAD_REQUEST {
            warn!(error = self.error.to_string(), "Responding with error");
        } else {
            error!(error = self.error.to_string(), "Responding with error");
        }

        (
            self.code(),
            Json(ProverServiceResponse::Error {
                message: self.error.to_string(),
            }),
        )
            .into_response()
    }
}

pub fn make_error(
    e: anyhow::Error,
    code: StatusCode,
    message: &str,
) -> (StatusCode, Json<ProverServiceResponse>) {
    logging::do_tracing(&e, code, message);

    let e_description = e.to_string();
    (
        code,
        Json(ProverServiceResponse::Error {
            message: format!("{message}\n{e_description}"),
        }),
    )
}

pub fn handle_prover_lib_error(e: ProverError) -> ErrorWithCode {
    match e {
        ProverError::InvalidInput => bad_request(e.into())
            .context("Input is invalid or malformed"),

        ProverError::WitnessGenerationBinaryProblem => server_error(e.into()).context("Problem with the witness generation binary"),

        ProverError::WitnessGenerationInvalidCurve => server_error(e.into())
            .context("The generated witness file uses a different curve than bn128, which is currently the only supported curve."),

        ProverError::Unknown(s) => server_error(e.into())
            .context(&format!("Unknown error: {s}")),
    }
}

#[macro_export]
macro_rules! bail {
    ($msg:literal $(,)?) => {
        return anyhow::Result::Err($crate::error::ErrorWithCode{error: anyhow::anyhow!($msg), code: None})
    };
    ($err:expr $(,)?) => {
        return anyhow::Result::Err($crate::error::ErrorWithCode{anyhow::anyhow!($err), code: None})
    };
    ($fmt:expr, $($arg:tt)*) => {
        return anyhow::Result::Err($crate::error::ErrorWithCode{error: anyhow::anyhow!($fmt, $($arg)*), code: None})
    };
}
