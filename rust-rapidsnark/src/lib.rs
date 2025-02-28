// Copyright © Aptos Foundation

// Copyright © Aptos Foundation

// Copyright © Aptos Foundation

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

mod cpp {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
    unsafe impl Send for FullProverImpl {}
    unsafe impl Send for FullProver {}
}

use std::ffi::{CStr, CString};
use thiserror::Error;

pub type ProverResponse<'a> = Result<&'a str, ProverError>;

#[derive(Debug, Error)]
pub enum ProverInitError {
    #[error("Problem loading the prover key")]
    ZKeyFileLoadError,
    #[error("Prover key is using an unsupported curve")]
    UnsupportedZKeyCurve,
    #[error("Unknown error")]
    Unknown,
}

#[derive(Debug, Error)]
pub enum ProverError {
    #[error("Invalid input")]
    InvalidInput,
    #[error("There was a problem with the witness generation binary")]
    WitnessGenerationBinaryProblem,
    #[error("Witness generation outputted with an invalid curve")]
    WitnessGenerationInvalidCurve,
    #[error("Unknown error: {0}")]
    Unknown(&'static str),
}

pub struct FullProver {
    _full_prover: cpp::FullProver,
}

impl FullProver {
    pub fn new(zkey_path: &str) -> Result<FullProver, ProverInitError> {
        let zkey_path_cstr = CString::new(zkey_path).expect("CString::new failed");
        let full_prover = unsafe {
            FullProver {
                _full_prover: cpp::FullProver::new(zkey_path_cstr.as_ptr()),
            }
        };
        match full_prover._full_prover.state {
            cpp::FullProverState_OK => Ok(full_prover),
            cpp::FullProverState_ZKEY_FILE_LOAD_ERROR => Err(ProverInitError::ZKeyFileLoadError),
            cpp::FullProverState_UNSUPPORTED_ZKEY_CURVE => {
                Err(ProverInitError::UnsupportedZKeyCurve)
            }
            _ => Err(ProverInitError::Unknown),
        }
    }

    pub fn prove(
        &self,
        witness_file_path: &str,
    ) -> Result<(&str, cpp::ProverResponseMetrics), ProverError> {
        let witness_file_path_cstr = CString::new(witness_file_path).expect("CString::new failed");
        let response = unsafe { self._full_prover.prove(witness_file_path_cstr.as_ptr()) };
        match response.type_ {
            cpp::ProverResponseType_SUCCESS => unsafe {
                Ok((
                    CStr::from_ptr(response.raw_json)
                        .to_str()
                        .expect("CStr::to_str failed"),
                    response.metrics,
                ))
            },
            cpp::ProverResponseType_ERROR => match response.error {
                cpp::ProverError_NONE => Err(ProverError::Unknown(
                    "c++ rapidsnark prover returned \"error\" response type but error is \"none\"",
                )),
                cpp::ProverError_PROVER_NOT_READY => panic!(
                    "Somehow called prove on an uninitialized prover (this shouldn't ever happen)"
                ),
                cpp::ProverError_INVALID_INPUT => Err(ProverError::InvalidInput),
                cpp::ProverError_WITNESS_GENERATION_INVALID_CURVE => {
                    Err(ProverError::WitnessGenerationInvalidCurve)
                }
                _ => Err(ProverError::Unknown(
                    "c++ rapidsnark prover returned an unknown error code",
                )),
            },
            _ => Err(ProverError::Unknown(
                "c++ rapidsnark prover returned an unknown error code",
            )),
        }
    }
}

impl Drop for FullProver {
    fn drop(&mut self) {
        unsafe {
            self._full_prover.destruct();
        }
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn dummy_prove_test() {
        // let prover = crate::FullProver::new("../zkey.zkey").expect("failed to initialize prover");
        // let _result = prover.prove("../witness.wtns");
        assert_eq!(2 + 2, 4);
    }
}
