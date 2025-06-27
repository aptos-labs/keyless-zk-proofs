// Copyright © Aptos Foundation

use crate::config::ProverServiceConfig;
use anyhow::{anyhow, bail, Result};
use aptos_keyless_common::logging;
use std::fs;
use std::process::Command;
use tempfile::NamedTempFile;

pub trait PathStr {
    fn path_str(&self) -> Result<&str>;
}

impl PathStr for NamedTempFile {
    fn path_str(&self) -> Result<&str> {
        self.path().to_str().ok_or(anyhow!("tempfile path error"))
    }
}

pub fn witness_gen(config: &ProverServiceConfig, body: &str) -> Result<NamedTempFile> {
    let _span = logging::new_span("GenerateWitness");

    let input_file = NamedTempFile::new()?;
    let witness_file = NamedTempFile::new()?;

    fs::write(input_file.path(), body.as_bytes())?;

    let output =
        get_witness_command(config, input_file.path_str()?, witness_file.path_str()?).output()?;

    // Check if the command executed successfully
    if output.status.success() {
        // Convert the output bytes to a string
        // let stdout = String::from_utf8_lossy(&output.stdout);

        // Print the output
        // This prints sensitive data. Do not uncomment in production.
        //println!("Command output:\n{}", stdout);
        Ok(witness_file)
    } else {
        // Print the error message if the command failed
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Command failed:\n{}", stderr);
    }
}

#[cfg(not(target_arch = "x86_64"))]
fn get_witness_command(
    config: &ProverServiceConfig,
    input_file_path: &str,
    witness_file_path: &str,
) -> Command {
    let mut c = Command::new("node");
    c.args(&[
        config.witness_gen_js_path(),
        config.witness_gen_wasm_path(),
        String::from(input_file_path),
        String::from(witness_file_path),
    ]);
    c
}

#[cfg(target_arch = "x86_64")]
fn get_witness_command(
    config: &ProverServiceConfig,
    input_file_path: &str,
    witness_file_path: &str,
) -> Command {
    let mut c = Command::new(config.witness_gen_binary_path());
    c.args([input_file_path, witness_file_path]); // Example arguments
    c
}
