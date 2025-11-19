// Copyright (c) Aptos Foundation

use anyhow::{anyhow, bail, Result};
use std::path::Path;
use std::{fs, process::Command};
use tempfile::NamedTempFile;

pub fn witness_gen(
    witness_gen_js_path: &str,
    witness_gen_wasm_path: &str,
    body: &str,
) -> Result<NamedTempFile> {
    let input_file = NamedTempFile::new()?;
    let witness_file = NamedTempFile::new()?;
    fs::write(input_file.path(), body.as_bytes())?;

    let input_file_path = get_file_path_string(input_file.path())?;
    let witness_file_path = get_file_path_string(witness_file.path())?;

    let mut cmd = get_witness_command(
        witness_gen_js_path,
        witness_gen_wasm_path,
        &input_file_path,
        &witness_file_path,
    );
    let output = cmd.output()?;

    // Check if the command executed successfully
    if output.status.success() {
        Ok(witness_file)
    } else {
        // Print the error message if the command failed
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        bail!("Command failed:\n{}\n{}", stdout, stderr)
    }
}

/// Converts a file path to a string, returning an error if the conversion fails
pub fn get_file_path_string(file_path: &Path) -> Result<String> {
    let file_path_string = file_path
        .to_str()
        .ok_or_else(|| anyhow!("Failed to convert file path to string: {:?}!", file_path))?;
    Ok(file_path_string.to_string())
}

fn get_witness_command(
    witness_gen_js_path: &str,
    witness_gen_wasm_path: &str,
    input_file_path: &str,
    witness_file_path: &str,
) -> Command {
    let mut c = Command::new("node");
    c.args(&[
        witness_gen_js_path.to_string(),
        witness_gen_wasm_path.to_string(),
        String::from(input_file_path),
        String::from(witness_file_path),
    ]);
    c
}
