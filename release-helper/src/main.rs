// Copyright (c) Aptos Foundation

use aptos_keyless_common::groth16_vk::{
    OnChainGroth16VerificationKey, SnarkJsGroth16VerificationKey,
};
use clap::{Parser, Subcommand};
use std::fs;
use std::io::Write;
use std::path::PathBuf;

// Paths to various release builder directories (relative to aptos-core repo root)
const APTOS_RELEASE_BUILDER_DATA_PATH: &str = "aptos-move/aptos-release-builder/data";
const APTOS_RELEASE_BUILDER_PROPOSALS_PATH: &str =
    "aptos-move/aptos-release-builder/data/proposals";

// Prefix for hex strings
const HEX_PREFIX: &str = "0x";

// File names for the keyless config update files
const KEYLESS_CONFIG_MOVE_FILE_NAME: &str = "keyless-config-update.move";
const KEYLESS_CONFIG_YAML_FILE: &str = "keyless-config-update.yaml";

#[derive(Parser)]
#[clap(name = "release-helper")]
#[clap(about = "Aptos Keyless Release Helper")]
#[clap(version)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate root signer script
    GenerateRootSignerScript {
        /// Path to the verification key file
        #[clap(long = "vk-path")]
        vk_path: PathBuf,

        /// Path to the training wheel public key file
        #[clap(long = "twpk-path")]
        twpk_path: PathBuf,

        /// Output path for the generated governance script
        #[clap(long = "out")]
        out: PathBuf,
    },
    /// Generate a governance proposal in a local aptos-core repo
    GenerateProposal {
        /// Path to a local aptos-core repo that this tool will modify
        #[clap(long = "aptos-core-path")]
        aptos_core_path: PathBuf,

        /// Path to the verification key file
        #[clap(long = "vk-path")]
        vk_path: PathBuf,

        /// Path to the training wheel public key file
        #[clap(long = "twpk-path")]
        twpk_path: PathBuf,

        /// The circuit release tag (only used in description text)
        #[clap(long = "circuit-release-tag")]
        circuit_release_tag: String,

        /// The training wheel key ID (only used in description text)
        #[clap(long = "tw-key-id")]
        tw_key_id: String,

        /// The remote endpoint URL (only used in YAML file)
        #[clap(
            long = "remote-endpoint",
            default_value = "https://api.mainnet.aptoslabs.com"
        )]
        remote_endpoint: String,
    },
}

/// The mode for generating the proposal script
enum ProposalExecutionMode {
    RootSigner,
    ProposalID,
}

fn main() {
    // Parse the CLI arguments
    let cli = Cli::parse();

    // Execute the command
    match cli.command {
        Commands::GenerateRootSignerScript {
            vk_path,
            twpk_path,
            out,
        } => generate_root_signer_script(vk_path, twpk_path, out),
        Commands::GenerateProposal {
            aptos_core_path,
            circuit_release_tag,
            tw_key_id,
            vk_path,
            twpk_path,
            remote_endpoint,
        } => generate_governance_proposal(
            aptos_core_path,
            circuit_release_tag,
            tw_key_id,
            vk_path,
            twpk_path,
            remote_endpoint,
        ),
    }
}

/// Generates a governance proposal in the specified aptos-core repo
fn generate_governance_proposal(
    aptos_core_path: PathBuf,
    circuit_release_tag: String,
    tw_key_id: String,
    vk_path: PathBuf,
    twpk_path: PathBuf,
    remote_endpoint: String,
) {
    // Create the release YAML file
    create_release_yaml(
        aptos_core_path.clone(),
        circuit_release_tag,
        tw_key_id,
        remote_endpoint,
    );

    // Generate the proposal script
    generate_proposal_script(aptos_core_path, vk_path, twpk_path);
}

/// Creates the release YAML file and writes it to the specified aptos-core repo
fn create_release_yaml(
    aptos_core_path: PathBuf,
    circuit_release_tag: String,
    tw_key_id: String,
    remote_endpoint: String,
) {
    // Create the YAML content
    let release_yaml_content = format!(
        r#"---
remote_endpoint: {}
name: "keyless_config_update"
proposals:
  - name: keyless_config_update
    metadata:
      title: "Update to circuit release {} + training-wheel key ID {}"
      description: ""
    execution_mode: MultiStep
    update_sequence:
      - RawScript: aptos-move/aptos-release-builder/data/proposals/keyless-config-update.move
"#,
        remote_endpoint, circuit_release_tag, tw_key_id
    );

    // Write the YAML to the output file
    let target_path = aptos_core_path
        .join(APTOS_RELEASE_BUILDER_DATA_PATH)
        .join(KEYLESS_CONFIG_YAML_FILE);
    write_bytes_to_file(target_path, release_yaml_content);
}

/// Generates the proposal script and writes it to the specified aptos-core repo
fn generate_proposal_script(aptos_core_path: PathBuf, vk_path: PathBuf, twpk_path: PathBuf) {
    // Generate the script content
    let script_content =
        generate_script_content(ProposalExecutionMode::ProposalID, vk_path, twpk_path);

    // Write the script to the output file
    let target_path = aptos_core_path
        .join(APTOS_RELEASE_BUILDER_PROPOSALS_PATH)
        .join(KEYLESS_CONFIG_MOVE_FILE_NAME);
    write_bytes_to_file(target_path, script_content);
}

/// Generates a root signer script and writes it to the specified output path
fn generate_root_signer_script(vk_path: PathBuf, twpk_path: PathBuf, out: PathBuf) {
    println!("Generating root signer script...");
    println!("VK path: {}", vk_path.display());
    println!("TWPK path: {}", twpk_path.display());
    println!("Output path: {}", out.display());

    // Generate the governance script
    let script_content =
        generate_script_content(ProposalExecutionMode::RootSigner, vk_path, twpk_path);

    // Ensure the output directory exists
    if let Some(parent) = out.parent() {
        fs::create_dir_all(parent).unwrap();
    }

    // Write the script to the output file
    fs::write(out.clone(), script_content).unwrap();

    println!(
        "Successfully generated root signer script at path: {}",
        out.display()
    );
}

/// Generates the Move script content for updating the keyless config (depending on the mode)
fn generate_script_content(
    proposal_execution_mode: ProposalExecutionMode,
    vk_path: PathBuf,
    twpk_path: PathBuf,
) -> String {
    // Read the verification key file and transform it into an on-chain format
    let local_vk_json = read_file_contents(vk_path);
    let local_vk: SnarkJsGroth16VerificationKey = serde_json::from_str(&local_vk_json).unwrap();
    let vk = OnChainGroth16VerificationKey::try_from(local_vk).unwrap();

    // Read the training wheel public key file
    let twpk_repr = read_file_contents(twpk_path);

    // Determine the main parameter and framework signer expression
    let (main_param, framework_signer_expression) = match proposal_execution_mode {
        ProposalExecutionMode::RootSigner => (
            "core_resources: &signer",
            "aptos_governance::get_signer_testnet_only(core_resources, @0x1)",
        ),
        ProposalExecutionMode::ProposalID => (
            "proposal_id: u64",
            "aptos_governance::resolve_multi_step_proposal(proposal_id, @0x1, {{ script_hash }},)",
        ),
    };

    // Create and return the script content
    format!(
        r#"
script {{
    use aptos_framework::keyless_account;
    use aptos_framework::aptos_governance;
    use std::option;
    fun main({}) {{
        let framework_signer = {};

        let alpha_g1 = x"{}";
        let beta_g2 = x"{}";
        let gamma_g2 = x"{}";
        let delta_g2 = x"{}";
        let gamma_abc_g1 = vector[
            x"{}",
            x"{}",
        ];
        let vk = keyless_account::new_groth16_verification_key(alpha_g1, beta_g2, gamma_g2, delta_g2, gamma_abc_g1);
        keyless_account::set_groth16_verification_key_for_next_epoch(&framework_signer, vk);
        let pk_bytes = x"{}";
        keyless_account::update_training_wheels_for_next_epoch(&framework_signer, option::some(pk_bytes));
        aptos_governance::reconfigure(&framework_signer);
    }}
}}
"#,
        main_param,
        framework_signer_expression,
        remove_hex_prefix(&vk.data.alpha_g1),
        remove_hex_prefix(&vk.data.beta_g2),
        remove_hex_prefix(&vk.data.gamma_g2),
        remove_hex_prefix(&vk.data.delta_g2),
        remove_hex_prefix(&vk.data.gamma_abc_g1[0]),
        remove_hex_prefix(&vk.data.gamma_abc_g1[1]),
        remove_hex_prefix(twpk_repr.as_str()),
    )
}

/// Reads the contents of the specified file and returns it as a string
fn read_file_contents(file_path: PathBuf) -> String {
    fs::read_to_string(file_path.clone()).unwrap_or_else(|error| {
        panic!(
            "Failed to read file at path: {:?}. Error: {:?}",
            file_path, error
        )
    })
}

/// Removes the "0x" prefix from the given hex string
fn remove_hex_prefix(hex_string: &str) -> String {
    assert!(hex_string.starts_with(HEX_PREFIX));
    hex_string.trim_start_matches(HEX_PREFIX).into()
}

/// Writes the given string to the specified file path (as bytes)
fn write_bytes_to_file(file_path: PathBuf, file_content: String) {
    println!("Writing to file path: {:?}...", file_path);

    let mut file = fs::File::create(&file_path).unwrap_or_else(|error| {
        panic!(
            "Failed to create file at path: {:?}. Error: {:?}",
            file_path, error
        )
    });
    file.write_all(file_content.as_bytes())
        .unwrap_or_else(|error| {
            panic!(
                "Failed to write to file at path: {:?}. Error: {:?}",
                file_path, error
            )
        });
}
