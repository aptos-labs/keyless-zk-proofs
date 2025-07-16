use aptos_keyless_common::groth16_vk::{
    OnChainGroth16VerificationKey, SnarkJsGroth16VerificationKey,
};
use clap::{Parser, Subcommand};
use std::fs;
use std::io::Write;
use std::path::PathBuf;

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
    /// Generate a governance proposal in an local aptos-core repo.
    GenerateProposal {
        /// Path to a local aptos-core repo that this tool will modify.
        #[clap(long = "aptos-core-path")]
        aptos_core_path: PathBuf,

        /// Path to the verification key file
        #[clap(long = "vk-path")]
        vk_path: PathBuf,

        /// Path to the training wheel public key file
        #[clap(long = "twpk-path")]
        twpk_path: PathBuf,

        /// Only used in description text.
        #[clap(long = "circuit-release-tag")]
        circuit_release_tag: String,

        /// Only used in description text.
        #[clap(long = "tw-key-id")]
        tw_key_id: String,
    },
}

enum ProposalExecutionMode {
    RootSigner,
    ProposalID,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::GenerateRootSignerScript {
            vk_path,
            twpk_path,
            out,
        } => generate_root_signer_script(&vk_path, &twpk_path, &out),
        Commands::GenerateProposal {
            aptos_core_path,
            circuit_release_tag,
            tw_key_id,
            vk_path,
            twpk_path,
        } => generate_governance_proposal(
            &aptos_core_path,
            &circuit_release_tag,
            &tw_key_id,
            &vk_path,
            &twpk_path,
        ),
    }
}

fn generate_governance_proposal(
    repo_path: &PathBuf,
    circuit_release_tag: &str,
    tw_key_id: &str,
    vk_path: &PathBuf,
    twpk_path: &PathBuf,
) {
    new_release_yaml(&repo_path, circuit_release_tag, tw_key_id);
    generate_proposal_script(&repo_path, vk_path, twpk_path);
}

fn new_release_yaml(aptos_core_path: &PathBuf, circuit_release_tag: &str, tw_key_id: &str) {
    let target_path =
        aptos_core_path.join("aptos-move/aptos-release-builder/data/keyless-config-update.yaml");
    println!("Writing to {target_path:?}.");
    let mut file = fs::File::create(&target_path).unwrap();
    let release_yaml_content = format!(
        r#"---
remote_endpoint: https://fullnode.mainnet.aptoslabs.com
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
        circuit_release_tag, tw_key_id
    );
    file.write_all(release_yaml_content.as_bytes()).unwrap();
}

fn generate_proposal_script(repo_path: &PathBuf, vk_path: &PathBuf, twpk_path: &PathBuf) {
    let script_content =
        generate_script_content(ProposalExecutionMode::ProposalID, vk_path, twpk_path);
    let target_path = repo_path
        .join("aptos-move/aptos-release-builder/data/proposals/keyless-config-update.move");
    println!("Writing to {target_path:?}.");
    let mut file = fs::File::create(&target_path).unwrap();
    file.write_all(script_content.as_bytes()).unwrap();
}

fn generate_root_signer_script(vk_path: &PathBuf, twpk_path: &PathBuf, out: &PathBuf) {
    println!("Generating root signer script...");
    println!("VK path: {}", vk_path.display());
    println!("TWPK path: {}", twpk_path.display());
    println!("Output path: {}", out.display());

    // Generate the governance script
    let script_content =
        generate_script_content(ProposalExecutionMode::RootSigner, vk_path, twpk_path);

    // Ensure output directory exists
    if let Some(parent) = out.parent() {
        fs::create_dir_all(parent).unwrap();
    }

    // Write the script to the output file
    fs::write(out, script_content).unwrap();

    println!(
        "Successfully generated root signer script at: {}",
        out.display()
    );
}

fn generate_script_content(
    mode: ProposalExecutionMode,
    vk_path: &PathBuf,
    twpk_path: &PathBuf,
) -> String {
    // Read the verification key file
    let local_vk_json = fs::read_to_string(&vk_path).unwrap();
    let local_vk: SnarkJsGroth16VerificationKey = serde_json::from_str(&local_vk_json).unwrap();
    let vk = OnChainGroth16VerificationKey::try_from(local_vk).unwrap();
    // Read the training wheel public key file
    let twpk_repr = fs::read_to_string(&twpk_path).unwrap();

    let (main_param, framework_signer_expression) = match mode {
        ProposalExecutionMode::RootSigner => (
            "core_resources: &signer",
            "aptos_governance::get_signer_testnet_only(core_resources, @0x1)",
        ),
        ProposalExecutionMode::ProposalID => (
            "proposal_id: u64",
            "aptos_governance::resolve_multi_step_proposal(proposal_id, @0x1, {{ script_hash }},)",
        ),
    };
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
        remove_0x(&vk.data.alpha_g1),
        remove_0x(&vk.data.beta_g2),
        remove_0x(&vk.data.gamma_g2),
        remove_0x(&vk.data.delta_g2),
        remove_0x(&vk.data.gamma_abc_g1[0]),
        remove_0x(&vk.data.gamma_abc_g1[1]),
        remove_0x(twpk_repr.as_str()),
    )
}

fn remove_0x(bytes_repr: &str) -> String {
    assert!(bytes_repr.starts_with("0x"));
    bytes_repr.trim_start_matches("0x").to_owned()
}
