use aptos_keyless_common::groth16_vk::{
    OnChainGroth16VerificationKey, SnarkJsGroth16VerificationKey,
};
use clap::{Parser, Subcommand};
use std::fs;
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
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::GenerateRootSignerScript {
            vk_path,
            twpk_path,
            out,
        } => generate_root_signer_script(vk_path, twpk_path, out),
    }
}

fn generate_root_signer_script(vk_path: PathBuf, twpk_path: PathBuf, out: PathBuf) {
    println!("Generating root signer script...");
    println!("VK path: {}", vk_path.display());
    println!("TWPK path: {}", twpk_path.display());
    println!("Output path: {}", out.display());

    // Read the verification key file
    let local_vk_json = fs::read_to_string(&vk_path).unwrap();
    let local_vk: SnarkJsGroth16VerificationKey = serde_json::from_str(&local_vk_json).unwrap();
    let onchain_vk = OnChainGroth16VerificationKey::try_from(local_vk).unwrap();
    // Read the training wheel public key file
    let twpk_repr = fs::read_to_string(&twpk_path).unwrap();

    // Generate the governance script
    let script_content = generate_script_content(&onchain_vk, &twpk_repr);

    // Ensure output directory exists
    if let Some(parent) = out.parent() {
        fs::create_dir_all(parent).unwrap();
    }

    // Write the script to the output file
    fs::write(&out, script_content).unwrap();

    println!(
        "Successfully generated root signer script at: {}",
        out.display()
    );
}

fn generate_script_content(vk: &OnChainGroth16VerificationKey, twpk_repr: &str) -> String {
    format!(
        r#"
script {{
    use aptos_framework::keyless_account;
    use aptos_framework::aptos_governance;
    use std::option;
    fun main(core_resources: &signer) {{
        let framework_signer = aptos_governance::get_signer_testnet_only(core_resources, @0x1);

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
        remove_0x(&vk.data.alpha_g1),
        remove_0x(&vk.data.beta_g2),
        remove_0x(&vk.data.gamma_g2),
        remove_0x(&vk.data.delta_g2),
        remove_0x(&vk.data.gamma_abc_g1[0]),
        remove_0x(&vk.data.gamma_abc_g1[1]),
        remove_0x(twpk_repr),
    )
}

fn remove_0x(bytes_repr: &str) -> String {
    assert!(bytes_repr.starts_with("0x"));
    bytes_repr.trim_start_matches("0x").to_owned()
}
