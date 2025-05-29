use aptos_keyless_common::groth16_vk::{
    OnChainGroth16VerificationKey, SnarkJsGroth16VerificationKey,
};
use clap::{Parser, ValueEnum};
use std::process::exit;
use strum_macros::Display;
use url::Url;

#[derive(Clone, Debug, ValueEnum, Display)]
enum Network {
    #[strum(serialize = "devnet")]
    Devnet,
    #[strum(serialize = "testnet")]
    Testnet,
    #[strum(serialize = "mainnet")]
    Mainnet,
}

/// Program to benchmark three types of Merkle trees: traditional CRHF-based Merkle,
/// incrementally-hashed Merkle (or Merkle++), and VC-based Merkle (or Verkle)
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// URL to snarkjs VK JSON
    #[clap(short = 'j', long = "json", required = true)]
    snarkjs_json_url: Url,

    /// The Aptos network name
    #[clap(short, long, value_enum, required = true)]
    network: Network,
}

fn main() {
    let args = Args::parse();
    let on_chain_json_url = format!("https://api.{}.aptoslabs.com/v1/accounts/0x1/resource/0x1::keyless_account::Groth16VerificationKey",
                                    args.network);
    println!();

    println!("Fetching snarkjs VK from {}", args.snarkjs_json_url);
    println!();
    let snarkjs_json = ureq::get(args.snarkjs_json_url.as_str())
        .call()
        .into_json()
        .expect("Failed to parse snarkjs VK JSON");
    let snarkjs_json_pretty = serde_json::to_string_pretty(&snarkjs_json).unwrap();
    // println!("snarkjs JSON VK:\n {}", snarkjs_json_pretty_str);
    let snarkjs_vk = OnChainGroth16VerificationKey::try_from(
        serde_json::from_str::<SnarkJsGroth16VerificationKey>(&snarkjs_json_pretty).unwrap(),
    )
    .unwrap();
    // println!("snarkjs_vk: {:?}", snarkjs_vk);

    println!("Fetching `{}` VK from {}", args.network, on_chain_json_url);
    println!();
    let on_chain_vk_json = ureq::get(on_chain_json_url.as_str())
        .call()
        .into_json()
        .unwrap_or_else(|_| panic!("Failed to parse {} VK JSON", args.network));
    let on_chain_vk_json_pretty = serde_json::to_string_pretty(&on_chain_vk_json).unwrap();
    // println!(format!("{} JSON VK:\n {}", args.network, on_chain_vk_json_pretty_str));
    let on_chain_vk =
        serde_json::from_str::<OnChainGroth16VerificationKey>(on_chain_vk_json_pretty.as_str())
            .unwrap();
    // println!("on_chain_vk: {:?}", on_chain_vk);

    if snarkjs_vk != on_chain_vk {
        println!("snarkjs VK:\n {:?}", snarkjs_vk);
        println!();
        println!("{} VK:\n {:?}", args.network, on_chain_vk);
        println!();
        println!("VKs are different!");
        exit(1)
    } else {
        println!("VKs match!");
    }
}
