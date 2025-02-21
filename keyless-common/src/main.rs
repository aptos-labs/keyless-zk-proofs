use aptos_types::keyless::Groth16VerificationKey;
// use std::fs;
// use std::fs::File;
// use std::io::Read;
// use std::path::Path;
// use std::process::Command;
// use ark_bn254::{Fq, Fq2, Fr, G1Projective, G2Projective};
// use serde::{Deserialize, Serialize};
// use anyhow::Result;
// use ark_ff::PrimeField;
// use num_bigint::BigUint;
// use num_traits::Num;
// use hex;
use clap::{Parser, ValueEnum};
use strum_macros::Display;
use url::Url;
//
// fn read_file_to_string(file_path: &str) -> Result<String> {
//     let mut file = File::open(file_path)?;
//     let mut content = String::new();
//     file.read_to_string(&mut content)?;
//     Ok(content)
// }

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
    let move_json_url = format!("https://api.{}.aptoslabs.com/v1/accounts/0x1/resource/0x1::keyless_account::Groth16VerificationKey",
                                args.network.to_string());

    println!();
    println!("Fetching snarkjs VK from {}", args.snarkjs_json_url);
    println!();
    println!(
        "Fetching Aptos Move VK on `{}` from {}",
        args.network, move_json_url
    );
    println!();

    let snarkjs_json = ureq::get(args.snarkjs_json_url.as_str())
        .call()
        .into_json()
        .expect("Failed to parse snarkjs VK JSON");
    let snarkjs_json_pretty_str = serde_json::to_string_pretty(&snarkjs_json).unwrap();
    println!("snarkjs JSON VK:\n {}", snarkjs_json_pretty_str);
    println!();

    let on_chain_json = ureq::get(move_json_url.as_str())
        .call()
        .into_json()
        .expect("Failed to parse Aptos Move VK JSON")
        .get("data")
        .cloned()
        .expect("Failed to find \"data\" field in Aptos Move VK JSON");
    let on_chain_json_pretty_str = serde_json::to_string_pretty(&on_chain_json).unwrap();

    fn get_hex_bytes(json: &serde_json::Value, field_name: &str) -> Vec<u8> {
        println!("{}", field_name);
        hex::decode(
            json.get(field_name)
                .cloned()
                .unwrap()
                .as_str()
                .unwrap()
                .to_string()
                .strip_prefix("0x")
                .unwrap()
                .to_string(),
        )
        .unwrap()
    }

    let gamma_abc_g1 = on_chain_json
        .get("gamma_abc_g1")
        .cloned()
        .unwrap()
        .as_array()
        .cloned()
        .unwrap();
    let gamma_abc_g1_1 = gamma_abc_g1
        .get(0)
        .cloned()
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    let gamma_abc_g1_2 = gamma_abc_g1
        .get(1)
        .cloned()
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();

    let on_chain_vk = Groth16VerificationKey {
        alpha_g1: get_hex_bytes(&on_chain_json, "alpha_g1"),
        beta_g2: get_hex_bytes(&on_chain_json, "beta_g2"),
        gamma_abc_g1: vec![
            hex::decode(gamma_abc_g1_1.strip_prefix("0x").unwrap().to_string()).unwrap(),
            hex::decode(gamma_abc_g1_2.strip_prefix("0x").unwrap().to_string()).unwrap(),
        ],
        delta_g2: get_hex_bytes(&on_chain_json, "delta_g2"),
        gamma_g2: get_hex_bytes(&on_chain_json, "gamma_g2"),
    };

    println!("Move JSON VK:\n {}", on_chain_json_pretty_str);
}
