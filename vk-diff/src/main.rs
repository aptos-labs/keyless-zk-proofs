// Copyright (c) Aptos Foundation

use aptos_keyless_common::groth16_vk::{
    OnChainGroth16VerificationKey, SnarkJsGroth16VerificationKey,
};
use clap::{Parser, ValueEnum};
use std::process::exit;
use strum_macros::Display;
use url::Url;

/// Template URL for fetching the Groth16 VK from an Aptos on-chain resource
const APTOS_GROTH16_VK_URL_TEMPLATE: &str = "https://api.{network}.aptoslabs.com/v1/accounts/0x1/resource/0x1::keyless_account::Groth16VerificationKey";

/// A simple enum representing the different Aptos networks
#[derive(Clone, Debug, ValueEnum, Display)]
enum Network {
    #[strum(serialize = "devnet")]
    Devnet,
    #[strum(serialize = "testnet")]
    Testnet,
    #[strum(serialize = "mainnet")]
    Mainnet,
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// URL to snarkjs VK JSON
    #[clap(short = 'j', long = "json", required = true)]
    snarkjs_json_url: Url,

    /// The Aptos network name
    #[clap(short, long, value_enum, required = true)]
    network: Network,

    /// Whether to print debug info at runtime
    #[clap(short = 'd', long = "debug", action)]
    print_debug_info: bool,
}

/// Prints the given string if debug info is enabled
fn debug_print(string: String, print_debug_info: bool) {
    if print_debug_info {
        println!("{}", string);
    }
}

/// Fetches the on-chain VK from the Aptos network
fn fetch_on_chain_vk(network: &Network, print_debug_info: bool) -> OnChainGroth16VerificationKey {
    // Construct the on-chain VK URL
    let on_chain_vk_url = APTOS_GROTH16_VK_URL_TEMPLATE.replace("{network}", &network.to_string());
    print_with_newline(
        &format!("Fetching `{}` VK from {}", network, on_chain_vk_url),
        true,
    );

    // Fetch the on-chain VK JSON
    let on_chain_vk_json_string = get_json_string_from_url(on_chain_vk_url);

    // Print the received on-chain VK JSON
    debug_print(
        format!("Fetched {} VK JSON:\n {}", network, on_chain_vk_json_string),
        print_debug_info,
    );

    // Convert the JSON to an OnChainGroth16VerificationKey
    serde_json::from_str::<OnChainGroth16VerificationKey>(on_chain_vk_json_string.as_str())
        .expect("Failed to convert on-chain VK JSON to OnChainGroth16VerificationKey!")
}

/// Fetches the snarkjs VK from the given URL
fn fetch_snarkjs_vk(
    snarkjs_json_url: &Url,
    print_debug_info: bool,
) -> OnChainGroth16VerificationKey {
    print_with_newline(
        &format!("Fetching snarkjs VK from {}", snarkjs_json_url),
        true,
    );

    // Fetch the snarkjs VK JSON
    let snarkjs_json_string = get_json_string_from_url(snarkjs_json_url.to_string());

    // Print the received snarkjs VK JSON
    debug_print(
        format!("Fetched snarkjs VK JSON:\n {}", snarkjs_json_string),
        print_debug_info,
    );

    // Convert the JSON to an OnChainGroth16VerificationKey
    OnChainGroth16VerificationKey::try_from(
        serde_json::from_str::<SnarkJsGroth16VerificationKey>(&snarkjs_json_string).unwrap(),
    )
    .expect("Failed to convert snarkjs VK JSON to OnChainGroth16VerificationKey!")
}

/// Fetches a JSON string from the given URL
fn get_json_string_from_url(url: String) -> String {
    let response = ureq::get(url.as_str()).call();
    let json = response.into_json().unwrap_or_else(|error| {
        panic!(
            "Failed to parse json from given URL: {}. Error: {}",
            url, error
        )
    });
    serde_json::to_string_pretty(&json).unwrap_or_else(|error| {
        panic!(
            "Failed to convert fetched JSON to string: {:?}. Error: {}",
            json, error
        )
    })
}

/// Prints the given string, and optionally appends an empty newline
fn print_with_newline(string: &str, append_newline: bool) {
    println!("{}", string);
    if append_newline {
        println!();
    }
}

fn main() {
    // Parse the command line arguments
    let args = Args::parse();
    print_with_newline("Starting VK comparison...", true);

    // Fetch the snarkjs VK
    let snarkjs_vk = fetch_snarkjs_vk(&args.snarkjs_json_url, args.print_debug_info);

    // Fetch the on-chain VK
    let on_chain_vk = fetch_on_chain_vk(&args.network, args.print_debug_info);

    // Compare the two VKs
    print_with_newline("Comparing VKs...", true);
    if snarkjs_vk != on_chain_vk {
        print_with_newline(&format!("snarkjs VK:\n {:?}", snarkjs_vk), true);
        print_with_newline(&format!("{} VK:\n {:?}", args.network, on_chain_vk), true);
        print_with_newline("ERROR: VKs are different!", false);
        exit(1)
    } else {
        println!("SUCCESS: VKs match!");
    }
}
