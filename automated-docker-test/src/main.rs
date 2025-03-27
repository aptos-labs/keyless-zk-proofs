use std::fs::{self};
use std::path::Path;
use std::process::Command;

use aptos_crypto::ed25519::Ed25519PublicKey;
use aptos_crypto::ValidCryptoMaterialStringExt;
use aptos_types::jwks::rsa::RSA_JWK;
use keyless_common::input_processing::{config::CircuitConfig, encoding::AsFr};
use prover_service::api::ProverServiceResponse;
use prover_service::groth16_vk::SnarkJsGroth16VerificationKey;
use prover_service::tests::common::types::{
    DefaultTestJWKKeyPair, ProofTestCase, TestJWKKeyPair, TestJWTPayload,
};
use prover_service::training_wheels;
use serde::Serialize;

#[derive(Serialize)]
struct JwkKeys {
    keys: Vec<RSA_JWK>,
}

fn ceremony_dir_exists(release_tag: &str) -> bool {
    Path::new(
        shellexpand::tilde(&format!(
            "~/.local/share/aptos-keyless/ceremonies/{}",
            release_tag
        ))
        .as_ref(),
    )
    .is_dir()
}

fn ceremony_vk_path(release_tag: &str) -> String {
    shellexpand::tilde(&format!(
        "~/.local/share/aptos-keyless/ceremonies/{}/verification_key.json",
        release_tag
    ))
    .to_string()
}

fn circuit_config_path(release_tag: &str) -> String {
    shellexpand::tilde(&format!(
        "~/.local/share/aptos-keyless/ceremonies/{}/circuit_config.yml",
        release_tag
    ))
    .to_string()
}

fn get_circuit_config() -> CircuitConfig {
    serde_yaml::from_str(&fs::read_to_string("circuit_config.yml").expect("Unable to read file"))
        .expect("should parse correctly")
}

fn main() {
    // DEFAULT FLOW
    // ============
    //
    // take as input:
    // - release, "default" or "new" tag

    // download release using script if not present
    // generate tw keypair
    // generate jwk keypair

    // write out envvar file: (these envvars must be passed to prover service)
    // - ONCHAIN_GROTH16_VK_URL=http://mock-on-chain:4444/groth16_vk.json
    // - ONCHAIN_TW_VK_URL=http://mock-on-chain:4444/keyless_config.json
    // - PRIVATE_KEY_0=0x8c75cacb54de1af0bd7b6c0549548b8d39a8177320f46ca5f767e5ed603dc08b
    // - PRIVATE_KEY_1=0x6bf4bd737ac8cc87841b5e83d396ff4e9197b014b7b395434d09c5828cca0e1d
    // - OIDC_PROVIDERS="[ { iss='test.oidc.provider', endpoint_url='http://mock-on-chain:4444/jwk.json' } ]"

    // output files:
    // /groth16_vk.json: vk for the release, can use cargo test code to generate DONE
    // /keyless_config.json: contains training wheels VK? (can also gen using cargo test code) DONE
    // /jwk.json: generate using jwk keypair
    // /jwk_sk.txt: jwk sk, used during testing to sign jwt
    // /tw_vk.txt: tw vk, used during testing to verify prover service response
    //
    //
    // SEND TEST REQUEST FLOW
    // ======================
    // take as input:
    // - jwk_sk.txt
    // - tw_vk.txt
    //
    // output prover service request

    let command = std::env::args()
        .nth(1)
        .expect("No command given. Expected \"prepare-test\" or \"request\"");

    if command == "prepare-test" {
        std::fs::create_dir_all("./test-staging").unwrap();
        std::env::set_current_dir("./test-staging").unwrap();

        let release_tag = std::env::args().nth(2).expect("no path given");
        println!("Using release tag {}.", release_tag);

        let mut envvars = vec![];
        envvars.push("CONFIG_FILE=\"config.yml\"".to_string());

        println!("Circuit config path {}.", circuit_config_path(&release_tag));
        fs::copy(&circuit_config_path(&release_tag), "circuit_config.yml").unwrap();

        if !ceremony_dir_exists(&release_tag) {
            Command::new("../scripts/task.sh")
                .args([
                    "setup",
                    "download-ceremonies-for-releases",
                    &release_tag,
                    &release_tag,
                ])
                .status()
                .expect("Setup download task.sh action failed");

            assert!(ceremony_dir_exists(&release_tag));
        }

        // Generate tw keypair and write tw sk/vk files/envvars
        let tw_keypair = prover_service::tests::common::gen_test_training_wheels_keypair();
        prover_service::prover_key::write_tw_on_chain_repr_json(&tw_keypair, "keyless_config.json");
        fs::write(
            "tw_vk.txt",
            &tw_keypair.verification_key.to_encoded_string().unwrap(),
        )
        .unwrap();
        envvars.push(format!(
            "PRIVATE_KEY_0={}",
            &tw_keypair.signing_key.to_encoded_string().unwrap()
        ));
        envvars.push(format!(
            "PRIVATE_KEY_1={}",
            &tw_keypair.signing_key.to_encoded_string().unwrap()
        ));
        envvars.push(format!(
            "ONCHAIN_TW_VK_URL={}",
            "http://mock-on-chain:4444/keyless_config.json"
        ));
        envvars.push(format!("OIDC_PROVIDERS={}", "[ { iss=\"test.oidc.provider\", endpoint_url=\"http://mock-on-chain:4444/jwk.json\" } ]"));

        // Convert verification_key.json output by snarkjs into the on-chain-config format
        let local_vk_json = std::fs::read_to_string(ceremony_vk_path(&release_tag)).unwrap();
        let local_vk: SnarkJsGroth16VerificationKey = serde_json::from_str(&local_vk_json).unwrap();
        prover_service::groth16_vk::write_vk_onchain_repr_file(local_vk, "groth16_vk.json");
        fs::copy(
            &ceremony_vk_path(&release_tag),
            "snarkjs_verification_key.json",
        )
        .unwrap();
        envvars.push(format!(
            "ONCHAIN_GROTH16_VK_URL={}",
            "http://mock-on-chain:4444/groth16_vk.json"
        ));

        // JWK keypair
        let jwk_keypair = prover_service::tests::common::gen_test_jwk_keypair();
        let jwk_keys = JwkKeys {
            keys: vec![jwk_keypair.into_rsa_jwk()],
        };
        let jwk_keys_json = serde_json::to_string(&jwk_keys).unwrap();
        fs::write("jwk.json", &jwk_keys_json).unwrap();
        fs::write(
            "jwk_keypair.json",
            &serde_json::to_string(&jwk_keypair).unwrap(),
        )
        .unwrap();

        fs::write("envvars.env", envvars.join("\n")).unwrap();
    } else if command == "request" {
        std::env::set_current_dir("./test-staging").unwrap();

        let url = std::env::args().nth(2).expect("no url given");

        let tw_vk =
            Ed25519PublicKey::from_encoded_string(&fs::read_to_string("tw_vk.txt").unwrap())
                .unwrap();

        let jwk_keypair: DefaultTestJWKKeyPair =
            serde_json::from_str(&fs::read_to_string("jwk_keypair.json").unwrap()).unwrap();

        let testcase = ProofTestCase::default_with_payload(TestJWTPayload::default())
            .compute_nonce(&get_circuit_config());

        let prover_request_input = testcase.convert_to_prover_request(&jwk_keypair);

        println!(
            "Prover request: {}",
            serde_json::to_string_pretty(&prover_request_input).unwrap()
        );

        let client = reqwest::blocking::Client::new();
        let response_str = client
            .post(&(String::from("http://") + &url + "/v0/prove"))
            .json(&prover_request_input)
            .send()
            .unwrap()
            .text()
            .unwrap();

        println!("Prover response: {}", response_str);

        let response: ProverServiceResponse = serde_json::from_str(&response_str).unwrap();

        match response {
            ProverServiceResponse::Success {
                proof,
                public_inputs_hash,
                ..
            } => {
                let g16vk = prover_service::load_vk::prepared_vk("snarkjs_verification_key.json");
                proof
                    .verify_proof(public_inputs_hash.as_fr(), &g16vk)
                    .unwrap();
                training_wheels::verify(&response, &tw_vk).unwrap();
                println!("Verification of prover response succeeded")
            }
            ProverServiceResponse::Error { message } => {
                panic!("returned ProverServiceResponse::Error: {}", message)
            }
        }
    } else {
        println!("Command not recognized. Expected \"prepare-test\" or \"request\"");
    }
}
