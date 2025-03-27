use crate::watcher::ExternalResource;
use anyhow::{anyhow, Result};
use ark_bn254::{Fq, Fq2, G1Projective, G2Projective};
use ark_ff::PrimeField;
use num_bigint::BigUint;
use num_traits::Num;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write;
use std::sync::{Arc, RwLock};

//
// Below are some utils for converting a VK from snarkjs to its on-chain representation.
//

type SnarkJsFqRepr = String;
fn try_as_fq(repr: &SnarkJsFqRepr) -> Result<Fq> {
    let val = BigUint::from_str_radix(repr.as_str(), 10)?;
    let bytes = val.to_bytes_be();
    Ok(Fq::from_be_bytes_mod_order(bytes.as_slice()))
}

type SnarkJsFq2Repr = [SnarkJsFqRepr; 2];
fn try_as_fq2(repr: &SnarkJsFq2Repr) -> Result<Fq2> {
    let x = try_as_fq(&repr[0])?;
    let y = try_as_fq(&repr[1])?;
    Ok(Fq2::new(x, y))
}

type SnarkJsG1Repr = [SnarkJsFqRepr; 3];
fn try_as_g1_proj(repr: &SnarkJsG1Repr) -> Result<G1Projective> {
    let a = try_as_fq(&repr[0])?;
    let b = try_as_fq(&repr[1])?;
    let c = try_as_fq(&repr[2])?;
    Ok(G1Projective::new(a, b, c))
}

type SnarkJsG2Repr = [SnarkJsFq2Repr; 3];
fn try_as_g2_proj(repr: &SnarkJsG2Repr) -> Result<G2Projective> {
    let a = try_as_fq2(&repr[0])?;
    let b = try_as_fq2(&repr[1])?;
    let c = try_as_fq2(&repr[2])?;
    Ok(G2Projective::new(a, b, c))
}

#[derive(Deserialize, Serialize)]
pub struct SnarkJsGroth16VerificationKey {
    vk_alpha_1: SnarkJsG1Repr,
    vk_beta_2: SnarkJsG2Repr,
    vk_gamma_2: SnarkJsG2Repr,
    vk_delta_2: SnarkJsG2Repr,
    #[serde(rename = "IC")]
    ic: Vec<SnarkJsG1Repr>,
}

#[test]
fn test_local_vk_load_convert() {
    let local_vk_json = include_str!("../resources/202405_vk.vkey");
    let local_vk: SnarkJsGroth16VerificationKey = serde_json::from_str(local_vk_json).unwrap();

    // The VK we currently use on chain.
    // For the full setup details, see https://github.com/aptos-labs/aptos-keyless-trusted-setup-contributions-may-2024.
    let expected = OnChainGroth16VerificationKey {
        r#type: "0x1::keyless_account::Groth16VerificationKey".to_string(),
        data: VKeyData {
            alpha_g1: "0xe2f26dbea299f5223b646cb1fb33eadb059d9407559d7441dfd902e3a79a4d2d".to_string(),
            beta_g2: "0xabb73dc17fbc13021e2471e0c08bd67d8401f52b73d6d07483794cad4778180e0c06f33bbc4c79a9cadef253a68084d382f17788f885c9afd176f7cb2f036789".to_string(),
            delta_g2: "0x6176de7d77e614e09ef5e8e19cbf785ffed405d6531cee13cd71a46e2b4ef30deb18f6976c172bdcd7ea8ab2b509991bb5ce34f9fbb42486b78aac62a894a480".to_string(),
            gamma_abc_g1: vec![
                "0x7e92d0c6818f2e51248cd1e8e82eb14521d990b0bb155ab0e3cf99b888bc5387".to_string(),
                "0xbe1ad9f5fec081770956f846e1d0ea97219a3f6499acc33e1a67aef6d6e16898".to_string(),
            ],
            gamma_g2: "0xedf692d95cbdde46ddda5ef7d422436779445c5e66006a42761e1f12efde0018c212f3aeb785e49712e7a9353349aaf1255dfb31b7bf60723a480d9293938e19".to_string(),
        },
    };
    let actual = local_vk.try_as_onchain_repr().unwrap();
    assert_eq!(expected, actual);
}

/// This is not a UT, but a tool to convert a .vkey to its on-chain representation and save in a file.
#[test]
fn groth16_vk_rewriter() {
    if let (Ok(path_in), Ok(path_out)) = (
        std::env::var("LOCAL_VK_IN"),
        std::env::var("ONCHAIN_VK_OUT"),
    ) {
        let local_vk_json = std::fs::read_to_string(path_in.as_str()).unwrap();
        let local_vk: SnarkJsGroth16VerificationKey = serde_json::from_str(&local_vk_json).unwrap();
        write_vk_onchain_repr_file(local_vk, &path_out);
    }
}

pub fn write_vk_onchain_repr_file(vk: SnarkJsGroth16VerificationKey, path_out: &str) {
    let onchain_vk = vk.try_as_onchain_repr().unwrap();
    let json_out = serde_json::to_string_pretty(&onchain_vk).unwrap();
    File::create(&path_out)
        .unwrap()
        .write_all(json_out.as_bytes())
        .unwrap();
}

//
// Utils end.
//

/// This variable holds the cached on-chain VK. A refresh loop exists to update it periodically.
pub static ON_CHAIN_GROTH16_VK: Lazy<Arc<RwLock<Option<OnChainGroth16VerificationKey>>>> =
    Lazy::new(|| Arc::new(RwLock::new(None)));

/// On-chain representation of a VK.
///
/// https://fullnode.testnet.aptoslabs.com/v1/accounts/0x1/resource/0x1::keyless_account::Groth16VerificationKey
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct OnChainGroth16VerificationKey {
    /// Some type info returned by node API.
    pub r#type: String,
    pub data: VKeyData,
}

impl ExternalResource for OnChainGroth16VerificationKey {
    fn resource_name() -> String {
        "OnChainGroth16VerificationKey".to_string()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct VKeyData {
    pub alpha_g1: String,
    pub beta_g2: String,
    pub delta_g2: String,
    pub gamma_abc_g1: Vec<String>,
    pub gamma_g2: String,
}

// TODO(Alin): This needs to be implemented more naturally via a TryFrom... Zhoujun would rather not because IDEs like CLion can get tripped up when doing a search for usages of `try_from`
impl SnarkJsGroth16VerificationKey {
    pub fn try_as_onchain_repr(&self) -> Result<OnChainGroth16VerificationKey> {
        let SnarkJsGroth16VerificationKey {
            vk_alpha_1,
            vk_beta_2,
            vk_gamma_2,
            vk_delta_2,
            ic,
        } = self;
        let alpha_g1 =
            try_as_g1_proj(vk_alpha_1).map_err(|e| anyhow!("alpha_g1 decoding error: {e}"))?;
        let beta_g2 =
            try_as_g2_proj(vk_beta_2).map_err(|e| anyhow!("beta_g2 decoding error: {e}"))?;
        let delta_g2 =
            try_as_g2_proj(vk_delta_2).map_err(|e| anyhow!("delta_g2 decoding error: {e}"))?;
        let gamma_abc_g1_0 =
            try_as_g1_proj(&ic[0]).map_err(|e| anyhow!("gamma_abc_g1[0] decoding error: {e}"))?;
        let gamma_abc_g1_1 =
            try_as_g1_proj(&ic[1]).map_err(|e| anyhow!("gamma_abc_g1[1] decoding error: {e}"))?;
        let gamma_g2 =
            try_as_g2_proj(vk_gamma_2).map_err(|e| anyhow!("gamma_g2 decoding error: {e}"))?;

        Ok(OnChainGroth16VerificationKey {
            r#type: "0x1::keyless_account::Groth16VerificationKey".to_string(),
            data: VKeyData {
                alpha_g1: as_onchain_repr(&alpha_g1)
                    .map_err(|e| anyhow!("alpha_g1 re-encoding error: {e}"))?,
                beta_g2: as_onchain_repr(&beta_g2)
                    .map_err(|e| anyhow!("beta_g2 re-encoding error: {e}"))?,
                delta_g2: as_onchain_repr(&delta_g2)
                    .map_err(|e| anyhow!("delta_g2 re-encoding error: {e}"))?,
                gamma_abc_g1: vec![
                    as_onchain_repr(&gamma_abc_g1_0)
                        .map_err(|e| anyhow!("gamma_abc_g1[0] re-encoding error: {e}"))?,
                    as_onchain_repr(&gamma_abc_g1_1)
                        .map_err(|e| anyhow!("gamma_abc_g1[1] re-encoding error: {e}"))?,
                ],
                gamma_g2: as_onchain_repr(&gamma_g2)
                    .map_err(|e| anyhow!("gamma_g2 re-encoding error: {e}"))?,
            },
        })
    }
}

fn as_onchain_repr<T: ark_serialize::CanonicalSerialize>(point: &T) -> Result<String> {
    let mut buf = vec![];
    point.serialize_compressed(&mut buf)?;
    Ok(format!("0x{}", hex::encode(buf)))
}
