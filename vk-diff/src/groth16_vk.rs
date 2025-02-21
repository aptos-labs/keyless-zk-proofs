// TODO(Alin): This file should be removed from and reconciled with `prover/groth16_vk.rs`
use anyhow::{anyhow, Result};
use ark_bn254::{Fq, Fq2, G1Projective, G2Projective};
use ark_ff::PrimeField;
use num_bigint::BigUint;
use num_traits::Num;
use serde::{Deserialize, Serialize};
#[cfg(test)]
use std::fs::File;
#[cfg(test)]
use std::io::Write;

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

#[derive(Deserialize, Serialize, Debug)]
pub struct SnarkJsGroth16VerificationKey {
    vk_alpha_1: SnarkJsG1Repr,
    vk_beta_2: SnarkJsG2Repr,
    vk_gamma_2: SnarkJsG2Repr,
    vk_delta_2: SnarkJsG2Repr,
    #[serde(rename = "IC")]
    ic: Vec<SnarkJsG1Repr>,
}
#[test]
fn groth16_vk_rewriter() {
    if let (Ok(path_in), Ok(path_out)) = (
        std::env::var("LOCAL_VK_IN"),
        std::env::var("ONCHAIN_VK_OUT"),
    ) {
        let local_vk_json = std::fs::read_to_string(path_in.as_str()).unwrap();
        let local_vk: SnarkJsGroth16VerificationKey = serde_json::from_str(&local_vk_json).unwrap();
        let onchain_vk = OnChainGroth16VerificationKey::try_from(local_vk).unwrap();
        let json_out = serde_json::to_string_pretty(&onchain_vk).unwrap();
        File::create(path_out)
            .unwrap()
            .write_all(json_out.as_bytes())
            .unwrap();
    }
}

/// On-chain representation of a VK.
///
/// https://fullnode.testnet.aptoslabs.com/v1/accounts/0x1/resource/0x1::keyless_account::Groth16VerificationKey
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct OnChainGroth16VerificationKey {
    /// Some type info returned by node API.
    pub r#type: String,
    pub data: VKeyData,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct VKeyData {
    pub alpha_g1: String,
    pub beta_g2: String,
    pub delta_g2: String,
    pub gamma_abc_g1: Vec<String>,
    pub gamma_g2: String,
}

impl TryFrom<SnarkJsGroth16VerificationKey> for OnChainGroth16VerificationKey {
    type Error = anyhow::Error;

    fn try_from(vk: SnarkJsGroth16VerificationKey) -> Result<Self> {
        let SnarkJsGroth16VerificationKey {
            vk_alpha_1,
            vk_beta_2,
            vk_gamma_2,
            vk_delta_2,
            ic,
        } = &vk;

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
