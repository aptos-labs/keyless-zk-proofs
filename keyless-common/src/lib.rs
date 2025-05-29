// Copyright © Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

pub mod groth16_vk;
pub mod input_processing;

pub type EphemeralPublicKeyBlinder = Vec<u8>;

// TODO can I wrap this in a struct while preserving serialization format?
pub type PoseidonHash = [u8; 32];
