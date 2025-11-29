// Copyright (c) Aptos Foundation

use super::circuit_config::CircuitConfig;
use crate::input_processing::encoding::{Padded, Unpadded};
use anyhow::{anyhow, bail, Result};
use ark_bn254::Fr;
use serde_json::Value;
use std::{collections::BTreeMap, marker::PhantomData};

/// A single input signal to a circuit
#[derive(Debug)]
pub enum CircuitInputSignal {
    U64(u64),
    Fr(Fr),
    Frs(Vec<Fr>),
    Limbs(Vec<u64>),
    Bytes(Vec<u8>),
}

/// A collection of input signals to a circuit
#[derive(Debug)]
pub struct CircuitInputSignals<T> {
    signals: BTreeMap<String, CircuitInputSignal>,
    t: PhantomData<T>,
}

impl Default for CircuitInputSignals<Unpadded> {
    fn default() -> Self {
        Self::new()
    }
}

impl CircuitInputSignals<Unpadded> {
    pub fn new() -> Self {
        Self {
            signals: BTreeMap::new(),
            t: PhantomData,
        }
    }

    /// Add a bytes input signal
    pub fn bytes_input(mut self, signal_name: &str, signal_value: &[u8]) -> Self {
        self.signals.insert(
            String::from(signal_name),
            CircuitInputSignal::Bytes(Vec::from(signal_value)),
        );
        self
    }

    /// Add a byte input signal
    pub fn byte_input(mut self, signal_name: &str, signal_value: u8) -> Self {
        self.signals.insert(
            String::from(signal_name),
            CircuitInputSignal::U64(signal_value as u64),
        );
        self
    }

    /// Add a bits input signal
    pub fn bits_input(self, signal_name: &str, signal_value: &[bool]) -> Self {
        let bytes: Vec<u8> = signal_value.iter().map(|&val| val as u8).collect();
        self.bytes_input(signal_name, bytes.as_slice())
    }

    /// Add a string input signal
    pub fn str_input(mut self, signal_name: &str, signal_value: &str) -> Self {
        self.signals.insert(
            String::from(signal_name),
            CircuitInputSignal::Bytes(Vec::from(signal_value.as_bytes())),
        );
        self
    }

    /// Add a usize input signal
    pub fn usize_input(mut self, signal_name: &str, signal_value: usize) -> Self {
        self.signals.insert(
            String::from(signal_name),
            CircuitInputSignal::U64(signal_value as u64),
        );
        self
    }

    /// Add a limbs input signal
    pub fn limbs_input(mut self, signal_name: &str, signal_value: &[u64]) -> Self {
        self.signals.insert(
            String::from(signal_name),
            CircuitInputSignal::Limbs(Vec::from(signal_value)),
        );
        self
    }

    /// Add a u64 input signal
    pub fn u64_input(mut self, signal_name: &str, signal_value: u64) -> Self {
        self.signals.insert(
            String::from(signal_name),
            CircuitInputSignal::U64(signal_value),
        );
        self
    }

    /// Add a Frs input signal
    pub fn frs_input(mut self, signal_name: &str, signal_value: &[Fr]) -> Self {
        self.signals.insert(
            String::from(signal_name),
            CircuitInputSignal::Frs(Vec::from(signal_value)),
        );
        self
    }

    /// Add a Fr input signal
    pub fn fr_input(mut self, signal_name: &str, signal_value: Fr) -> Self {
        self.signals.insert(
            String::from(signal_name),
            CircuitInputSignal::Fr(signal_value),
        );
        self
    }

    /// Add a bools input signal
    pub fn bools_input(mut self, signal_name: &str, signal_value: &[bool]) -> Self {
        self.signals.insert(
            String::from(signal_name),
            CircuitInputSignal::Bytes(signal_value.iter().map(|b| *b as u8).collect::<Vec<u8>>()),
        );
        self
    }

    /// Add a bool input signal
    pub fn bool_input(mut self, signal_name: &str, signal_value: bool) -> Self {
        self.signals.insert(
            String::from(signal_name),
            CircuitInputSignal::U64(signal_value as u64),
        );
        self
    }

    /// Merge another circuit input signals into this one
    pub fn merge(mut self, to_merge: CircuitInputSignals<Unpadded>) -> Result<Self> {
        // Ensure no signal inputs are being redefined
        for (key, _) in self.signals.iter() {
            if to_merge.signals.contains_key(key) {
                bail!(
                    "Cannot redefine a signal input that is already defined! Key: {}",
                    key
                );
            }
        }

        // Merge the signals
        self.signals.extend(to_merge.signals);

        Ok(Self {
            signals: self.signals,
            t: PhantomData,
        })
    }

    /// Pad all signals to their max lengths as defined in the circuit config
    pub fn pad(self, config: &CircuitConfig) -> Result<CircuitInputSignals<Padded>> {
        // Pad each signal as needed
        let padded_signals_vec: Result<Vec<(String, CircuitInputSignal)>> = self
            .signals
            .into_iter()
            .map(|(k, v)| {
                anyhow::Ok((
                    String::from(&k),
                    pad_if_needed(&k, v, config.all_max_lengths())?,
                ))
            })
            .collect();

        // Reconstruct the map
        let padded_signals: BTreeMap<String, CircuitInputSignal> =
            BTreeMap::from_iter(padded_signals_vec?);

        Ok(CircuitInputSignals {
            signals: padded_signals,
            t: PhantomData,
        })
    }
}

// Note: we can only serialize padded signals because unpadded signals may have
// variable lengths which would make deserialization ambiguous.
impl CircuitInputSignals<Padded> {
    /// Convert the circuit input signals to a JSON value
    pub fn to_json_value(&self) -> Value {
        Value::from(serde_json::Map::from_iter(
            self.signals.iter().map(|(k, v)| (k.clone(), stringify(v))),
        ))
    }
}

/// Pad a circuit input signal if needed (based on the global max lengths)
fn pad_if_needed(
    key: &str,
    circuit_input_signal: CircuitInputSignal,
    global_input_max_lengths: &BTreeMap<String, usize>,
) -> Result<CircuitInputSignal, anyhow::Error> {
    let result = match circuit_input_signal {
        CircuitInputSignal::U64(x) => CircuitInputSignal::U64(x),
        CircuitInputSignal::Fr(x) => CircuitInputSignal::Fr(x),
        CircuitInputSignal::Frs(x) => CircuitInputSignal::Frs(x),
        CircuitInputSignal::Limbs(mut limbs) => {
            // Get the max length for this key
            let max_length = global_input_max_lengths
                .get(key)
                .copied()
                .unwrap_or(limbs.len());

            // Pad the limbs with zeros if needed
            if max_length < limbs.len() {
                Err(anyhow!(
                    "Max limb size exceeded! Key: {}, Max Size: {}, Actual Size: {}",
                    key,
                    max_length,
                    limbs.len()
                ))?
            } else {
                let zeros_needed = max_length - limbs.len();
                limbs.extend(vec![0; zeros_needed]);
                CircuitInputSignal::Limbs(limbs)
            }
        }
        CircuitInputSignal::Bytes(bytes) => {
            // Get the max length for this key
            let max_length = global_input_max_lengths
                .get(key)
                .copied()
                .ok_or_else(|| anyhow!("No max length found for key {}", key))?;

            // Pad the bytes with zeros if needed
            if max_length < bytes.len() {
                Err(anyhow!(
                    "Max byte size exceeded! Key: {}, Max Size: {}, Actual Size: {}",
                    key,
                    max_length,
                    bytes.len()
                ))?
            } else {
                let zeros_needed = max_length - bytes.len();

                let mut padded_bytes = bytes.clone();
                padded_bytes.extend([0].repeat(zeros_needed));
                CircuitInputSignal::Bytes(padded_bytes)
            }
        }
    };

    Ok(result)
}

/// Helper function to stringify a circuit input signal
fn stringify(circuit_input_signal: &CircuitInputSignal) -> Value {
    match circuit_input_signal {
        CircuitInputSignal::U64(u64) => Value::from(u64.to_string()),
        CircuitInputSignal::Fr(fr) => Value::from(fr_to_string(fr)),
        CircuitInputSignal::Frs(frs) => {
            let strings: Vec<String> = frs.iter().map(fr_to_string).collect();
            Value::from(strings)
        }
        CircuitInputSignal::Limbs(limbs) => Value::from(stringify_vec(limbs)),
        CircuitInputSignal::Bytes(bytes) => Value::from(stringify_vec(bytes)),
    }
}

/// Helper function to stringify a vector of items
fn stringify_vec<T: ToString>(v: &[T]) -> Vec<String> {
    v.iter().map(|num| num.to_string()).collect()
}

/// Annoyingly, Fr serializes 0 to the empty string. So, we mitigate this here.
fn fr_to_string(fr: &Fr) -> String {
    let string = fr.to_string();
    if string.is_empty() {
        "0".to_string()
    } else {
        string
    }
}
