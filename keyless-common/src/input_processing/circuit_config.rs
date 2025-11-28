// Copyright (c) Aptos Foundation

use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Serialize, Deserialize, Clone)]
#[serde(default, deny_unknown_fields)]
pub struct CircuitConfig {
    max_lengths: BTreeMap<String, usize>,
    has_input_skip_aud_checks: bool,
}

impl Default for CircuitConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl CircuitConfig {
    pub fn new() -> Self {
        Self {
            max_lengths: BTreeMap::new(),
            has_input_skip_aud_checks: false, // Do not skip by default
        }
    }

    /// Returns a reference to all maximum lengths
    pub fn all_max_lengths(&self) -> &BTreeMap<String, usize> {
        &self.max_lengths
    }

    /// Gets the maximum length for a given signal
    pub fn get_max_length(&self, key: &str) -> anyhow::Result<usize> {
        let max_length = self
            .max_lengths
            .get(key)
            .ok_or_else(|| anyhow!("Can't find key {} in circuit config!", key))?;
        Ok(*max_length)
    }

    /// Returns whether the circuit config has the input signal to skip audit checks
    pub fn has_input_skip_aud_checks(&self) -> bool {
        self.has_input_skip_aud_checks
    }

    /// Sets the maximum length for a given signal, and returns the updated config
    pub fn max_length(mut self, signal: &str, length: usize) -> Self {
        self.max_lengths.insert(signal.to_string(), length);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_config_max_length() {
        // Create a circuit config with some max lengths
        let config = CircuitConfig::new()
            .max_length("signal_a", 128)
            .max_length("signal_b", 256);

        // Test retrieval of max lengths
        assert_eq!(config.get_max_length("signal_a").unwrap(), 128);
        assert_eq!(config.get_max_length("signal_b").unwrap(), 256);
        assert!(config.get_max_length("signal_c").is_err());
    }

    #[test]
    fn test_circuit_config_has_input_skip_aud_checks() {
        // Create a default circuit config
        let config = CircuitConfig::new();

        // Test that the default value is false
        assert!(!config.has_input_skip_aud_checks());

        // Create a circuit config with skip audit checks enabled
        let config_with_skip = CircuitConfig {
            max_lengths: BTreeMap::new(),
            has_input_skip_aud_checks: true,
        };

        // Test that the value is true
        assert!(config_with_skip.has_input_skip_aud_checks());
    }
}
