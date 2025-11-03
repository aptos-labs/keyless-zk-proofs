// Copyright (c) Aptos Foundation

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Serialize, Deserialize, Clone)]
pub struct CircuitConfig {
    pub max_lengths: BTreeMap<String, usize>,
    #[serde(default)]
    pub has_input_skip_aud_checks: bool,
}

impl CircuitConfig {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            max_lengths: BTreeMap::new(),
            has_input_skip_aud_checks: false,
        }
    }

    pub fn max_length(mut self, signal: &str, l: usize) -> Self {
        self.max_lengths.insert(String::from(signal), l);
        self
    }
}
